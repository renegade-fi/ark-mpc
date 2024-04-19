use std::{
    io::Write,
    net::SocketAddr,
    process::exit,
    sync::{Arc, Mutex, MutexGuard},
    thread,
    time::Duration,
};

use ark_bn254::G1Projective as Bn254Projective;
use ark_mpc::{
    algebra::{CurvePoint, Scalar},
    network::{NetworkOutbound, NetworkPayload, QuicTwoPartyNet},
    offline_prep::PartyIDBeaverSource,
    MpcFabric, PARTY0,
};
use clap::Parser;
use colored::Colorize;
use dns_lookup::lookup_host;
use env_logger::Builder;
use futures::{SinkExt, StreamExt};
use tokio::runtime::{Builder as RuntimeBuilder, Handle};
use tracing::log::{self, LevelFilter};

mod authenticated_curve;
mod authenticated_scalar;
mod circuits;
mod fabric;
mod helpers;
mod lowgear;

/// The amount of time to sleep after sending a shutdown
const SHUTDOWN_TIMEOUT_MS: u64 = 3_000; // 3 seconds

/// The curve used for testing, set to bn254
pub type TestCurve = Bn254Projective;
/// The curve point type used for testing
pub type TestCurvePoint = CurvePoint<TestCurve>;
/// The scalar point ype used for testing
pub type TestScalar = Scalar<TestCurve>;

/// Integration test arguments, common to all tests
#[derive(Clone)]
struct IntegrationTestArgs {
    /// The ID of the local party in the MPC
    party_id: u64,
    /// The local party's alternate hostport for one-off network connections
    local_addr: SocketAddr,
    /// The remote party's alternate hostport for one-off network connections
    peer_addr: SocketAddr,
    /// The underlying MPC fabric
    fabric: MpcFabric<TestCurve>,
}

impl IntegrationTestArgs {
    /// Get a new quic connection to the counterparty
    pub async fn new_quic_conn(&self) -> QuicTwoPartyNet<TestCurve> {
        let mut net = QuicTwoPartyNet::new(self.party_id, self.local_addr, self.peer_addr);
        net.connect().await.unwrap();
        net
    }
}

/// Integration test format
#[derive(Clone)]
struct IntegrationTest {
    pub name: &'static str,
    pub test_fn: fn(&IntegrationTestArgs) -> Result<(), String>,
}

// Collect the statically defined tests into an interable
inventory::collect!(IntegrationTest);

/// The command line interface for the test harness
#[derive(Clone, Parser, Debug)]
struct Args {
    /// The party id of the
    #[clap(long, value_parser)]
    party: u64,
    /// The port to accept inbound on
    #[clap(long = "port1", value_parser)]
    port1: u64,
    /// The port to expect the counterparty on
    #[clap(long = "port2", value_parser)]
    port2: u64,
    /// The test to run
    #[clap(short, long, value_parser)]
    test: Option<String>,
    /// Whether running in docker or not, used for peer lookup
    #[clap(long, takes_value = false, value_parser)]
    docker: bool,
}

#[allow(unused_doc_comments, clippy::await_holding_refcell_ref)]
fn main() {
    // Setup logging
    init_logger();

    // Parse the cli args
    let args = Args::parse();
    let args_clone = args.clone();

    // Build a runtime to execute within
    let runtime = RuntimeBuilder::new_multi_thread().enable_all().build().unwrap();

    // We run the harness inside of a tokio blocking task so that blocking network
    // calls are able to function properly
    let result = runtime.spawn_blocking(move || {
        // ---------
        // | Setup |
        // ---------

        // Listen on 0.0.0.0 (all network interfaces) with the given port
        // We do this because listening on localhost when running in a container points
        // to the container's loopback interface, not the docker bridge
        let local_addr: SocketAddr = format!("0.0.0.0:{}", args.port1).parse().unwrap();
        let local_addr2: SocketAddr = format!("0.0.0.0:{}", args.port1 + 1).parse().unwrap();

        // If the code is running in a docker compose setup (set by the --docker flag);
        // attempt to lookup the peer via DNS. The compose networking interface
        // will add an alias for party0 for the first peer and party1 for the
        // second. If not running on docker, dial the peer directly on the
        // loopback interface.
        let peer_addr: SocketAddr = {
            if args.docker {
                let other_host_alias = format!("party{}", if args.party == 1 { 0 } else { 1 });
                let hosts = lookup_host(other_host_alias.as_str()).unwrap();

                println!("Lookup successful for {}... found hosts: {:?}", other_host_alias, hosts);

                format!("{}:{}", hosts[0], args.port2).parse().unwrap()
            } else {
                format!("{}:{}", "127.0.0.1", args.port2).parse().unwrap()
            }
        };
        let mut peer_addr2 = peer_addr;
        peer_addr2.set_port(peer_addr.port() + 1);

        println!("Lookup successful, found peer at {:?}", peer_addr);

        // Build and connect to the network
        let mut net = QuicTwoPartyNet::new(args.party, local_addr, peer_addr);
        Handle::current().block_on(net.connect()).unwrap();

        // Send a byte to give the connection time to establish
        if args.party == 0 {
            Handle::current()
                .block_on(net.send(NetworkOutbound {
                    result_id: 1,
                    payload: NetworkPayload::Bytes(vec![1u8]),
                }))
                .unwrap();
        } else {
            let _recv_bytes = Handle::current().block_on(net.next()).unwrap();
        }

        let beaver_source = PartyIDBeaverSource::new(args.party);
        let fabric = MpcFabric::new(net, beaver_source);

        // ----------------
        // | Test Harness |
        // ----------------

        if args.party == 0 {
            println!("\n\n{}\n", "Running integration tests...".blue());
        }

        // Setup new ports for tests that require a network connection directly
        let mut local_addr = local_addr;
        local_addr.set_port(local_addr.port() + 1);
        let mut peer_addr = peer_addr;
        peer_addr.set_port(peer_addr.port() + 1);
        let test_args = IntegrationTestArgs {
            party_id: args.party,
            local_addr,
            peer_addr,
            fabric: fabric.clone(),
        };
        let mut all_success = true;

        for test in inventory::iter::<IntegrationTest> {
            if args.test.is_some() && args.test.as_deref().unwrap() != test.name {
                continue;
            }

            if args.party == 0 {
                print!("Running {}... ", test.name);
            }

            // Spawn the test in the runtime and drive it to completion
            let test_clone = test.clone();
            let res = (test_clone.test_fn)(&test_args);

            all_success &= validate_success(res, args.party);
        }

        if test_args.party_id == PARTY0 {
            log::info!("Tearing down fabric...");
        }

        thread::sleep(Duration::from_millis(SHUTDOWN_TIMEOUT_MS));
        fabric.shutdown();
        all_success
    });

    // Run the tests and delay shutdown to allow graceful network teardown
    let all_success = runtime.block_on(result).unwrap();

    if all_success {
        if args_clone.party == 0 {
            log::info!("{}", "Integration tests successful!".green(),);
        }

        exit(0);
    }

    exit(-1);
}

/// Setups up logging for the test suite
fn init_logger() {
    // Configure logging
    Builder::new()
        .format(|buf, record| writeln!(buf, "[{}] - {}", record.level(), record.args()))
        .filter(None, LevelFilter::Info)
        .init();
}

/// Prints a success or failure message, returns true if success, false if
/// failure
#[inline]
fn validate_success(res: Result<(), String>, party_id: u64) -> bool {
    if res.is_ok() {
        if party_id == 0 {
            println!("{}", "Success!".green());
        }

        true
    } else {
        println!("{}\n\t{}", "Failure...".red(), res.err().unwrap());
        false
    }
}
