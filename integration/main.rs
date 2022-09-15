mod network;
use std::net::SocketAddr;

use clap::Parser;
use colored::Colorize;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, constants};
use dns_lookup::lookup_host;

use mpc_ristretto::network::{QuicTwoPartyNet};

use crate::network::{test_send_ristretto, test_send_scalar};

#[derive(Parser, Debug)]
struct Args {
    /// The party id of the 
    #[clap(long, value_parser)]
    party: u64,
    /// The port to accept inbound on
    #[clap(long="port1", value_parser)]
    port1: u64,
    /// The port to expect the counterparty on
    #[clap(long="port2", value_parser)]
    port2: u64
}

#[allow(unused_doc_comments)]
#[tokio::main]
async fn main() {
    /**
     * Setup
     */

    let args = Args::parse();

    // Listen on 0.0.0.0 (all network interfaces) with the given port
    // We do this because listening on localhost when running in a container points to
    // the container's loopback interface, not the docker bridge
    let local_addr: SocketAddr = format!("0.0.0.0:{}", args.port1)
        .parse()
        .unwrap();
    
    // This assumes the code is executing in a docker compose setup like the one in this repo;
    // that is, compose will define a network alias party0 for the first container and party1
    // for the second container
    let peer_addr: SocketAddr = {
        let other_host_alias = format!("party{}", if args.party == 1 { 0 } else { 1 });
        let hosts = lookup_host(other_host_alias.as_str()).unwrap();
        
        println!("Lookup successful for {}... found hosts: {:?}", other_host_alias, hosts);
        
        format!("{}:{}", hosts[0], args.port2)
            .parse()
            .unwrap()
    };

    println!("Lookup successful, found peer at {:?}", peer_addr);

    // Build and connect to the network
    let mut net = QuicTwoPartyNet::new(
        args.party, 
        local_addr, 
        peer_addr 
    );

    net.connect().await
        .unwrap();
    
    /**
     * Test harness
     */

    let mut all_success = true;

    // Test sending a number across the network encoded as a Ristretto point
    print!("Running test_send_ristretto... ");
    let res = test_send_ristretto(args.party, &mut net).await;
    all_success &= validate_success(res);

    // Test sending a number across the network encoded as a Dalek Scalar
    print!("Running test_send_scalar... ");
    let res = test_send_scalar(args.party, &mut net).await;
    all_success &= validate_success(res);

    if all_success {
        println!(
            "\n{}", 
            "Integration tests successful!".green(), 
        )
    }
}

/// Computes a * G where G is the generator of the Ristretto group
#[inline]
pub(crate) fn base_point_mul(a: u64) -> RistrettoPoint {
    constants::RISTRETTO_BASEPOINT_POINT * Scalar::from(a)
}

/// Prints a success or failure message, returns true if success, false if failure
#[inline]
fn validate_success(res: Result<(), String>) -> bool {
    if res.is_ok() {
        println!("{}", "Success!".green());
        true
    } else {
        println!("{}\n\t{}", "Failure...".red(), res.err().unwrap());
        false
    }
}