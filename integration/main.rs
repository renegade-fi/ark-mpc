use std::net::SocketAddr;

use clap::Parser;
use colored::Colorize;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, constants};
use dns_lookup::lookup_host;

use mpc_ristretto::network::{QuicTwoPartyNet, MPCNetwork};

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

#[tokio::main]
async fn main() {
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
    
    // Send a value over the network
    println!("Sending party ID to peer...");
    let res = net.broadcast_single_point(base_point_mul(args.party))
        .await
        .unwrap();

    let expected = base_point_mul(
        if args.party == 0 { 1u64 } else { 0u64 }
    );

    assert_eq!(res, expected);
    println!(
        "\n{}", 
        "Integration tests successful!".green(), 
    )
}

/// Computes a * G where G is the generator of the Ristretto group
#[inline]
fn base_point_mul(a: u64) -> RistrettoPoint {
    constants::RISTRETTO_BASEPOINT_POINT * Scalar::from(a)
}