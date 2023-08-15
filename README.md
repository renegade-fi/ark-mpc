# MPC-Stark
<div>
  <img
    src="https://github.com/renegade-fi/mpc-stark/actions/workflows/test.yml/badge.svg"
  />
  <img
    src="https://github.com/renegade-fi/mpc-stark/actions/workflows/clippy.yml/badge.svg"
  />
  <img
    src="https://github.com/renegade-fi/mpc-stark/actions/workflows/rustfmt.yml/badge.svg"
  />
  <img
    src="https://img.shields.io/crates/v/mpc-stark"
  />
</div>

## Example
`mpc-stark` provides a malicious secure [SPDZ](https://eprint.iacr.org/2011/535.pdf) style framework for two party secure computation. The circuit is constructed on the fly, by overloading arithmetic operators of MPC types, see the example below in which each of the parties shares a value and together they compute the product:
```rust
use mpc_stark::{
    algebra::scalar::Scalar, beaver::SharedValueSource, network::QuicTwoPartyNet, MpcFabric,
    PARTY0, PARTY1,
};
use rand::thread_rng;

#[tokio::main]
async fn main() {
    // Beaver source should be defined outside of the crate and rely on separate infrastructure
    let beaver = BeaverSource::new();

    let local_addr = "127.0.0.1:8000".parse().unwrap();
    let peer_addr = "127.0.0.1:9000".parse().unwrap();
    let network = QuicTwoPartyNet::new(PARTY0, local_addr, peer_addr);

    // MPC circuit
    let mut rng = thread_rng();
    let my_val = Scalar::random(&mut rng);
    let fabric = MpcFabric::new(network, beaver);

    let a = fabric.share_scalar(my_val, PARTY0 /* sender */); // party0 value
    let b = fabric.share_scalar(my_val, PARTY1 /* sender */); // party1 value
    let c = a * b;

    let res = c.open_authenticated().await.expect("authentication error");
    println!("a * b = {res}");
}

```

## Tests
Unit tests for isolated parts of the library are available via
```bash
cargo test --lib --features test_helpers
```

The bulk of this library's testing is best done with real communication; and so most of the tests are integration tests. The integration tests can be run as
```bash
./run_integration.zsh
```
or more directly as
```bash
docker compose up
```
