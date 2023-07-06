# MPC-Ristretto
This library provides an abstraction over the `curve25519-dalek` arithmetic implementations ([repo](https://github.com/dalek-cryptography/curve25519-dalek))
that allows for secret-sharing based MPC computations over the algebra. As well, this library includes SPDZ style share authentication for maliciously secure computation.
## Organization
The core of the library lives in `src/`, and the integration tests live in `integration/`. The source folder is organized as follows:

- `network.rs` and `network/` define a P2P transport on top of QUIC (using [quinn](https://github.com/quinn-rs/quinn)) in which two peers open up a bi-directional stream to communicate about `Scalar` and `RistrettoPoint` types. 
- `mpc_scalar.rs` and `mpc_stark.rs` define an unauthenticated (semi-honest secure) wrapper around the Dalek `Scalar` and `RistrettoPoint` respectively. These implementations override arithmetic operations such that the result of these operations is a valid secret sharing of the underlying result. This includes use of the [Beaver Trick](https://link.springer.com/content/pdf/10.1007/3-540-46766-1_34.pdf) for multiplication.
- `authenticated_scalar.rs` and `authenticated_ristretto.rs` define authentication wrappers around `MpcScalar` and `MpcRistrettoPoint` that maintain SPDZ style MACs throughout the computation. These wrappers can be opened in an authenticated commit/reveal interaction that ensures their results have not been tampered with.
- `commitment.rs` defines commitment implementations for both `Scalar` values (Pedersen) and `RistrettoPoint` values (`SHA3_512` hash commitment).
- `macros.rs` defines a series of macros used to aid in arithmetic implementation for borrowed values, wrapped values, etc.
- `beaver.rs` defines an interface the library expects to receive Beaver triplets through. Because the preprocessing functionality is largely an infrastructural burden, only dummy implementations are given. The consumer of this library should implement an appropriate pre-processing functionality.
- `fabric.rs` defines an "MPC Fabric" that effectively acts as a dependency injection layer on top of the network. That is, the `MpcFabric` holds network references, beaver source implementations, and MAC keys; allowing the consumer of the library to allocate secret shared values without passing around these dependencies.

## Tests
Unit tests for isolated parts of the library are available via
```bash
cargo test --lib
```

The bulk of this library's testing is best done with real communication; and so most of the tests are integration tests. The integration tests can be run as
```bash
./run_integration.zsh
```
or more directly as
```bash
docker compose up
```