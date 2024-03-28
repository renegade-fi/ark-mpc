//! The `offline-phase` defines the low-gear SPDZ (https://eprint.iacr.org/2017/1230.pdf)
//! implementation. This involves generating triples via a shallow FHE circuit
//! and authenticating them via a ZKPoK and the classic SPDZ sacrifice protocol
//!
//! The offline phase runs ahead of any computation to setup a `BeaverSource` in
//! the context of `ark-mpc`. This is done to ensure that the online phase may
//! proceed efficiently without the need for complex public key primitives

// TODO: Implementation
