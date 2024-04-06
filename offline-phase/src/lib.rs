//! The `offline-phase` defines the low-gear SPDZ (https://eprint.iacr.org/2017/1230.pdf)
//! implementation. This involves generating triples via a shallow FHE circuit
//! and authenticating them via a ZKPoK and the classic SPDZ sacrifice protocol
//!
//! The offline phase runs ahead of any computation to setup a `BeaverSource` in
//! the context of `ark-mpc`. This is done to ensure that the online phase may
//! proceed efficiently without the need for complex public key primitives

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![allow(ambiguous_glob_reexports)]
#![feature(inherent_associated_types)]
#![feature(stmt_expr_attributes)]

pub mod beaver_source;
pub mod error;
pub mod lowgear;

#[cfg(test)]
pub(crate) mod test_helpers {
    use ark_mpc::{
        network::{MockNetwork, UnboundedDuplexStream},
        PARTY0, PARTY1,
    };
    use futures::Future;

    use crate::lowgear::LowGear;

    /// The curve used for testing in this crate
    pub type TestCurve = ark_bn254::G1Projective;

    /// Run a two-party method with a `LowGear` instance setup and in scope
    pub async fn mock_lowgear<F, S, T>(mut f: F) -> (T, T)
    where
        T: Send + 'static,
        S: Future<Output = T> + Send + 'static,
        F: FnMut(LowGear<TestCurve, MockNetwork<TestCurve>>) -> S,
    {
        let (stream1, stream2) = UnboundedDuplexStream::new_duplex_pair();
        let net1 = MockNetwork::new(PARTY0, stream1);
        let net2 = MockNetwork::new(PARTY1, stream2);

        let lowgear1 = LowGear::new(net1);
        let lowgear2 = LowGear::new(net2);

        let task1 = tokio::spawn(f(lowgear1));
        let task2 = tokio::spawn(f(lowgear2));
        let party0_out = task1.await.unwrap();
        let party1_out = task2.await.unwrap();

        (party0_out, party1_out)
    }
}
