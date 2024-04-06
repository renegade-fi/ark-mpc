//! Defines rust FFI bindings for the LowGear implementation in MP-SPDZ
//! written in c++
//!
//! This library is intended to be a thin wrapper around the MP-SPDZ library,
//! and to internalize build and link procedure with the foreign ABI
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![allow(ambiguous_glob_reexports)]
#![feature(inherent_associated_types)]
#![feature(stmt_expr_attributes)]

pub mod ffi;
pub mod fhe;

/// A trait for serializing to bytes
pub trait ToBytes {
    /// Serialize to bytes
    fn to_bytes(&self) -> Vec<u8>;
}

/// A trait for deserializing from bytes with BGV parameters in scope
pub trait FromBytesWithParams<C: CurveGroup> {
    /// Deserialize from bytes
    fn from_bytes(data: &[u8], params: &BGVParams<C>) -> Self;
}

#[allow(clippy::items_after_test_module)]
#[cfg(any(test, feature = "test-helpers"))]
mod test_helpers {
    //! Helper methods for unit tests
    use super::ToBytes;

    /// The curve group to use for testing
    pub type TestCurve = ark_bn254::G1Projective;

    /// Compare two values by byte-serializing them
    pub fn compare_bytes<T: ToBytes>(a: &T, b: &T) -> bool {
        a.to_bytes() == b.to_bytes()
    }
}
use ark_ec::CurveGroup;
use fhe::params::BGVParams;
#[cfg(any(test, feature = "test-helpers"))]
pub use test_helpers::*;

#[cfg(feature = "test-helpers")]
pub mod benchmark_helpers {
    //! Helper methods for benchmarks
    use ark_ec::CurveGroup;
    use ark_mpc::algebra::Scalar;
    use rand::thread_rng;

    use crate::fhe::{params::BGVParams, plaintext::Plaintext};

    /// Get a random plaintext filled with random values
    pub fn random_plaintext<C: CurveGroup>(params: &BGVParams<C>) -> Plaintext<C> {
        let mut rng = thread_rng();
        let mut pt = Plaintext::new(params);

        for i in 0..pt.num_slots() as usize {
            pt.set_element(i, Scalar::random(&mut rng));
        }

        pt
    }
}
