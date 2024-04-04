//! Defines rust FFI bindings for the LowGear implementation in MP-SPDZ
//! written in c++
//!
//! This library is intended to be a thin wrapper around the MP-SPDZ library,
//! and to internalize build and link procedure with the foreign ABI

pub mod ffi;
pub mod fhe;

#[allow(clippy::items_after_test_module)]
#[cfg(any(test, feature = "test-helpers"))]
mod test_helpers {
    /// The curve group to use for testing
    pub type TestCurve = ark_bn254::G1Projective;
}
#[cfg(any(test, feature = "test-helpers"))]
pub use test_helpers::*;

#[cfg(feature = "test-helpers")]
pub mod benchmark_helpers {
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
