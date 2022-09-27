//! Defines the Beaver value generation interface
//! as well as a dummy beaver interface for testing

use curve25519_dalek::scalar::Scalar;

/// SharedValueSource implements both the functionality for:
///     1. Single additively shared values [x] where party 1 holds
///        x_1 and party 2 holds x_2 such that x_1 + x_2 = x
///     2. Beaver triplets; additively shared values [a], [b], [c] such
///        that a * b = c
pub trait SharedValueSource<T> {
    // Fetch the next shared single value
    fn next_shared_value(&mut self) -> T;
    // Fetch the next beaver triplet
    fn next_triplet(&mut self) -> (T, T, T);
}

/// A dummy value source that outputs only ones
/// Used for testing
#[derive(Debug)]
pub(crate) struct DummySharedScalarSource;

#[allow(dead_code)]
impl DummySharedScalarSource {
    pub fn new() -> Self {
        Self
    }
}

impl SharedValueSource<Scalar> for DummySharedScalarSource {
    fn next_shared_value(&mut self) -> Scalar {
        Scalar::one()
    }

    fn next_triplet(&mut self) -> (Scalar, Scalar, Scalar) {
        (Scalar::one(), Scalar::one(), Scalar::one())
    }
}
