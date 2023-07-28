//! Defines the Beaver value generation interface
//! as well as a dummy beaver interface for testing

use itertools::Itertools;

use crate::algebra::scalar::Scalar;

/// SharedValueSource implements both the functionality for:
///     1. Single additively shared values [x] where party 1 holds
///        x_1 and party 2 holds x_2 such that x_1 + x_2 = x
///     2. Beaver triplets; additively shared values [a], [b], [c] such
///        that a * b = c
pub trait SharedValueSource: Send + Sync {
    /// Fetch the next shared single bit
    fn next_shared_bit(&mut self) -> Scalar;
    /// Fetch the next shared batch of bits
    fn next_shared_bit_batch(&mut self, num_values: usize) -> Vec<Scalar> {
        (0..num_values)
            .map(|_| self.next_shared_bit())
            .collect_vec()
    }
    /// Fetch the next shared single value
    fn next_shared_value(&mut self) -> Scalar;
    /// Fetch a batch of shared single values
    fn next_shared_value_batch(&mut self, num_values: usize) -> Vec<Scalar> {
        (0..num_values)
            .map(|_| self.next_shared_value())
            .collect_vec()
    }
    /// Fetch the next pair of values that are multiplicative inverses of one another
    fn next_shared_inverse_pair(&mut self) -> (Scalar, Scalar);
    /// Fetch the next batch of multiplicative inverse pairs
    fn next_shared_inverse_pair_batch(&mut self, num_pairs: usize) -> (Vec<Scalar>, Vec<Scalar>) {
        (0..num_pairs)
            .map(|_| self.next_shared_inverse_pair())
            .unzip()
    }
    /// Fetch the next beaver triplet
    fn next_triplet(&mut self) -> (Scalar, Scalar, Scalar);
    /// Fetch a batch of beaver triplets
    fn next_triplet_batch(
        &mut self,
        num_triplets: usize,
    ) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>) {
        let mut a_vals = Vec::with_capacity(num_triplets);
        let mut b_vals = Vec::with_capacity(num_triplets);
        let mut c_vals = Vec::with_capacity(num_triplets);

        for _ in 0..num_triplets {
            let (a, b, c) = self.next_triplet();
            a_vals.push(a);
            b_vals.push(b);
            c_vals.push(c);
        }

        (a_vals, b_vals, c_vals)
    }
}

/// A dummy value source that outputs only ones
/// Used for testing
#[cfg(any(feature = "test_helpers", test))]
#[derive(Clone, Debug, Default)]
pub struct DummySharedScalarSource;

#[cfg(any(feature = "test_helpers", test))]
#[allow(dead_code)]
impl DummySharedScalarSource {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[cfg(any(feature = "test_helpers", test))]
impl SharedValueSource for DummySharedScalarSource {
    fn next_shared_bit(&mut self) -> Scalar {
        Scalar::one()
    }

    fn next_shared_value(&mut self) -> Scalar {
        Scalar::one()
    }

    fn next_shared_inverse_pair(&mut self) -> (Scalar, Scalar) {
        (Scalar::one(), Scalar::one())
    }

    fn next_triplet(&mut self) -> (Scalar, Scalar, Scalar) {
        (Scalar::one(), Scalar::one(), Scalar::one())
    }
}
