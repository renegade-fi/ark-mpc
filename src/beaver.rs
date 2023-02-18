//! Defines the Beaver value generation interface
//! as well as a dummy beaver interface for testing

#[cfg(test)]
use curve25519_dalek::scalar::Scalar;
use itertools::Itertools;

/// SharedValueSource implements both the functionality for:
///     1. Single additively shared values [x] where party 1 holds
///        x_1 and party 2 holds x_2 such that x_1 + x_2 = x
///     2. Beaver triplets; additively shared values [a], [b], [c] such
///        that a * b = c
pub trait SharedValueSource<T> {
    /// Fetch the next shared single bit
    fn next_shared_bit(&mut self) -> T;
    /// Fetch the next shared batch of bits
    fn next_shared_bit_batch(&mut self, num_values: usize) -> Vec<T> {
        (0..num_values)
            .map(|_| self.next_shared_bit())
            .collect_vec()
    }
    /// Fetch the next shared single value
    fn next_shared_value(&mut self) -> T;
    /// Fetch a batch of shared single values
    fn next_shared_value_batch(&mut self, num_values: usize) -> Vec<T> {
        (0..num_values)
            .map(|_| self.next_shared_value())
            .collect_vec()
    }
    /// Fetch the next pair of values that are multiplicative inverses of one another
    fn next_shared_inverse_pair(&mut self) -> (T, T);
    /// Fetch the next batch of multiplicative inverse pairs
    fn next_shared_inverse_pair_batch(&mut self, num_pairs: usize) -> Vec<(T, T)> {
        (0..num_pairs)
            .map(|_| self.next_shared_inverse_pair())
            .collect_vec()
    }
    /// Fetch the next beaver triplet
    fn next_triplet(&mut self) -> (T, T, T);
    /// Fetch a batch of beaver triplets
    fn next_triplet_batch(&mut self, num_triplets: usize) -> Vec<(T, T, T)> {
        (0..num_triplets).map(|_| self.next_triplet()).collect_vec()
    }
}

/// A dummy value source that outputs only ones
/// Used for testing
#[cfg(test)]
#[derive(Debug, Default)]
pub struct DummySharedScalarSource;

#[cfg(test)]
#[allow(dead_code)]
impl DummySharedScalarSource {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
impl SharedValueSource<Scalar> for DummySharedScalarSource {
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
