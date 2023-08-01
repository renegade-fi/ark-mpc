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
/// An implementation of a beaver value source that returns
/// beaver triples (0, 0, 0) for party 0 and (1, 1, 1) for party 1
#[cfg(any(feature = "test_helpers", test))]
#[derive(Clone, Debug, Default)]
pub struct PartyIDBeaverSource {
    /// The ID of the local party
    party_id: u64,
}

#[cfg(any(feature = "test_helpers", test))]
impl PartyIDBeaverSource {
    /// Create a new beaver source given the local party_id
    pub fn new(party_id: u64) -> Self {
        Self { party_id }
    }
}

/// The PartyIDBeaverSource returns beaver triplets split statically between the
/// parties. We assume a = 2, b = 3 ==> c = 6. [a] = (1, 1); [b] = (3, 0) [c] = (2, 4)
#[cfg(any(feature = "test_helpers", test))]
impl SharedValueSource for PartyIDBeaverSource {
    fn next_shared_bit(&mut self) -> Scalar {
        // Simply output partyID, assume partyID \in {0, 1}
        assert!(self.party_id == 0 || self.party_id == 1);
        Scalar::from(self.party_id)
    }

    fn next_triplet(&mut self) -> (Scalar, Scalar, Scalar) {
        if self.party_id == 0 {
            (Scalar::from(1u64), Scalar::from(3u64), Scalar::from(2u64))
        } else {
            (Scalar::from(1u64), Scalar::from(0u64), Scalar::from(4u64))
        }
    }

    fn next_shared_inverse_pair(&mut self) -> (Scalar, Scalar) {
        (Scalar::from(self.party_id), Scalar::from(self.party_id))
    }

    fn next_shared_value(&mut self) -> Scalar {
        Scalar::from(self.party_id)
    }
}
