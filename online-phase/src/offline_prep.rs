//! Defines the Beaver value generation interface
//! as well as a dummy beaver interface for testing

use ark_ec::CurveGroup;
use itertools::Itertools;

use crate::algebra::{Scalar, ScalarShare};

/// OfflinePhase implements both the functionality for:
///     1. Single additively shared values [x] where party 1 holds x_1 and party
///        2 holds x_2 such that x_1 + x_2 = x
///     2. Beaver triplets; additively shared values [a], [b], [c] such that a *
///        b = c
pub trait OfflinePhase<C: CurveGroup>: Send + Sync {
    /// Fetch the next shared single bit
    fn next_shared_bit(&mut self) -> ScalarShare<C>;
    /// Fetch the next shared batch of bits
    fn next_shared_bit_batch(&mut self, num_values: usize) -> Vec<ScalarShare<C>> {
        (0..num_values).map(|_| self.next_shared_bit()).collect_vec()
    }
    /// Fetch the next shared single value
    fn next_shared_value(&mut self) -> ScalarShare<C>;
    /// Fetch a batch of shared single values
    fn next_shared_value_batch(&mut self, num_values: usize) -> Vec<ScalarShare<C>> {
        (0..num_values).map(|_| self.next_shared_value()).collect_vec()
    }
    /// Fetch the next pair of values that are multiplicative inverses of one
    /// another
    fn next_shared_inverse_pair(&mut self) -> (ScalarShare<C>, ScalarShare<C>);
    /// Fetch the next batch of multiplicative inverse pairs
    fn next_shared_inverse_pair_batch(
        &mut self,
        num_pairs: usize,
    ) -> (Vec<ScalarShare<C>>, Vec<ScalarShare<C>>) {
        (0..num_pairs).map(|_| self.next_shared_inverse_pair()).unzip()
    }
    /// Fetch the next beaver triplet
    fn next_triplet(&mut self) -> (ScalarShare<C>, ScalarShare<C>, ScalarShare<C>);
    /// Fetch a batch of beaver triplets
    #[allow(clippy::type_complexity)]
    fn next_triplet_batch(
        &mut self,
        num_triplets: usize,
    ) -> (Vec<ScalarShare<C>>, Vec<ScalarShare<C>>, Vec<ScalarShare<C>>) {
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
/// parties. We assume a = 2, b = 3 ==> c = 6. [a] = (1, 1); [b] = (3, 0) [c] =
/// (2, 4)
///
/// We also assume the MAC key is a secret sharing of 1 with each party holding
/// their own party id as a mac key share
#[cfg(any(feature = "test_helpers", test))]
impl<C: CurveGroup> OfflinePhase<C> for PartyIDBeaverSource {
    fn next_shared_bit(&mut self) -> ScalarShare<C> {
        // Simply output partyID, assume partyID \in {0, 1}
        assert!(self.party_id == 0 || self.party_id == 1);
        let value = Scalar::from(self.party_id);
        ScalarShare::new(value, value)
    }

    fn next_triplet(&mut self) -> (ScalarShare<C>, ScalarShare<C>, ScalarShare<C>) {
        let a = Scalar::from(2u8);
        let b = Scalar::from(3u8);
        let c = Scalar::from(6u8);

        let party_id = Scalar::from(self.party_id);
        let a_mac = party_id * a;
        let b_mac = party_id * b;
        let c_mac = party_id * c;

        let (a_share, b_share, c_share) = if self.party_id == 0 {
            (Scalar::from(1u64), Scalar::from(3u64), Scalar::from(2u64))
        } else {
            (Scalar::from(1u64), Scalar::from(0u64), Scalar::from(4u64))
        };

        (
            ScalarShare::new(a_share, a_mac),
            ScalarShare::new(b_share, b_mac),
            ScalarShare::new(c_share, c_mac),
        )
    }

    fn next_shared_inverse_pair(&mut self) -> (ScalarShare<C>, ScalarShare<C>) {
        (
            ScalarShare::new(Scalar::from(self.party_id), Scalar::from(self.party_id)),
            ScalarShare::new(Scalar::from(self.party_id), Scalar::from(self.party_id)),
        )
    }

    fn next_shared_value(&mut self) -> ScalarShare<C> {
        ScalarShare::new(Scalar::from(self.party_id), Scalar::from(self.party_id))
    }
}
