//! Defines the Beaver value generation interface
//! as well as a dummy beaver interface for testing

use ark_ec::CurveGroup;
use itertools::Itertools;

use crate::algebra::{Scalar, ScalarShare};

/// PreprocessingPhase implements both the functionality for:
///     1. Input authentication and sharing
///     2. Shared values from the pre-processing phase
pub trait PreprocessingPhase<C: CurveGroup>: Send + Sync {
    /// dummy
    fn print_use(&self) {}
    // === Input Authentication === //
    /// Get the local party's share of the mac key
    fn get_mac_key_share(&self) -> Scalar<C>;
    /// Get an input mask value for the local party
    ///
    /// That is, a cleartext random value and the local party's share of the
    /// value
    fn next_local_input_mask(&mut self) -> (Scalar<C>, ScalarShare<C>);
    /// Get a batch of input mask values for the local party
    fn next_local_input_mask_batch(
        &mut self,
        num_values: usize,
    ) -> (Vec<Scalar<C>>, Vec<ScalarShare<C>>) {
        (0..num_values).map(|_| self.next_local_input_mask()).unzip()
    }
    /// Get an input mask share for the counterparty
    ///
    /// That is, a share of a random value for which the counterparty holds the
    /// cleartext
    fn next_counterparty_input_mask(&mut self) -> ScalarShare<C>;
    /// Get a batch of input mask shares for the counterparty
    fn next_counterparty_input_mask_batch(&mut self, num_values: usize) -> Vec<ScalarShare<C>> {
        (0..num_values).map(|_| self.next_counterparty_input_mask()).collect_vec()
    }

    // === Shared Values === //
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
        assert!(party_id == 0 || party_id == 1);
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
impl<C: CurveGroup> PreprocessingPhase<C> for PartyIDBeaverSource {
    fn get_mac_key_share(&self) -> Scalar<C> {
        Scalar::from(self.party_id)
    }

    fn next_local_input_mask(&mut self) -> (Scalar<C>, ScalarShare<C>) {
        let party = Scalar::from(self.party_id);
        let value = Scalar::from(3u8);
        let share = party * value;
        let mac = party * value;

        (value, ScalarShare::new(share, mac))
    }

    fn next_counterparty_input_mask(&mut self) -> ScalarShare<C> {
        let party = Scalar::from(self.party_id);
        let value = Scalar::from(3u8) * party;
        let mac = party * value;

        ScalarShare::new(value, mac)
    }

    fn next_shared_bit(&mut self) -> ScalarShare<C> {
        // Simply output partyID, assume partyID \in {0, 1}
        let value = Scalar::from(self.party_id);
        ScalarShare::new(value, value)
    }

    fn next_triplet(&mut self) -> (ScalarShare<C>, ScalarShare<C>, ScalarShare<C>) {
        let a = Scalar::from(2u8);
        let b = Scalar::from(3u8);
        let c = Scalar::from(6u8);

        let key = self.get_mac_key_share();
        let a_mac = key * a;
        let b_mac = key * b;
        let c_mac = key * c;

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
