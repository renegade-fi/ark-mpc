//! Defines the subprotocol for generating tuples (a, a^{-1}) for a random value
//! a

use ark_ec::CurveGroup;
use ark_mpc::network::MpcNetwork;

use crate::error::LowGearError;

use super::LowGear;

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin + Send> LowGear<C, N> {
    /// Generate a set of inverse tuples
    pub async fn generate_inverse_tuples(&mut self, n: usize) -> Result<(), LowGearError> {
        // We use one triplet per tuple, so we need at least n triples
        assert!(self.triples.len() >= n, "not enough triplets for {n} inverse tuples");
        let random_values = self.get_authenticated_randomness_vec(2 * n).await?;

        // Split into halves that we will multiply using the Beaver trick
        let (random_values1, random_values2) = random_values.split_at(n);

        Ok(())
    }
}
