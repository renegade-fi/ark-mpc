//! Subprotocol definitions for checking MACs on opened values

use ark_ec::CurveGroup;
use ark_mpc::{algebra::Scalar, network::MpcNetwork};

use crate::{beaver_source::ValueMacBatch, error::LowGearError};

use super::LowGear;

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin + Send> LowGear<C, N> {
    /// Open a batch of values and check their MACs
    ///
    /// Returns the opened values
    pub async fn open_and_check_macs(
        &mut self,
        x: &ValueMacBatch<C>,
    ) -> Result<Vec<Scalar<C>>, LowGearError> {
        // Open and reconstruct
        let recovered_values = self.open_batch(&x.values()).await?;

        // Take a linear combination of the values and their macs
        let random_values = self.get_shared_randomness_vec(recovered_values.len()).await?;
        let combined_value = Self::linear_combination(&recovered_values, &random_values);
        let combined_mac = Self::linear_combination(&x.macs(), &random_values);

        // Check the MAC before returning
        self.check_mac(combined_value, combined_mac).await?;
        Ok(recovered_values)
    }

    /// Check the MAC of a given opening
    async fn check_mac(&mut self, x: Scalar<C>, mac: Scalar<C>) -> Result<(), LowGearError> {
        // Compute the mac check expression, then commit/open it
        let mac_check = mac - self.mac_share * x;
        let their_mac_check = self.commit_reveal_single(mac_check).await?;

        if their_mac_check + mac_check != Scalar::zero() {
            return Err(LowGearError::InvalidMac);
        }

        Ok(())
    }

    /// A helper to compute the linear combination of a batch of values
    fn linear_combination(values: &[Scalar<C>], coeffs: &[Scalar<C>]) -> Scalar<C> {
        assert_eq!(values.len(), coeffs.len());
        values.iter().zip(coeffs.iter()).map(|(v, c)| v * c).sum()
    }
}
