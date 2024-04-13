//! Implements the F_rand functionality from the LowGear paper

use ark_ec::CurveGroup;
use ark_mpc::{algebra::Scalar, network::MpcNetwork};
use itertools::Itertools;
use mp_spdz_rs::fhe::plaintext::PlaintextVector;
use rand::rngs::OsRng;

use crate::{beaver_source::ValueMac, error::LowGearError};

use super::LowGear;

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin + Send> LowGear<C, N> {
    /// Generate a single shared random value via commit/reveal
    pub async fn get_shared_randomness(&mut self) -> Result<Scalar<C>, LowGearError> {
        Ok(self.get_shared_randomness_vec(1).await?[0])
    }

    /// Generate a set of shared random values via commit/reveal
    ///
    /// 1. Generate local random values
    /// 2. Commit to the random values
    /// 3. Send & receive the commitments to/from the counterparty
    /// 4. Send & receive the random values to/from the counterparty
    /// 5. Verify commitments and construct shared value
    pub async fn get_shared_randomness_vec(
        &mut self,
        n: usize,
    ) -> Result<Vec<Scalar<C>>, LowGearError> {
        // Generate local random values
        let mut rng = OsRng;
        let my_shares = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
        let their_shares = self.commit_reveal(&my_shares).await?;

        let final_shares = my_shares
            .iter()
            .zip(their_shares.iter())
            .map(|(my_share, their_share)| my_share + their_share)
            .collect_vec();
        Ok(final_shares)
    }

    /// Generate secret shared, authenticated random values
    pub async fn get_authenticated_randomness_vec(
        &mut self,
        n: usize,
    ) -> Result<Vec<ValueMac<C>>, LowGearError> {
        // Each party generates shares locally with the represented value implicitly
        // defined as the sum of the shares
        let mut rng = OsRng;
        let my_shares = (0..n).map(|_| Scalar::<C>::random(&mut rng)).collect_vec();

        let pt_vec = PlaintextVector::from_scalars(&my_shares, &self.params);
        let mut macs = self.authenticate_vec(&pt_vec).await?.to_scalars();

        // Recombine into ValueMac pairs
        macs.truncate(n);
        let res =
            my_shares.into_iter().zip(macs.into_iter()).map(|(v, m)| ValueMac::new(v, m)).collect();

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        beaver_source::ValueMacBatch,
        test_helpers::{mock_lowgear, mock_lowgear_with_keys},
    };

    use super::*;

    /// Tests creating a shared vector of public randomness values
    #[tokio::test]
    async fn test_get_shared_randomness_vec() {
        mock_lowgear(|mut lowgear| async move {
            let n = 5;
            let shares = lowgear.get_shared_randomness_vec(n).await.unwrap();

            assert_eq!(shares.len(), n);

            // Send the shares to one another to verify they are the same
            lowgear.send_network_payload(shares.clone()).await.unwrap();
            let their_shares: Vec<Scalar<_>> = lowgear.receive_network_payload().await.unwrap();

            assert_eq!(shares, their_shares);
        })
        .await;
    }

    /// Tests creating a shared vector of authenticated random values
    #[tokio::test]
    async fn test_get_authenticated_randomness_vec() {
        const N: usize = 100;

        mock_lowgear_with_keys(|mut lowgear| async move {
            let shares = lowgear.get_authenticated_randomness_vec(N).await.unwrap();
            assert_eq!(shares.len(), N);

            // Check the macs on the shares
            lowgear.open_and_check_macs(ValueMacBatch::new(shares)).await.unwrap();
        })
        .await;
    }
}
