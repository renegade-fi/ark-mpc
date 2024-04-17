//! Generates input masks for a party

use ark_ec::CurveGroup;
use ark_mpc::{algebra::Scalar, network::MpcNetwork};
use itertools::Itertools;
use mp_spdz_rs::fhe::{ciphertext::Ciphertext, plaintext::Plaintext};
use rand::rngs::OsRng;

use crate::{error::LowGearError, structs::ValueMacBatch};

use super::LowGear;

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin + Send> LowGear<C, N> {
    /// Generate input masks for the given party
    pub async fn generate_input_masks(&mut self, n: usize) -> Result<(), LowGearError> {
        assert!(
            n <= self.params.plaintext_slots(),
            "can only generate input masks for {} slots",
            self.params.plaintext_slots()
        );

        // Each party generates their values, shares, and mac shares
        let mut rng = OsRng;
        let my_values = (0..n).map(|_| Scalar::<C>::random(&mut rng)).collect_vec();
        let my_share = (0..n).map(|_| Scalar::<C>::random(&mut rng)).collect_vec();

        let mut mac_mask = Plaintext::new(&self.params);
        mac_mask.randomize();
        let my_key = self.mac_share;
        let my_mac_shares =
            my_values.iter().zip(mac_mask.to_scalars()).map(|(x, y)| my_key * x - y).collect_vec();

        let my_values_shares = ValueMacBatch::from_parts(&my_share, &my_mac_shares);
        self.input_masks.add_local_masks(my_values.clone(), my_values_shares.into_inner());

        // Compute the counterparty's shares and mac shares of my values
        let their_share = my_values.iter().zip(my_share.iter()).map(|(x, y)| x - y).collect_vec();
        let other_key_enc = self.other_mac_enc.as_ref().unwrap();
        let values_plaintext = Plaintext::from_scalars(&my_values, &self.params);
        let mut mac_product = other_key_enc * &values_plaintext;
        mac_product.rerandomize(self.other_pk.as_ref().unwrap());

        let their_mac = &mac_product + &mac_mask;

        // Exchange shares and macs
        self.send_network_payload(their_share).await?;
        let my_shares: Vec<Scalar<C>> = self.receive_network_payload().await?;

        self.send_message(&their_mac).await?;
        let my_counterparty_macs: Ciphertext<C> = self.receive_message().await?;
        let mut my_macs = self.local_keypair.decrypt(&my_counterparty_macs).to_scalars();
        my_macs.truncate(n);

        let my_counterparty_shares = ValueMacBatch::from_parts(&my_shares, &my_macs);
        self.input_masks.add_counterparty_masks(my_counterparty_shares);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ark_mpc::PARTY0;

    use crate::test_helpers::mock_lowgear_with_keys;

    /// Tests generating input masks
    #[tokio::test]
    async fn test_generate_input_masks() {
        const N: usize = 100;
        let (party0_res, _) = mock_lowgear_with_keys(|mut lowgear| async move {
            lowgear.generate_input_masks(N).await.unwrap();

            // Open the first party's input masks, verify that they're the same as party 0's
            // cleartext values
            if lowgear.party_id() == PARTY0 {
                let (cleartext, shares) = lowgear.input_masks.get_local_mask_batch(N);
                let opened = lowgear.open_and_check_macs(&shares).await.unwrap();

                cleartext == opened
            } else {
                let shares = lowgear.input_masks.get_counterparty_mask_batch(N);
                lowgear.open_and_check_macs(&shares).await.unwrap();

                true
            }
        })
        .await;

        assert!(party0_res);
    }
}
