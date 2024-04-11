//! Setup routines for the Lowgear implementation:
//!     - Exchange BGV keys
//!     - Generate MAC keys

use ark_ec::CurveGroup;
use ark_mpc::network::MpcNetwork;
use mp_spdz_rs::fhe::{ciphertext::CiphertextPoK, keys::BGVPublicKey, plaintext::Plaintext};

use crate::{error::LowGearError, lowgear::LowGear};

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin> LowGear<C, N> {
    /// Exchange BGV public keys and mac shares with the counterparty
    pub async fn run_key_exchange(&mut self) -> Result<(), LowGearError> {
        // First, share the public key
        self.send_message(&self.local_keypair.public_key()).await?;
        let counterparty_pk: BGVPublicKey<C> = self.receive_message().await?;

        // Encrypt my mac share under my public key
        let mut pt = Plaintext::new(&self.params);
        pt.set_all(self.mac_share);
        let ct = self.local_keypair.encrypt_and_prove(&pt);

        // Send and receive
        self.send_message(&ct).await?;
        let mut counterparty_mac_pok: CiphertextPoK<C> = self.receive_message().await?;
        let counterparty_mac_enc = counterparty_pk.verify_proof(&mut counterparty_mac_pok);

        self.other_pk = Some(counterparty_pk);
        // The counterparty's MAC share is the first element of the ciphertext vector,
        // which contains padding up to the proof's batching factor
        self.other_mac_enc = Some(counterparty_mac_enc.get(0));
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ark_mpc::{algebra::Scalar, network::MpcNetwork, PARTY0};
    use mp_spdz_rs::fhe::ciphertext::Ciphertext;
    use rand::thread_rng;

    use crate::test_helpers::{encrypt_val, mock_lowgear, plaintext_val, TestCurve};

    /// Tests the setup phase, i.e. that encrypted values are correctly shared
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_key_exchange() {
        let mut rng = thread_rng();
        let val1 = Scalar::<TestCurve>::random(&mut rng);
        let val2 = Scalar::<TestCurve>::random(&mut rng);

        mock_lowgear(|mut lowgear| async move {
            let (my_val, other_val) =
                if lowgear.network.party_id() == PARTY0 { (val1, val2) } else { (val2, val1) };

            lowgear.run_key_exchange().await.unwrap();
            assert!(lowgear.other_pk.is_some());
            assert!(lowgear.other_mac_enc.is_some());

            // Encrypt and send `my_val` to the other party
            let encrypted_val =
                encrypt_val(my_val, lowgear.other_pk.as_ref().unwrap(), &lowgear.params);

            lowgear.send_message(&encrypted_val).await.unwrap();
            let received_val: Ciphertext<TestCurve> = lowgear.receive_message().await.unwrap();

            let decrypted_val = lowgear.local_keypair.decrypt(&received_val);
            assert_eq!(decrypted_val.get_element(0), other_val);

            // Multiply `my_val` with the counterparty's MAC share
            // homomorphically
            let pt = plaintext_val(my_val, &lowgear.params);
            let ct = lowgear.other_mac_enc.as_ref().unwrap() * &pt;

            // Send the result to the other party
            lowgear.send_message(&ct).await.unwrap();
            let received_val: Ciphertext<TestCurve> = lowgear.receive_message().await.unwrap();

            let decrypted_val = lowgear.local_keypair.decrypt(&received_val);
            assert_eq!(decrypted_val.get_element(0), lowgear.mac_share * other_val);
        })
        .await;
    }
}
