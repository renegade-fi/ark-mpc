//! Defines the logic for generating shared triples (a, b, c) which satisfy the
//! identity:
//!      a * b = c
//!
//! These triples are used to define single-round multiplication in the SPDZ
//! protocol

use ark_ec::CurveGroup;
use ark_mpc::network::MpcNetwork;
use mp_spdz_rs::fhe::{ciphertext::CiphertextPoK, plaintext::PlaintextVector};

use crate::error::LowGearError;

use super::LowGear;

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin> LowGear<C, N> {
    /// Generate a single batch of shared triples
    pub async fn generate_triples(&mut self) -> Result<(), LowGearError> {
        // First step; generate random values a and b
        let mut a = PlaintextVector::random_pok_batch(&self.params);
        let b = PlaintextVector::random_pok_batch(&self.params);

        // Compute a plaintext multiplication
        let c = &a * &b;

        // Encrypt `a` and send it to the counterparty
        let my_proof = self.local_keypair.encrypt_and_prove_vector(&mut a);
        self.send_message(my_proof).await?;
        let mut other_proof: CiphertextPoK<C> = self.receive_message().await?;

        let other_pk = self.other_pk.as_ref().expect("setup not run");
        let other_a_enc = other_pk.verify_proof(&mut other_proof);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_helpers::mock_lowgear_with_keys;

    /// Tests the basic triplet generation flow
    #[tokio::test]
    async fn test_triplet_gen() {
        mock_lowgear_with_keys(|mut lowgear| async move {
            lowgear.generate_triples().await.unwrap();
        })
        .await;
    }
}
