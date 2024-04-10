//! Defines the logic for generating shared triples (a, b, c) which satisfy the
//! identity:
//!      a * b = c
//!
//! These triples are used to define single-round multiplication in the SPDZ
//! protocol
//!
//! Follows the protocol detailed in https://eprint.iacr.org/2017/1230.pdf (Figure 7)

use ark_ec::CurveGroup;
use ark_mpc::network::MpcNetwork;
use mp_spdz_rs::fhe::{
    ciphertext::{CiphertextPoK, CiphertextVector},
    plaintext::{Plaintext, PlaintextVector},
};

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
        let other_a_enc = self.exchange_a_values(&mut a).await?;

        // Generate shares of the product and exchange
        let c_shares = self.share_product(other_a_enc, &b, c).await?;

        Ok(())
    }

    /// Exchange encryptions of the `a` value
    ///
    /// Returns the counterparty's encryption of `a`
    async fn exchange_a_values(
        &mut self,
        a: &mut PlaintextVector<C>,
    ) -> Result<CiphertextVector<C>, LowGearError> {
        // Encrypt `a` and send it to the counterparty
        let my_proof = self.local_keypair.encrypt_and_prove_vector(a);
        self.send_message(my_proof).await?;
        let mut other_proof: CiphertextPoK<C> = self.receive_message().await?;

        let other_pk = self.other_pk.as_ref().expect("setup not run");
        let other_a_enc = other_pk.verify_proof(&mut other_proof);

        Ok(other_a_enc)
    }

    /// Create shares of the product `c` by exchanging homomorphically evaluated
    /// encryptions of `my_b * other_a`
    async fn share_product(
        &mut self,
        other_enc_a: CiphertextVector<C>,
        my_b_share: &PlaintextVector<C>,
        my_c_share: PlaintextVector<C>,
    ) -> Result<PlaintextVector<C>, LowGearError> {
        let mut c_res = my_c_share;

        // Compute the cross products then share them with the counterparty and compute
        // local shares of `c`
        let cross_products =
            self.compute_triplet_cross_products(&other_enc_a, my_b_share, &mut c_res);
        self.exchange_cross_products(cross_products, &mut c_res).await?;

        Ok(c_res)
    }

    /// Compute the cross products in the triplet generation
    fn compute_triplet_cross_products(
        &mut self,
        other_a: &CiphertextVector<C>,
        my_b: &PlaintextVector<C>,
        my_c: &mut PlaintextVector<C>,
    ) -> CiphertextVector<C> {
        let n = other_a.len();
        let mut cross_products = CiphertextVector::new(n, &self.params);

        // Compute the cross products of the local party's `b` share and the encryption
        // of the counterparty's `a` share
        for i in 0..n {
            let a_enc = other_a.get(i);
            let b = my_b.get(i);
            let c = my_c.get(i);

            // Compute the product of `my_b` and `other_enc_a`
            let mut product = &a_enc * &b;

            // Rerandomize the product to add drowning noise and mask it with a random value
            product.rerandomize(self.other_pk.as_ref().unwrap());
            let mut mask = Plaintext::new(&self.params);
            mask.randomize();

            let masked_product = &product + &mask;

            // Subtract the masked product from our share
            let my_share = &c - &mask;
            my_c.set(i, &my_share);
            cross_products.set(i, &masked_product);
        }

        cross_products
    }

    /// Exchange cross products and compute final shares of `c`
    async fn exchange_cross_products(
        &mut self,
        cross_products: CiphertextVector<C>,
        my_c_share: &mut PlaintextVector<C>,
    ) -> Result<(), LowGearError> {
        let n = cross_products.len();

        // Send and receive cross products to/from the counterparty
        self.send_message(cross_products).await?;
        let other_cross_products: CiphertextVector<C> = self.receive_message().await?;

        // Add each cross product to the local party's share of `c`
        for i in 0..n {
            let cross_product = other_cross_products.get(i);
            let c = my_c_share.get(i);

            // Decrypt the term
            let cross_product = self.local_keypair.decrypt(&cross_product);

            // Add the cross product to the local party's share of `c`
            let my_share = &c + &cross_product;
            my_c_share.set(i, &my_share);
        }

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
