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

        // Increase the size of self.triples by self.params.ciphertext_pok_batch_size
        self.triples.reserve(self.params.ciphertext_pok_batch_size());
        for pt_idx in 0..a.len() {
            let plaintext_a = a.get(pt_idx);
            let plaintext_b = b.get(pt_idx);
            let plaintext_c = c_shares.get(pt_idx);

            for slot_idx in 0..plaintext_a.num_slots() as usize {
                let a = plaintext_a.get_element(slot_idx);
                let b = plaintext_b.get_element(slot_idx);
                let c = plaintext_c.get_element(slot_idx);

                self.triples.push((a, b, c));
            }
        }

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
    use ark_mpc::algebra::Scalar;
    use itertools::izip;

    use crate::test_helpers::{mock_lowgear_with_keys, TestCurve};

    /// Tests the basic triplet generation flow
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_triplet_gen() {
        // The number of triplets to test
        mock_lowgear_with_keys(|mut lowgear| async move {
            lowgear.generate_triples().await.unwrap();

            assert_eq!(lowgear.triples.len(), lowgear.params.ciphertext_pok_batch_size());

            // Exchange triples
            let (mut my_a, mut my_b, mut my_c) = (vec![], vec![], vec![]);
            for (a, b, c) in lowgear.triples.iter() {
                my_a.push(*a);
                my_b.push(*b);
                my_c.push(*c);
            }

            lowgear.send_network_payload(my_a.clone()).await.unwrap();
            lowgear.send_network_payload(my_b.clone()).await.unwrap();
            lowgear.send_network_payload(my_c.clone()).await.unwrap();
            let their_a: Vec<Scalar<TestCurve>> = lowgear.receive_network_payload().await.unwrap();
            let their_b: Vec<Scalar<TestCurve>> = lowgear.receive_network_payload().await.unwrap();
            let their_c: Vec<Scalar<TestCurve>> = lowgear.receive_network_payload().await.unwrap();

            // Add together all the shares to get the final values
            for (a_1, a_2, b_1, b_2, c_1, c_2) in izip!(
                my_a.iter(),
                their_a.iter(),
                my_b.iter(),
                their_b.iter(),
                my_c.iter(),
                their_c.iter()
            ) {
                let a = a_1 + a_2;
                let b = b_1 + b_2;
                let c = c_1 + c_2;

                assert_eq!(a * b, c);
            }
        })
        .await;
    }
}
