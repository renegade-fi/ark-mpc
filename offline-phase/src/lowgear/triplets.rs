//! Defines the logic for generating shared triples (a, b, c) which satisfy the
//! identity:
//!      a * b = c
//!
//! These triples are used to define single-round multiplication in the SPDZ
//! protocol
//!
//! Follows the protocol detailed in https://eprint.iacr.org/2017/1230.pdf (Figure 7)

use ark_ec::CurveGroup;
use ark_mpc::{algebra::Scalar, network::MpcNetwork};
use itertools::izip;
use mp_spdz_rs::fhe::{
    ciphertext::{CiphertextPoK, CiphertextVector},
    plaintext::{Plaintext, PlaintextVector},
};

use crate::{beaver_source::ValueMacBatch, error::LowGearError};

use super::LowGear;

// ----------------------
// | Triplet Generation |
// ----------------------

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin> LowGear<C, N> {
    /// Generate a single batch of shared triples
    pub async fn generate_triples(&mut self) -> Result<(), LowGearError> {
        // First step; generate random values a and b
        let mut a = PlaintextVector::random_pok_batch(&self.params);
        let b = PlaintextVector::random_pok_batch(&self.params);
        let b_prime = PlaintextVector::random_pok_batch(&self.params);

        // Compute a plaintext multiplication
        let c = &a * &b;
        let c_prime = &a * &b_prime;

        // Encrypt `a` and send it to the counterparty
        let other_a_enc = self.exchange_a_values(&mut a).await?;

        // Generate shares of the product and exchange
        let c_shares = self.share_product(&other_a_enc, &b, c).await?;
        let c_prime_shares = self.share_product(&other_a_enc, &b_prime, c_prime).await?;

        // Authenticate the triplets and sacrificial redundant values
        let (a_mac, b_mac, c_mac) = self.authenticate_triplets(&a, &b, &c_shares).await?;
        let a = ValueMacBatch::from_plaintexts(&a, &a_mac);
        let b = ValueMacBatch::from_plaintexts(&b, &b_mac);
        let c = ValueMacBatch::from_plaintexts(&c_shares, &c_mac);

        let b_prime_mac = self.authenticate_vec(&b_prime).await?;
        let c_prime_mac = self.authenticate_vec(&c_prime_shares).await?;
        let b_prime = ValueMacBatch::from_plaintexts(&b_prime, &b_prime_mac);
        let c_prime = ValueMacBatch::from_plaintexts(&c_prime_shares, &c_prime_mac);

        // Sacrifice
        self.sacrifice(&a, &b, &c, &b_prime, &c_prime).await?;

        // Increase the size of self.triples by self.params.ciphertext_pok_batch_size
        self.triples = izip!(a, b, c).collect();
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
        self.send_message(&my_proof).await?;
        let mut other_proof: CiphertextPoK<C> = self.receive_message().await?;

        let other_pk = self.other_pk.as_ref().expect("setup not run");
        let other_a_enc = other_pk.verify_proof(&mut other_proof);

        Ok(other_a_enc)
    }

    // ------------------------------
    // | Authentication + Sacrifice |
    // ------------------------------

    /// Authenticate triplets with the counterparty
    ///
    /// Returns the mac shares for each triplet
    pub(crate) async fn authenticate_triplets(
        &mut self,
        a: &PlaintextVector<C>,
        b: &PlaintextVector<C>,
        c: &PlaintextVector<C>,
    ) -> Result<(PlaintextVector<C>, PlaintextVector<C>, PlaintextVector<C>), LowGearError> {
        let a_macs = self.authenticate_vec(a).await?;
        let b_macs = self.authenticate_vec(b).await?;
        let c_macs = self.authenticate_vec(c).await?;

        Ok((a_macs, b_macs, c_macs))
    }

    /// Authenticate a plaintext vector with the counterparty
    pub async fn authenticate_vec(
        &mut self,
        a: &PlaintextVector<C>,
    ) -> Result<PlaintextVector<C>, LowGearError> {
        let n = a.len();
        let mac_vec = self.get_mac_plaintext_vector(n);
        let other_mac_enc = self.get_other_mac_enc(n);

        let a_mac_shares = &mac_vec * a;
        self.share_product(&other_mac_enc, a, a_mac_shares).await
    }

    /// Execute the SPDZ sacrifice step to verify the triplets' algebraic
    /// identity
    async fn sacrifice(
        &mut self,
        a: &ValueMacBatch<C>,
        b: &ValueMacBatch<C>,
        c: &ValueMacBatch<C>,
        b_prime: &ValueMacBatch<C>,
        c_prime: &ValueMacBatch<C>,
    ) -> Result<(), LowGearError> {
        // Generate a shared random value
        let r = self.get_shared_randomness().await?;

        // Open r * b - b'
        let my_rho = &(b * r) - b_prime;
        let rho = self.open_and_check_macs(&my_rho).await?;

        // Compute the expected rhs of the sacrifice identity
        let rho_a = a * rho.as_slice();
        let c_diff = &(c * r) - c_prime;
        let my_tau = &c_diff - &rho_a;

        // Open tau and check that all values are zero
        let tau = self.open_and_check_macs(&my_tau).await?;

        let zero = Scalar::zero();
        if !tau.into_iter().all(|s| s == zero) {
            return Err(LowGearError::SacrificeError);
        }

        Ok(())
    }

    // --------------------------
    // | Arithmetic Subroutines |
    // --------------------------

    /// Create shares of the product `c` by exchanging homomorphically evaluated
    /// encryptions of `my_b * other_a`
    async fn share_product(
        &mut self,
        other_enc_a: &CiphertextVector<C>,
        my_b_share: &PlaintextVector<C>,
        my_c_share: PlaintextVector<C>,
    ) -> Result<PlaintextVector<C>, LowGearError> {
        let mut c_res = my_c_share;

        // Compute the cross products then share them with the counterparty and compute
        // local shares of `c`
        let cross_products = self.compute_cross_products(other_enc_a, my_b_share, &mut c_res);
        self.exchange_cross_products(cross_products, &mut c_res).await?;

        Ok(c_res)
    }

    /// Compute the cross products in the triplet generation
    fn compute_cross_products(
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
        self.send_message(&cross_products).await?;
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
    use ark_mpc::{
        algebra::Scalar,
        network::{MpcNetwork, NetworkPayload},
        PARTY0,
    };
    use itertools::{izip, Itertools};
    use mp_spdz_rs::fhe::{
        params::BGVParams,
        plaintext::{Plaintext, PlaintextVector},
    };
    use rand::{rngs::OsRng, thread_rng};

    use crate::{
        beaver_source::ValueMacBatch,
        error::LowGearError,
        lowgear::LowGear,
        test_helpers::{mock_lowgear_with_keys, TestCurve},
    };

    // -----------
    // | Helpers |
    // -----------

    /// Generate a vector of random scalar values
    fn random_scalars(n: usize) -> Vec<Scalar<TestCurve>> {
        (0..n).map(|_| Scalar::random(&mut OsRng)).collect()
    }

    /// Create secret shares of each value in the vector
    fn create_shares(
        values: &[Scalar<TestCurve>],
    ) -> (Vec<Scalar<TestCurve>>, Vec<Scalar<TestCurve>>) {
        let mut rng = thread_rng();
        let mut shares1 = Vec::new();
        let mut shares2 = Vec::new();

        for x in values.iter() {
            let r = Scalar::random(&mut rng);
            shares1.push(r);
            shares2.push(x - r);
        }

        (shares1, shares2)
    }

    /// Create authenticated shares of the given values using the given mac key
    fn create_authenticated_shares(
        key: Scalar<TestCurve>,
        values: &[Scalar<TestCurve>],
    ) -> (ValueMacBatch<TestCurve>, ValueMacBatch<TestCurve>) {
        let macs = values.iter().map(|v| v * key).collect_vec();
        let (shares1, shares2) = create_shares(values);
        let (mac_shares1, mac_shares2) = create_shares(&macs);

        let batch1 = ValueMacBatch::from_parts(&shares1, &mac_shares1);
        let batch2 = ValueMacBatch::from_parts(&shares2, &mac_shares2);

        (batch1, batch2)
    }

    /// Generate a plaintext vector with a single element from a vector of
    /// scalars
    fn scalars_to_plaintext_vec(
        scalars: &[Scalar<TestCurve>],
        params: &BGVParams<TestCurve>,
    ) -> PlaintextVector<TestCurve> {
        let mut pt = Plaintext::new(params);
        for (i, s) in scalars.iter().enumerate() {
            pt.set_element(i, *s);
        }

        PlaintextVector::from(&pt)
    }

    /// Get a vector of scalars from a plaintext vector
    fn plaintext_vec_to_scalars(pt_vec: &PlaintextVector<TestCurve>) -> Vec<Scalar<TestCurve>> {
        if pt_vec.is_empty() {
            return vec![];
        }

        let n = pt_vec.len();
        let slots = pt_vec.get(0).num_slots();
        let mut vec = Vec::with_capacity(n * slots);

        for i in 0..n {
            let pt = pt_vec.get(i);
            for j in 0..slots {
                vec.push(pt.get_element(j));
            }
        }

        vec
    }

    /// Send and receive a payload between two `LowGear` instances
    async fn send_receive_payload<T, N>(
        my_val: T,
        lowgear: &mut LowGear<TestCurve, N>,
    ) -> Result<T, LowGearError>
    where
        T: Into<NetworkPayload<TestCurve>> + From<NetworkPayload<TestCurve>> + Send + 'static,
        N: MpcNetwork<TestCurve> + Unpin + Send,
    {
        lowgear.send_network_payload(my_val).await?;
        let their_val: T = lowgear.receive_network_payload().await?;

        Ok(their_val)
    }

    /// Verify the macs on a set of values given the opened shares from both
    /// parties
    fn verify_macs(
        my_share: &[Scalar<TestCurve>],
        their_share: &[Scalar<TestCurve>],
        my_mac: &[Scalar<TestCurve>],
        their_mac: &[Scalar<TestCurve>],
        mac_key: Scalar<TestCurve>,
    ) {
        let n = my_share.len();
        assert_eq!(their_share.len(), n);
        assert_eq!(my_mac.len(), n);
        assert_eq!(their_mac.len(), n);

        for (a1, a2, mac1, mac2) in izip!(my_share, their_share, my_mac, their_mac) {
            let val = a1 + a2;
            let expected = mac_key * val;
            let actual = mac1 + mac2;

            assert_eq!(expected, actual);
        }
    }

    // ---------
    // | Tests |
    // ---------

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
                my_a.push(a.value());
                my_b.push(b.value());
                my_c.push(c.value());
            }

            let their_a = send_receive_payload(my_a.clone(), &mut lowgear).await.unwrap();
            let their_b = send_receive_payload(my_b.clone(), &mut lowgear).await.unwrap();
            let their_c = send_receive_payload(my_c.clone(), &mut lowgear).await.unwrap();

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

    /// Tests authenticating the triples in a batch
    #[tokio::test]
    async fn test_triplet_auth() {
        // The number of plaintext vectors to test
        mock_lowgear_with_keys(|mut lowgear| async move {
            // Generate values for the triplets
            let n_slots = lowgear.params.plaintext_slots();
            let my_a = random_scalars(n_slots);
            let my_b = random_scalars(n_slots);
            let my_c = random_scalars(n_slots);

            // Convert to plaintexts
            let a = scalars_to_plaintext_vec(&my_a, &lowgear.params);
            let b = scalars_to_plaintext_vec(&my_b, &lowgear.params);
            let c = scalars_to_plaintext_vec(&my_c, &lowgear.params);

            // Authenticate the triplets
            let (a_mac, b_mac, c_mac) = lowgear.authenticate_triplets(&a, &b, &c).await.unwrap();
            let a_mac = plaintext_vec_to_scalars(&a_mac);
            let b_mac = plaintext_vec_to_scalars(&b_mac);
            let c_mac = plaintext_vec_to_scalars(&c_mac);

            // Share the scalars, macs, and mac keys with the counterparty then verify
            let their_a = send_receive_payload(my_a.clone(), &mut lowgear).await.unwrap();
            let their_b = send_receive_payload(my_b.clone(), &mut lowgear).await.unwrap();
            let their_c = send_receive_payload(my_c.clone(), &mut lowgear).await.unwrap();

            let their_a_mac = &send_receive_payload(a_mac.clone(), &mut lowgear).await.unwrap();
            let their_b_mac = &send_receive_payload(b_mac.clone(), &mut lowgear).await.unwrap();
            let their_c_mac = &send_receive_payload(c_mac.clone(), &mut lowgear).await.unwrap();

            let their_mac_key =
                send_receive_payload(lowgear.mac_share, &mut lowgear).await.unwrap();
            let mac_key = lowgear.mac_share + their_mac_key;

            // Verify the macs
            verify_macs(&my_a, &their_a, &a_mac, their_a_mac, mac_key);
            verify_macs(&my_b, &their_b, &b_mac, their_b_mac, mac_key);
            verify_macs(&my_c, &their_c, &c_mac, their_c_mac, mac_key);
        })
        .await;
    }

    /// Tests the sacrifice subprotocol
    #[tokio::test]
    async fn test_sacrifice() {
        const N: usize = 100;

        // Define values
        let mac_key = Scalar::random(&mut OsRng);
        let mac_key1 = Scalar::random(&mut OsRng);
        let mac_key2 = mac_key - mac_key1;

        let a = random_scalars(N);
        let b = random_scalars(N);
        let c = a.iter().zip(b.iter()).map(|(x, y)| x * y).collect_vec();
        let b_prime = random_scalars(N);
        let c_prime = a.iter().zip(b_prime.iter()).map(|(x, y)| x * y).collect_vec();

        // Split into shares
        let (a1, a2) = create_authenticated_shares(mac_key, &a);
        let (b1, b2) = create_authenticated_shares(mac_key, &b);
        let (c1, c2) = create_authenticated_shares(mac_key, &c);
        let (b_prime1, b_prime2) = create_authenticated_shares(mac_key, &b_prime);
        let (c_prime1, c_prime2) = create_authenticated_shares(mac_key, &c_prime);

        // Run the sacrifice protocol
        mock_lowgear_with_keys(|mut lowgear| {
            // Set the mac key shares
            let is_party0 = lowgear.network.party_id() == PARTY0;
            let my_share = if is_party0 { mac_key1 } else { mac_key2 };
            lowgear.mac_share = my_share;

            let (my_a, my_b, my_c, my_b_prime, my_c_prime) = if is_party0 {
                (a1.clone(), b1.clone(), c1.clone(), b_prime1.clone(), c_prime1.clone())
            } else {
                (a2.clone(), b2.clone(), c2.clone(), b_prime2.clone(), c_prime2.clone())
            };

            async move {
                lowgear.sacrifice(&my_a, &my_b, &my_c, &my_b_prime, &my_c_prime).await.unwrap();
            }
        })
        .await;
    }
}
