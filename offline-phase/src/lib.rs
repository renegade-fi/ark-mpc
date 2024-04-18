//! The `offline-phase` defines the low-gear SPDZ (https://eprint.iacr.org/2017/1230.pdf)
//! implementation. This involves generating triples via a shallow FHE circuit
//! and authenticating them via a ZKPoK and the classic SPDZ sacrifice protocol
//!
//! The offline phase runs ahead of any computation to setup a `BeaverSource` in
//! the context of `ark-mpc`. This is done to ensure that the online phase may
//! proceed efficiently without the need for complex public key primitives

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![allow(ambiguous_glob_reexports)]
#![feature(inherent_associated_types)]
#![feature(stmt_expr_attributes)]

pub mod error;
pub mod lowgear;
pub mod structs;

#[cfg(test)]
pub(crate) mod test_helpers {
    use ark_ec::CurveGroup;
    use ark_mpc::{
        algebra::Scalar,
        network::{MockNetwork, UnboundedDuplexStream},
        PARTY0, PARTY1,
    };
    use futures::Future;
    use itertools::Itertools;
    use mp_spdz_rs::fhe::{
        ciphertext::Ciphertext,
        keys::{BGVKeypair, BGVPublicKey},
        params::BGVParams,
        plaintext::Plaintext,
    };
    use rand::thread_rng;

    use crate::{lowgear::LowGear, structs::ValueMacBatch};

    /// The curve used for testing in this crate
    pub type TestCurve = ark_bn254::G1Projective;

    /// Get a plaintext with a single value in the zeroth slot
    pub fn plaintext_val<C: CurveGroup>(val: Scalar<C>, params: &BGVParams<C>) -> Plaintext<C> {
        let mut pt = Plaintext::new(params);
        pt.set_element(0, val);

        pt
    }

    /// Get a plaintext with a single value in all slots
    pub fn plaintext_all<C: CurveGroup>(val: Scalar<C>, params: &BGVParams<C>) -> Plaintext<C> {
        let mut pt = Plaintext::new(params);
        pt.set_all(val);

        pt
    }

    /// Encrypt a single value using the BGV cryptosystem
    ///
    /// Places the element in the zeroth slot of the plaintext
    pub fn encrypt_val<C: CurveGroup>(
        val: Scalar<C>,
        key: &BGVPublicKey<C>,
        params: &BGVParams<C>,
    ) -> Ciphertext<C> {
        let pt = plaintext_val(val, params);
        key.encrypt(&pt)
    }

    /// Encrypt a single value in all slots of a plaintext
    pub fn encrypt_all<C: CurveGroup>(
        val: Scalar<C>,
        key: &BGVPublicKey<C>,
        params: &BGVParams<C>,
    ) -> Ciphertext<C> {
        let pt = plaintext_all(val, params);
        key.encrypt(&pt)
    }

    /// Generate random mock triples for the Beaver trick
    #[allow(clippy::type_complexity)]
    pub fn generate_triples(
        n: usize,
    ) -> (Vec<Scalar<TestCurve>>, Vec<Scalar<TestCurve>>, Vec<Scalar<TestCurve>>) {
        let mut rng = thread_rng();
        let a = (0..n).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();
        let b = (0..n).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();
        let c = a.iter().zip(b.iter()).map(|(a, b)| a * b).collect_vec();

        (a, b, c)
    }

    /// Generate authenticated secret shares of a given set of values
    pub fn generate_authenticated_secret_shares(
        values: &[Scalar<TestCurve>],
        mac_key: Scalar<TestCurve>,
    ) -> (ValueMacBatch<TestCurve>, ValueMacBatch<TestCurve>) {
        let (shares1, shares2) = generate_secret_shares(values);
        let macs = values.iter().map(|value| *value * mac_key).collect_vec();
        let (macs1, macs2) = generate_secret_shares(&macs);

        (ValueMacBatch::from_parts(&shares1, &macs1), ValueMacBatch::from_parts(&shares2, &macs2))
    }

    /// Generate secret shares of a set of values
    pub fn generate_secret_shares(
        values: &[Scalar<TestCurve>],
    ) -> (Vec<Scalar<TestCurve>>, Vec<Scalar<TestCurve>>) {
        let mut rng = thread_rng();
        let mut shares1 = Vec::with_capacity(values.len());
        let mut shares2 = Vec::with_capacity(values.len());
        for value in values {
            let share1 = Scalar::<TestCurve>::random(&mut rng);
            let share2 = value - share1;
            shares1.push(share1);
            shares2.push(share2);
        }

        (shares1, shares2)
    }

    /// Run a two-party method with a `LowGear` instance setup and in scope
    pub async fn mock_lowgear<F, S, T>(f: F) -> (T, T)
    where
        T: Send + 'static,
        S: Future<Output = T> + Send + 'static,
        F: FnMut(LowGear<TestCurve, MockNetwork<TestCurve>>) -> S,
    {
        let (stream1, stream2) = UnboundedDuplexStream::new_duplex_pair();
        let net1 = MockNetwork::new(PARTY0, stream1);
        let net2 = MockNetwork::new(PARTY1, stream2);

        let lowgear1 = LowGear::new(net1);
        let lowgear2 = LowGear::new(net2);

        run_mock_lowgear(f, lowgear1, lowgear2).await
    }

    /// Run a two-party method with a `LowGear` instance, mocking keygen setup
    pub async fn mock_lowgear_with_keys<F, S, T>(f: F) -> (T, T)
    where
        T: Send + 'static,
        S: Future<Output = T> + Send + 'static,
        F: FnMut(LowGear<TestCurve, MockNetwork<TestCurve>>) -> S,
    {
        let (stream1, stream2) = UnboundedDuplexStream::new_duplex_pair();
        let net1 = MockNetwork::new(PARTY0, stream1);
        let net2 = MockNetwork::new(PARTY1, stream2);
        let (lowgear1, lowgear2) = create_lowgear_with_keys(net1, net2);

        run_mock_lowgear(f, lowgear1, lowgear2).await
    }

    /// Run a mock lowgear protocol with `n` Beaver triples pre-generated
    pub async fn mock_lowgear_with_triples<F, S, T>(n: usize, f: F) -> (T, T)
    where
        T: Send + 'static,
        S: Future<Output = T> + Send + 'static,
        F: FnMut(LowGear<TestCurve, MockNetwork<TestCurve>>) -> S,
    {
        let (stream1, stream2) = UnboundedDuplexStream::new_duplex_pair();
        let net1 = MockNetwork::new(PARTY0, stream1);
        let net2 = MockNetwork::new(PARTY1, stream2);

        let (mut lowgear1, mut lowgear2) = create_lowgear_with_keys(net1, net2);

        let mac_key = lowgear1.mac_share + lowgear2.mac_share;
        let (a, b, c) = generate_triples(n);
        let (a1, a2) = generate_authenticated_secret_shares(&a, mac_key);
        let (b1, b2) = generate_authenticated_secret_shares(&b, mac_key);
        let (c1, c2) = generate_authenticated_secret_shares(&c, mac_key);

        lowgear1.triples = (a1, b1, c1);
        lowgear2.triples = (a2, b2, c2);

        run_mock_lowgear(f, lowgear1, lowgear2).await
    }

    /// Setup two lowgear instances with keys given the network implementations
    pub fn create_lowgear_with_keys(
        net1: MockNetwork<TestCurve>,
        net2: MockNetwork<TestCurve>,
    ) -> (LowGear<TestCurve, MockNetwork<TestCurve>>, LowGear<TestCurve, MockNetwork<TestCurve>>)
    {
        let mut rng = thread_rng();
        let mut lowgear1 = LowGear::new(net1);
        let mut lowgear2 = LowGear::new(net2);

        // Setup the lowgear instances
        let params1 = &lowgear1.params;
        let params2 = &lowgear2.params;
        let keypair1 = BGVKeypair::gen(params1);
        let keypair2 = BGVKeypair::gen(params2);

        let mac_share1 = Scalar::random(&mut rng);
        let mac_share2 = Scalar::random(&mut rng);

        // Set the local keypairs and mac shares
        lowgear1.local_keypair = keypair1.clone();
        lowgear1.mac_share = mac_share1;
        lowgear2.local_keypair = keypair2.clone();
        lowgear2.mac_share = mac_share2;

        // Set the exchanged values
        lowgear1.other_pk = Some(keypair2.public_key());
        lowgear1.other_mac_enc = Some(encrypt_all(mac_share2, &keypair2.public_key(), params1));
        lowgear2.other_pk = Some(keypair1.public_key());
        lowgear2.other_mac_enc = Some(encrypt_all(mac_share1, &keypair1.public_key(), params2));

        (lowgear1, lowgear2)
    }

    /// Run a two-party protocol using the given `LowGear` instances
    pub async fn run_mock_lowgear<F, S, T>(
        mut f: F,
        lowgear1: LowGear<TestCurve, MockNetwork<TestCurve>>,
        lowgear2: LowGear<TestCurve, MockNetwork<TestCurve>>,
    ) -> (T, T)
    where
        T: Send + 'static,
        S: Future<Output = T> + Send + 'static,
        F: FnMut(LowGear<TestCurve, MockNetwork<TestCurve>>) -> S,
    {
        let task1 = tokio::spawn(f(lowgear1));
        let task2 = tokio::spawn(f(lowgear2));
        let party0_out = task1.await.unwrap();
        let party1_out = task2.await.unwrap();

        (party0_out, party1_out)
    }
}
