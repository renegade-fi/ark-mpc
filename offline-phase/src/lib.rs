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

pub mod beaver_source;
pub mod error;
pub mod lowgear;

#[cfg(test)]
pub(crate) mod test_helpers {
    use ark_ec::CurveGroup;
    use ark_mpc::{
        algebra::Scalar,
        network::{MockNetwork, UnboundedDuplexStream},
        PARTY0, PARTY1,
    };
    use futures::Future;
    use mp_spdz_rs::fhe::{
        ciphertext::Ciphertext,
        keys::{BGVKeypair, BGVPublicKey},
        params::BGVParams,
        plaintext::Plaintext,
    };
    use rand::thread_rng;

    use crate::lowgear::LowGear;

    /// The curve used for testing in this crate
    pub type TestCurve = ark_bn254::G1Projective;

    /// Get a plaintext with a single value in the zeroth slot
    pub fn plaintext_val<C: CurveGroup>(val: Scalar<C>, params: &BGVParams<C>) -> Plaintext<C> {
        let mut pt = Plaintext::new(params);
        pt.set_element(0, val);

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
        let mut rng = thread_rng();
        let (stream1, stream2) = UnboundedDuplexStream::new_duplex_pair();
        let net1 = MockNetwork::new(PARTY0, stream1);
        let net2 = MockNetwork::new(PARTY1, stream2);

        let mut lowgear1 = LowGear::new(net1);
        let mut lowgear2 = LowGear::new(net2);

        // Setup the lowgear instances
        let params = BGVParams::new_no_mults();
        let keypair1 = BGVKeypair::gen(&params);
        let keypair2 = BGVKeypair::gen(&params);

        let mac_share1 = Scalar::random(&mut rng);
        let mac_share2 = Scalar::random(&mut rng);

        // Set the local keypairs and mac shares
        lowgear1.local_keypair = keypair1.clone();
        lowgear1.mac_share = mac_share1;
        lowgear2.local_keypair = keypair2.clone();
        lowgear2.mac_share = mac_share2;

        // Set the exchanged values
        lowgear1.other_pk = Some(keypair2.public_key());
        lowgear1.other_mac_enc = Some(encrypt_val(mac_share2, &keypair2.public_key(), &params));
        lowgear2.other_pk = Some(keypair1.public_key());
        lowgear2.other_mac_enc = Some(encrypt_val(mac_share1, &keypair1.public_key(), &params));

        run_mock_lowgear(f, lowgear1, lowgear2).await
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
