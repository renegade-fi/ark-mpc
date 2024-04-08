//! FHE keypair wrapper for the MP-SPDZ implementation

use std::marker::PhantomData;

use ark_ec::CurveGroup;
use cxx::UniquePtr;

use crate::{
    ffi::{
        decrypt as ffi_decrypt, encrypt as ffi_encrypt,
        encrypt_and_prove_batch as ffi_encrypt_and_prove_batch, get_pk as ffi_get_pk,
        get_sk as ffi_get_sk, keypair_from_rust_bytes, new_keypair as ffi_gen_keypair,
        pk_from_rust_bytes, sk_from_rust_bytes, CiphertextWithProof, FHE_KeyPair, FHE_PK, FHE_SK,
    },
    FromBytesWithParams, ToBytes,
};

use super::{
    ciphertext::Ciphertext,
    params::{BGVParams, DEFAULT_DROWN_SEC},
    plaintext::{Plaintext, PlaintextVector},
};

// --------------
// | Public Key |
// --------------

/// A public key in the BGV implementation
pub struct BGVPublicKey<C: CurveGroup> {
    /// The wrapped MP-SPDZ `PublicKey`
    pub(crate) inner: UniquePtr<FHE_PK>,
    /// Phantom
    _phantom: PhantomData<C>,
}

impl<C: CurveGroup> Clone for BGVPublicKey<C> {
    fn clone(&self) -> Self {
        self.as_ref().clone().into()
    }
}

impl<C: CurveGroup> From<UniquePtr<FHE_PK>> for BGVPublicKey<C> {
    fn from(inner: UniquePtr<FHE_PK>) -> Self {
        Self { inner, _phantom: PhantomData }
    }
}

impl<C: CurveGroup> AsRef<FHE_PK> for BGVPublicKey<C> {
    fn as_ref(&self) -> &FHE_PK {
        self.inner.as_ref().unwrap()
    }
}

impl<C: CurveGroup> BGVPublicKey<C> {
    /// Create a new public key
    pub fn new(pk: UniquePtr<FHE_PK>) -> Self {
        Self { inner: pk, _phantom: PhantomData }
    }

    /// Encrypt a plaintext
    pub fn encrypt(&self, plaintext: &Plaintext<C>) -> Ciphertext<C> {
        ffi_encrypt(self.as_ref(), plaintext.as_ref()).into()
    }

    /// Encrypt a plaintext and generate a proof of knowledge with it
    pub fn encrypt_and_prove(&self, plaintext: &Plaintext<C>) -> UniquePtr<CiphertextWithProof> {
        // Construct a plaintext vector
        let mut plaintext_vec: PlaintextVector<C> = plaintext.into();
        self.encrypt_and_prove_batch(&mut plaintext_vec)
    }

    /// Encrypt a batch of plaintexts and generate proofs of knowledge with them
    pub fn encrypt_and_prove_batch(
        &self,
        plaintexts: &mut PlaintextVector<C>,
    ) -> UniquePtr<CiphertextWithProof> {
        ffi_encrypt_and_prove_batch(
            &self.as_ref(),
            plaintexts.pin_mut(),
            DEFAULT_DROWN_SEC,
            false, // diag
        )
    }
}

impl<C: CurveGroup> ToBytes for BGVPublicKey<C> {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_ref().to_rust_bytes()
    }
}

impl<C: CurveGroup> FromBytesWithParams<C> for BGVPublicKey<C> {
    fn from_bytes(data: &[u8], params: &BGVParams<C>) -> Self {
        let pk = pk_from_rust_bytes(data, params.as_ref());
        Self::new(pk)
    }
}

// --------------
// | Secret Key |
// --------------

/// A secret key in the BGV implementation
pub struct BGVSecretKey<C: CurveGroup> {
    /// The wrapped MP-SPDZ `SecretKey`
    pub(crate) inner: UniquePtr<FHE_SK>,
    /// Phantom
    _phantom: PhantomData<C>,
}

impl<C: CurveGroup> Clone for BGVSecretKey<C> {
    fn clone(&self) -> Self {
        self.as_ref().clone().into()
    }
}

impl<C: CurveGroup> From<UniquePtr<FHE_SK>> for BGVSecretKey<C> {
    fn from(inner: UniquePtr<FHE_SK>) -> Self {
        Self { inner, _phantom: PhantomData }
    }
}

impl<C: CurveGroup> AsRef<FHE_SK> for BGVSecretKey<C> {
    fn as_ref(&self) -> &FHE_SK {
        self.inner.as_ref().unwrap()
    }
}

impl<C: CurveGroup> BGVSecretKey<C> {
    /// Create a new secret key
    pub fn new(sk: UniquePtr<FHE_SK>) -> Self {
        Self { inner: sk, _phantom: PhantomData }
    }

    /// Decrypt a ciphertext
    pub fn decrypt(&mut self, ciphertext: &Ciphertext<C>) -> Plaintext<C> {
        ffi_decrypt(self.inner.pin_mut(), ciphertext.as_ref()).into()
    }
}

impl<C: CurveGroup> ToBytes for BGVSecretKey<C> {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_ref().to_rust_bytes()
    }
}

impl<C: CurveGroup> FromBytesWithParams<C> for BGVSecretKey<C> {
    fn from_bytes(data: &[u8], params: &BGVParams<C>) -> Self {
        let sk = sk_from_rust_bytes(data, params.as_ref());
        Self::new(sk)
    }
}

// -----------
// | Keypair |
// -----------

/// A keypair in the BGV implementation
pub struct BGVKeypair<C: CurveGroup> {
    /// The MP-SPDZ `FHE_KeyPair` containing the public and secret keys
    pub(crate) inner: UniquePtr<FHE_KeyPair>,
    /// Phantom
    _phantom: PhantomData<C>,
}

impl<C: CurveGroup> Clone for BGVKeypair<C> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), _phantom: PhantomData }
    }
}

impl<C: CurveGroup> From<UniquePtr<FHE_KeyPair>> for BGVKeypair<C> {
    fn from(keypair: UniquePtr<FHE_KeyPair>) -> Self {
        Self { inner: keypair, _phantom: PhantomData }
    }
}

impl<C: CurveGroup> AsRef<FHE_KeyPair> for BGVKeypair<C> {
    fn as_ref(&self) -> &FHE_KeyPair {
        self.inner.as_ref().unwrap()
    }
}

impl<C: CurveGroup> BGVKeypair<C> {
    /// Generate a keypair
    pub fn gen(params: &BGVParams<C>) -> Self {
        let keypair = ffi_gen_keypair(params.as_ref());
        keypair.into()
    }

    /// Get the public key of the pair
    pub fn public_key(&self) -> BGVPublicKey<C> {
        let pk = ffi_get_pk(self.as_ref());
        pk.into()
    }

    /// Get the secret key of the pair
    pub fn secret_key(&self) -> BGVSecretKey<C> {
        let sk = ffi_get_sk(self.as_ref());
        sk.into()
    }

    /// Encrypt a plaintext
    pub fn encrypt(&self, plaintext: &Plaintext<C>) -> Ciphertext<C> {
        self.public_key().encrypt(plaintext)
    }

    /// Encrypt and prove a single plaintext
    pub fn encrypt_and_prove(&self, plaintext: &Plaintext<C>) -> UniquePtr<CiphertextWithProof> {
        self.public_key().encrypt_and_prove(plaintext)
    }

    /// Encrypt and prove a plaintext vector
    pub fn encrypt_and_prove_vector(
        &self,
        plaintexts: &mut PlaintextVector<C>,
    ) -> UniquePtr<CiphertextWithProof> {
        self.public_key().encrypt_and_prove_batch(plaintexts)
    }

    /// Decrypt a ciphertext
    pub fn decrypt(&mut self, ciphertext: &Ciphertext<C>) -> Plaintext<C> {
        self.secret_key().decrypt(ciphertext)
    }
}

impl<C: CurveGroup> ToBytes for BGVKeypair<C> {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_ref().to_rust_bytes()
    }
}

impl<C: CurveGroup> FromBytesWithParams<C> for BGVKeypair<C> {
    fn from_bytes(data: &[u8], params: &BGVParams<C>) -> Self {
        let keypair = keypair_from_rust_bytes(data, params.as_ref());
        keypair.into()
    }
}

#[cfg(test)]
mod test {

    use crate::ffi::Plaintext_mod_prime;
    use crate::fhe::keys::{BGVKeypair, BGVPublicKey, BGVSecretKey};
    use crate::fhe::params::BGVParams;
    use crate::fhe::plaintext::Plaintext;
    use crate::{compare_bytes, FromBytesWithParams, TestCurve, ToBytes};

    /// Tests serialization and deserialization of the public key
    #[test]
    fn test_serde_public_key() {
        let params = BGVParams::<TestCurve>::new_no_mults();
        let keypair = BGVKeypair::gen(&params);

        let serialized = keypair.public_key().to_bytes();
        let deserialized: BGVPublicKey<TestCurve> = BGVPublicKey::from_bytes(&serialized, &params);

        // Compare by re-serializing
        assert!(compare_bytes(&deserialized, &keypair.public_key()));
    }

    /// Tests serialization and deserialization of the secret key
    #[test]
    fn test_serde_secret_key() {
        let params = BGVParams::<TestCurve>::new_no_mults();
        let keypair = BGVKeypair::gen(&params);

        let serialized = keypair.secret_key().to_bytes();
        let deserialized: BGVSecretKey<TestCurve> = BGVSecretKey::from_bytes(&serialized, &params);

        // Compare by re-serializing
        assert!(compare_bytes(&deserialized, &keypair.secret_key()));
    }

    /// Tests serialization and deserialization of the keypair
    #[test]
    fn test_serde_keypair() {
        let params = BGVParams::<TestCurve>::new_no_mults();
        let keypair = BGVKeypair::gen(&params);

        let serialized = keypair.to_bytes();
        let deserialized: BGVKeypair<TestCurve> = BGVKeypair::from_bytes(&serialized, &params);

        // Compare by re-serializing
        assert!(compare_bytes(&deserialized, &keypair));
    }

    /// Tests encrypting and proving a single plaintext
    #[test]
    fn test_encrypt_and_prove_single() {
        let params = BGVParams::<TestCurve>::new_no_mults();
        let keypair = BGVKeypair::gen(&params);

        let mut plaintext = Plaintext::new(&params);
        plaintext.set_element(0, 1u8);

        // For now just test that it doesn't panic
        let _ciphertext = keypair.encrypt_and_prove(&plaintext);
    }
}
