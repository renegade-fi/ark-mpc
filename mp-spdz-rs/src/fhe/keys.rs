//! FHE keypair wrapper for the MP-SPDZ implementation

use std::marker::PhantomData;

use ark_ec::CurveGroup;
use cxx::UniquePtr;

use crate::ffi::{
    decrypt as ffi_decrypt, encrypt as ffi_encrypt, get_pk as ffi_get_pk, get_sk as ffi_get_sk,
    new_keypair as ffi_gen_keypair, FHE_KeyPair, FHE_PK, FHE_SK,
};

use super::{ciphertext::Ciphertext, params::BGVParams, plaintext::Plaintext};

/// A public key in the BGV implementation
pub struct BGVPublicKey<C: CurveGroup> {
    /// The wrapped MP-SPDZ `PublicKey`
    pub(crate) inner: UniquePtr<FHE_PK>,
    /// Phantom
    _phantom: PhantomData<C>,
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
}

/// A secret key in the BGV implementation
pub struct BGVSecretKey<C: CurveGroup> {
    /// The wrapped MP-SPDZ `SecretKey`
    pub(crate) inner: UniquePtr<FHE_SK>,
    /// Phantom
    _phantom: PhantomData<C>,
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

/// A keypair in the BGV implementation
pub struct BGVKeypair<C: CurveGroup> {
    /// The public key
    pub public_key: BGVPublicKey<C>,
    /// The secret key
    pub secret_key: BGVSecretKey<C>,
}

impl<C: CurveGroup> BGVKeypair<C> {
    /// Create a new keypair
    pub fn new(keypair: UniquePtr<FHE_KeyPair>) -> Self {
        let pk = BGVPublicKey::new(ffi_get_pk(keypair.as_ref().unwrap()));
        let sk = BGVSecretKey::new(ffi_get_sk(keypair.as_ref().unwrap()));

        Self { public_key: pk, secret_key: sk }
    }

    /// Generate a keypair
    pub fn gen(params: &BGVParams<C>) -> Self {
        let keypair = ffi_gen_keypair(params.as_ref());
        Self::new(keypair)
    }

    /// Encrypt a plaintext
    pub fn encrypt(&self, plaintext: &Plaintext<C>) -> Ciphertext<C> {
        self.public_key.encrypt(plaintext)
    }

    /// Decrypt a ciphertext
    pub fn decrypt(&mut self, ciphertext: &Ciphertext<C>) -> Plaintext<C> {
        self.secret_key.decrypt(ciphertext)
    }
}
