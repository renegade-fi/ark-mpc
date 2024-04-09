//! Ciphertext wrapper around the MP-SPDZ `Ciphertext` struct

use std::{
    marker::PhantomData,
    ops::{Add, Mul},
    pin::Pin,
};

use ark_ec::CurveGroup;
use cxx::UniquePtr;

use crate::{
    ffi::{self},
    FromBytesWithParams, ToBytes,
};

use super::{keys::BGVPublicKey, params::BGVParams, plaintext::Plaintext};

/// A ciphertext in the BGV implementation
///
/// The ciphertext is defined over the Scalar field of the curve group
pub struct Ciphertext<C: CurveGroup> {
    /// The wrapped MP-SPDZ `Ciphertext`
    pub(crate) inner: UniquePtr<ffi::Ciphertext>,
    /// Phantom
    _phantom: PhantomData<C>,
}

impl<C: CurveGroup> Ciphertext<C> {
    /// Multiply two ciphertexts
    pub fn mul_ciphertext(&self, other: &Self, pk: &BGVPublicKey<C>) -> Self {
        ffi::mul_ciphertexts(self.as_ref(), other.as_ref(), pk.as_ref()).into()
    }
}

impl<C: CurveGroup> Clone for Ciphertext<C> {
    fn clone(&self) -> Self {
        self.as_ref().clone().into()
    }
}

impl<C: CurveGroup> From<UniquePtr<ffi::Ciphertext>> for Ciphertext<C> {
    fn from(inner: UniquePtr<ffi::Ciphertext>) -> Self {
        Self { inner, _phantom: PhantomData }
    }
}

impl<C: CurveGroup> AsRef<ffi::Ciphertext> for Ciphertext<C> {
    fn as_ref(&self) -> &ffi::Ciphertext {
        self.inner.as_ref().unwrap()
    }
}

impl<C: CurveGroup> ToBytes for Ciphertext<C> {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_ref().to_rust_bytes()
    }
}

impl<C: CurveGroup> FromBytesWithParams<C> for Ciphertext<C> {
    fn from_bytes(data: &[u8], params: &BGVParams<C>) -> Self {
        ffi::ciphertext_from_rust_bytes(data, params.as_ref()).into()
    }
}

impl<C: CurveGroup> Add<&Plaintext<C>> for &Ciphertext<C> {
    type Output = Ciphertext<C>;

    fn add(self, rhs: &Plaintext<C>) -> Self::Output {
        ffi::add_plaintext(self.as_ref(), rhs.as_ref()).into()
    }
}

impl<C: CurveGroup> Add for &Ciphertext<C> {
    type Output = Ciphertext<C>;

    fn add(self, rhs: Self) -> Self::Output {
        ffi::add_ciphertexts(self.as_ref(), rhs.as_ref()).into()
    }
}

impl<C: CurveGroup> Mul<&Plaintext<C>> for &Ciphertext<C> {
    type Output = Ciphertext<C>;

    fn mul(self, rhs: &Plaintext<C>) -> Self::Output {
        ffi::mul_plaintext(self.as_ref(), rhs.as_ref()).into()
    }
}

// ---------------------
// | Ciphertext Vector |
// ---------------------

/// A container for a vector of ciphertexts
pub struct CiphertextVector<C: CurveGroup> {
    /// The wrapped MP-SPDZ `CiphertextVector`
    inner: UniquePtr<ffi::CiphertextVector>,
    /// Phantom data to tie the curve group type to this struct
    _phantom: PhantomData<C>,
}

impl<C: CurveGroup> From<&Ciphertext<C>> for CiphertextVector<C> {
    fn from(ct: &Ciphertext<C>) -> Self {
        ffi::new_ciphertext_vector_single(ct.as_ref()).into()
    }
}

impl<C: CurveGroup> From<UniquePtr<ffi::CiphertextVector>> for CiphertextVector<C> {
    fn from(inner: UniquePtr<ffi::CiphertextVector>) -> Self {
        Self { inner, _phantom: PhantomData }
    }
}

impl<C: CurveGroup> CiphertextVector<C> {
    /// Create a new `CiphertextVector` with a specified size
    pub fn new(size: usize, params: &BGVParams<C>) -> Self {
        let inner = ffi::new_ciphertext_vector(size, params.as_ref());
        Self { inner, _phantom: PhantomData }
    }

    /// Get a pinned mutable reference to the inner `CiphertextVector`
    pub fn pin_mut(&mut self) -> Pin<&mut ffi::CiphertextVector> {
        self.inner.pin_mut()
    }

    /// Get the size of the `CiphertextVector`
    pub fn size(&self) -> usize {
        ffi::ciphertext_vector_size(self.inner.as_ref().unwrap())
    }

    /// Add a `Ciphertext` to the end of the `CiphertextVector`
    pub fn push(&mut self, ciphertext: &Ciphertext<C>) {
        ffi::push_ciphertext_vector(self.inner.pin_mut(), ciphertext.as_ref());
    }

    /// Remove the last `Ciphertext` from the `CiphertextVector`
    pub fn pop(&mut self) {
        ffi::pop_ciphertext_vector(self.inner.pin_mut());
    }

    /// Get a `Ciphertext` at a specific index from the `CiphertextVector`
    pub fn get(&self, index: usize) -> Ciphertext<C> {
        let ciphertext = ffi::get_ciphertext_vector_element(self.inner.as_ref().unwrap(), index);
        Ciphertext::from(ciphertext)
    }
}

// -----------------
// | CiphertextPoK |
// -----------------

/// A ciphertext bundle with proof of plaintext knowledge
///
/// Fields are not interpretable, but are used for proof verification, after
/// which a ciphertext is extracted
pub struct CiphertextPoK<C: CurveGroup> {
    /// The wrapped MP-SPDZ `CiphertextPoK`
    pub(crate) inner: UniquePtr<ffi::CiphertextWithProof>,
    /// Phantom
    _phantom: PhantomData<C>,
}

impl<C: CurveGroup> Clone for CiphertextPoK<C> {
    fn clone(&self) -> Self {
        self.as_ref().clone().into()
    }
}

impl<C: CurveGroup> ToBytes for CiphertextPoK<C> {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_ref().to_rust_bytes()
    }
}

impl<C: CurveGroup> FromBytesWithParams<C> for CiphertextPoK<C> {
    fn from_bytes(data: &[u8], _: &BGVParams<C>) -> Self {
        ffi::ciphertext_with_proof_from_rust_bytes(data).into()
    }
}

impl<C: CurveGroup> From<UniquePtr<ffi::CiphertextWithProof>> for CiphertextPoK<C> {
    fn from(inner: UniquePtr<ffi::CiphertextWithProof>) -> Self {
        Self { inner, _phantom: PhantomData }
    }
}

impl<C: CurveGroup> AsRef<ffi::CiphertextWithProof> for CiphertextPoK<C> {
    fn as_ref(&self) -> &ffi::CiphertextWithProof {
        self.inner.as_ref().unwrap()
    }
}

impl<C: CurveGroup> CiphertextPoK<C> {
    /// Get a pinned mutable reference to the inner `CiphertextPoK`
    pub fn pin_mut(&mut self) -> Pin<&mut ffi::CiphertextWithProof> {
        self.inner.pin_mut()
    }
}

#[cfg(test)]
mod test {
    use ark_mpc::algebra::Scalar;
    use rand::thread_rng;

    use crate::fhe::{keys::BGVKeypair, params::BGVParams, plaintext::Plaintext};
    use crate::{compare_bytes, FromBytesWithParams, TestCurve, ToBytes};

    use super::Ciphertext;

    /// Setup the FHE scheme
    fn setup_fhe() -> (BGVParams<TestCurve>, BGVKeypair<TestCurve>) {
        let params = BGVParams::new(1 /* n_mults */);
        let keypair = BGVKeypair::gen(&params);

        (params, keypair)
    }

    /// Get a plaintext with the given value in the first slot
    fn plaintext_int(
        val: Scalar<TestCurve>,
        params: &BGVParams<TestCurve>,
    ) -> Plaintext<TestCurve> {
        let mut plaintext = Plaintext::new(params);
        plaintext.set_element(0, val);

        plaintext
    }

    /// Get the ciphertext with the given value in the first slot
    fn encrypt_int(
        value: Scalar<TestCurve>,
        keypair: &BGVKeypair<TestCurve>,
        params: &BGVParams<TestCurve>,
    ) -> Ciphertext<TestCurve> {
        let plaintext = plaintext_int(value, params);
        keypair.encrypt(&plaintext)
    }

    /// Tests serialization and deserialization of a ciphertext
    #[test]
    fn test_serde() {
        let mut rng = thread_rng();
        let (params, keypair) = setup_fhe();
        let plaintext = plaintext_int(Scalar::random(&mut rng), &params);
        let ciphertext = keypair.encrypt(&plaintext);

        let serialized = ciphertext.to_bytes();
        let deserialized: Ciphertext<TestCurve> = Ciphertext::from_bytes(&serialized, &params);

        assert!(compare_bytes(&deserialized, &ciphertext));
    }

    /// Tests addition of a ciphertext with a plaintext
    #[test]
    fn test_ciphertext_plaintext_addition() {
        let mut rng = thread_rng();
        let (params, mut keypair) = setup_fhe();

        // Add a ciphertext with a plaintext
        let val1 = Scalar::random(&mut rng);
        let val2 = Scalar::random(&mut rng);

        let plaintext = plaintext_int(val2, &params);
        let ciphertext = encrypt_int(val1, &keypair, &params);

        let sum = &ciphertext + &plaintext;

        // Decrypt the sum
        let plaintext_res = keypair.decrypt(&sum);
        let res = plaintext_res.get_element(0);
        let expected = val1 + val2;

        assert_eq!(res, expected);
    }

    /// Tests multiplication of a ciphertext with a plaintext
    #[test]
    fn test_ciphertext_plaintext_multiplication() {
        let mut rng = thread_rng();
        let (params, mut keypair) = setup_fhe();

        // Multiply a ciphertext with a plaintext
        let val1 = Scalar::random(&mut rng);
        let val2 = Scalar::random(&mut rng);

        let plaintext = plaintext_int(val2, &params);
        let ciphertext = encrypt_int(val1, &keypair, &params);

        let product = &ciphertext * &plaintext;

        // Decrypt the product
        let plaintext_res = keypair.decrypt(&product);
        let res = plaintext_res.get_element(0);
        let expected = val1 * val2;

        assert_eq!(res, expected);
    }

    /// Tests addition of two ciphertexts
    #[test]
    fn test_ciphertext_ciphertext_addition() {
        let mut rng = thread_rng();
        let (params, mut keypair) = setup_fhe();

        // Add two ciphertexts
        let val1 = Scalar::random(&mut rng);
        let val2 = Scalar::random(&mut rng);

        let ciphertext1 = encrypt_int(val1, &keypair, &params);
        let ciphertext2 = encrypt_int(val2, &keypair, &params);

        let sum = &ciphertext1 + &ciphertext2;

        // Decrypt the sum
        let plaintext_res = keypair.decrypt(&sum);
        let res = plaintext_res.get_element(0);
        let expected = val1 + val2;

        assert_eq!(res, expected);
    }

    /// Tests multiplication of two ciphertexts
    #[test]
    fn test_ciphertext_ciphertext_multiplication() {
        let mut rng = thread_rng();
        let (params, mut keypair) = setup_fhe();

        // Multiply two ciphertexts
        let val1 = Scalar::random(&mut rng);
        let val2 = Scalar::random(&mut rng);

        let ciphertext1 = encrypt_int(val1, &keypair, &params);
        let ciphertext2 = encrypt_int(val2, &keypair, &params);

        let product = ciphertext1.mul_ciphertext(&ciphertext2, &keypair.public_key());

        // Decrypt the product
        let plaintext_res = keypair.decrypt(&product);
        let res = plaintext_res.get_element(0);
        let expected = val1 * val2;

        assert_eq!(res, expected);
    }
}
