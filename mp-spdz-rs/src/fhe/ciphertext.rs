//! Ciphertext wrapper around the MP-SPDZ `Ciphertext` struct

use std::{
    marker::PhantomData,
    ops::{Add, Mul},
};

use ark_ec::CurveGroup;
use cxx::UniquePtr;

use crate::ffi::{
    add_ciphertexts as ffi_add_cipher, add_plaintext as ffi_add_plaintext,
    mul_ciphertexts as ffi_mul_ciphertext, mul_plaintext as ffi_mul_plaintext,
    Ciphertext as FfiCiphertext,
};

use super::{keys::BGVPublicKey, plaintext::Plaintext};

/// A ciphertext in the BGV implementation
///
/// The ciphertext is defined over the Scalar field of the curve group
pub struct Ciphertext<C: CurveGroup> {
    /// The wrapped MP-SPDZ `Ciphertext`
    pub(crate) inner: UniquePtr<FfiCiphertext>,
    /// Phantom
    _phantom: PhantomData<C>,
}

impl<C: CurveGroup> Ciphertext<C> {
    /// Multiply two ciphertexts
    pub fn mul_ciphertext(&self, other: &Self, pk: &BGVPublicKey<C>) -> Self {
        ffi_mul_ciphertext(self.as_ref(), other.as_ref(), pk.as_ref()).into()
    }
}

impl<C: CurveGroup> Clone for Ciphertext<C> {
    fn clone(&self) -> Self {
        self.as_ref().clone().into()
    }
}

impl<C: CurveGroup> From<UniquePtr<FfiCiphertext>> for Ciphertext<C> {
    fn from(inner: UniquePtr<FfiCiphertext>) -> Self {
        Self { inner, _phantom: PhantomData }
    }
}

impl<C: CurveGroup> AsRef<FfiCiphertext> for Ciphertext<C> {
    fn as_ref(&self) -> &FfiCiphertext {
        self.inner.as_ref().unwrap()
    }
}

impl<C: CurveGroup> Add<&Plaintext<C>> for &Ciphertext<C> {
    type Output = Ciphertext<C>;

    fn add(self, rhs: &Plaintext<C>) -> Self::Output {
        ffi_add_plaintext(self.as_ref(), rhs.as_ref()).into()
    }
}

impl<C: CurveGroup> Add for &Ciphertext<C> {
    type Output = Ciphertext<C>;

    fn add(self, rhs: Self) -> Self::Output {
        ffi_add_cipher(self.as_ref(), rhs.as_ref()).into()
    }
}

impl<C: CurveGroup> Mul<&Plaintext<C>> for &Ciphertext<C> {
    type Output = Ciphertext<C>;

    fn mul(self, rhs: &Plaintext<C>) -> Self::Output {
        ffi_mul_plaintext(self.as_ref(), rhs.as_ref()).into()
    }
}

#[cfg(test)]
mod test {
    use ark_mpc::algebra::Scalar;
    use rand::thread_rng;

    use crate::fhe::{keys::BGVKeypair, params::BGVParams, plaintext::Plaintext};
    use crate::TestCurve;

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

        let product = ciphertext1.mul_ciphertext(&ciphertext2, &keypair.public_key);

        // Decrypt the product
        let plaintext_res = keypair.decrypt(&product);
        let res = plaintext_res.get_element(0);
        let expected = val1 * val2;

        assert_eq!(res, expected);
    }
}
