//! Wrapper around an MP-SPDZ plaintext that exports a rust-friendly interface

use std::{
    marker::PhantomData,
    ops::{Add, Mul, Sub},
};

use ark_ec::CurveGroup;
use ark_mpc::algebra::Scalar;
use cxx::UniquePtr;

use crate::ffi::{
    add_plaintexts, get_element_bigint, mul_plaintexts, new_plaintext, set_element_bigint,
    sub_plaintexts, Plaintext_mod_prime,
};

use super::{ffi_bigint_to_scalar, params::BGVParams, scalar_to_ffi_bigint};

/// A plaintext in the BGV implementation
///
/// The plaintext is defined over the Scalar field of the curve group
pub struct Plaintext<C: CurveGroup> {
    /// The wrapped MP-SPDZ `Plaintext_mod_prime`
    inner: UniquePtr<Plaintext_mod_prime>,
    /// Phantom
    _phantom: PhantomData<C>,
}

impl<C: CurveGroup> Clone for Plaintext<C> {
    fn clone(&self) -> Self {
        self.as_ref().clone().into()
    }
}

impl<C: CurveGroup> From<UniquePtr<Plaintext_mod_prime>> for Plaintext<C> {
    fn from(inner: UniquePtr<Plaintext_mod_prime>) -> Self {
        Self { inner, _phantom: PhantomData }
    }
}

impl<C: CurveGroup> AsRef<Plaintext_mod_prime> for Plaintext<C> {
    fn as_ref(&self) -> &Plaintext_mod_prime {
        self.inner.as_ref().unwrap()
    }
}

impl<C: CurveGroup> Plaintext<C> {
    /// Create a new plaintext
    pub fn new(params: &BGVParams<C>) -> Self {
        let inner = new_plaintext(params.as_ref());
        Self { inner, _phantom: PhantomData }
    }

    /// Get the number of slots in the plaintext
    pub fn num_slots(&self) -> u32 {
        self.inner.num_slots()
    }

    /// Set the value of an element in the plaintext
    pub fn set_element(&mut self, idx: usize, value: Scalar<C>) {
        let val_bigint = scalar_to_ffi_bigint(value);
        set_element_bigint(self.inner.pin_mut(), idx, val_bigint.as_ref().unwrap());
    }

    /// Get the value of an element in the plaintext
    pub fn get_element(&self, idx: usize) -> Scalar<C> {
        let val_bigint = get_element_bigint(self.as_ref(), idx);
        ffi_bigint_to_scalar(val_bigint.as_ref().unwrap())
    }
}

// --------------
// | Arithmetic |
// --------------

impl<C: CurveGroup> Add for &Plaintext<C> {
    type Output = Plaintext<C>;

    fn add(self, rhs: Self) -> Self::Output {
        add_plaintexts(self.as_ref(), rhs.as_ref()).into()
    }
}
impl<C: CurveGroup> Sub for &Plaintext<C> {
    type Output = Plaintext<C>;

    fn sub(self, rhs: Self) -> Self::Output {
        sub_plaintexts(self.as_ref(), rhs.as_ref()).into()
    }
}

impl<C: CurveGroup> Mul<&Plaintext<C>> for &Plaintext<C> {
    type Output = Plaintext<C>;

    fn mul(self, rhs: &Plaintext<C>) -> Self::Output {
        mul_plaintexts(self.as_ref(), rhs.as_ref()).into()
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;
    use crate::TestCurve;

    /// A helper to get parameters for the tests
    fn get_params() -> BGVParams<TestCurve> {
        BGVParams::new(1 /* n_mults */)
    }

    #[test]
    fn test_add() {
        let mut rng = thread_rng();
        let params = get_params();
        let val1: Scalar<TestCurve> = Scalar::random(&mut rng);
        let val2: Scalar<TestCurve> = Scalar::random(&mut rng);

        let mut plaintext1 = Plaintext::new(&params);
        let mut plaintext2 = Plaintext::new(&params);
        plaintext1.set_element(0, val1);
        plaintext2.set_element(0, val2);

        let expected = val1 + val2;
        let result = &plaintext1 + &plaintext2;
        assert_eq!(result.get_element(0), expected);
    }

    #[test]
    fn test_sub() {
        let mut rng = thread_rng();
        let params = get_params();
        let val1: Scalar<TestCurve> = Scalar::random(&mut rng);
        let val2: Scalar<TestCurve> = Scalar::random(&mut rng);

        let mut plaintext1 = Plaintext::new(&params);
        let mut plaintext2 = Plaintext::new(&params);
        plaintext1.set_element(0, val1);
        plaintext2.set_element(0, val2);

        let expected = val1 - val2;
        let result = &plaintext1 - &plaintext2;
        assert_eq!(result.get_element(0), expected);
    }

    #[test]
    fn test_mul() {
        let mut rng = thread_rng();
        let params = get_params();
        let val1: Scalar<TestCurve> = Scalar::random(&mut rng);
        let val2: Scalar<TestCurve> = Scalar::random(&mut rng);

        let mut plaintext1 = Plaintext::new(&params);
        let mut plaintext2 = Plaintext::new(&params);
        plaintext1.set_element(0, val1);
        plaintext2.set_element(0, val2);

        let expected = val1 * val2;
        let result = &plaintext1 * &plaintext2;
        assert_eq!(result.get_element(0), expected);
    }
}
