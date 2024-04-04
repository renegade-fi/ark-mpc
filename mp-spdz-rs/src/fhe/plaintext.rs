//! Wrapper around an MP-SPDZ plaintext that exports a rust-friendly interface

use std::{
    marker::PhantomData,
    ops::{Add, Mul, Sub},
};

use ark_ec::CurveGroup;
use cxx::UniquePtr;

use crate::ffi::{
    add_plaintexts, get_element_int, mul_plaintexts, new_plaintext, set_element_int,
    sub_plaintexts, Plaintext_mod_prime,
};

use super::params::BGVParams;

/// A plaintext in the BGV implementation
///
/// The plaintext is defined over the Scalar field of the curve group
pub struct Plaintext<C: CurveGroup> {
    /// The wrapped MP-SPDZ `Plaintext_mod_prime`
    inner: UniquePtr<Plaintext_mod_prime>,
    /// Phantom
    _phantom: PhantomData<C>,
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

    /// Set the value of an element in the plaintext
    pub fn set_element(&mut self, idx: usize, value: u32) {
        set_element_int(self.inner.pin_mut(), idx, value)
    }

    /// Get the value of an element in the plaintext
    pub fn get_element(&self, idx: usize) -> u32 {
        get_element_int(self.as_ref(), idx)
    }
}

impl<C: CurveGroup> From<UniquePtr<Plaintext_mod_prime>> for Plaintext<C> {
    fn from(inner: UniquePtr<Plaintext_mod_prime>) -> Self {
        Self { inner, _phantom: PhantomData }
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
    use rand::{thread_rng, Rng, RngCore};

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
        let val1 = rng.next_u32() / 2;
        let val2 = rng.next_u32() / 2;

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
        let val1 = rng.next_u32();
        let val2 = rng.gen_range(0..val1);

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
        let range = 0..(1u32 << 16);
        let val1 = rng.gen_range(range.clone());
        let val2 = rng.gen_range(range);

        let mut plaintext1 = Plaintext::new(&params);
        let mut plaintext2 = Plaintext::new(&params);
        plaintext1.set_element(0, val1);
        plaintext2.set_element(0, val2);

        let expected = val1 * val2;
        let result = &plaintext1 * &plaintext2;
        assert_eq!(result.get_element(0), expected);
    }
}
