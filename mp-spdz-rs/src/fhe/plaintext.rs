//! Wrapper around an MP-SPDZ plaintext that exports a rust-friendly interface

use std::{
    marker::PhantomData,
    ops::{Add, Mul, Sub},
    pin::Pin,
};

use ark_ec::CurveGroup;
use ark_mpc::algebra::Scalar;
use cxx::UniquePtr;

use crate::{ffi, FromBytesWithParams, ToBytes};

use super::{
    ffi_bigint_to_scalar,
    params::{BGVParams, DEFAULT_DROWN_SEC},
    scalar_to_ffi_bigint,
};

/// A plaintext in the BGV implementation
///
/// The plaintext is defined over the Scalar field of the curve group
pub struct Plaintext<C: CurveGroup> {
    /// The wrapped MP-SPDZ `Plaintext_mod_prime`
    inner: UniquePtr<ffi::Plaintext_mod_prime>,
    /// Phantom
    _phantom: PhantomData<C>,
}

impl<C: CurveGroup> Clone for Plaintext<C> {
    fn clone(&self) -> Self {
        self.as_ref().clone().into()
    }
}

impl<C: CurveGroup> From<UniquePtr<ffi::Plaintext_mod_prime>> for Plaintext<C> {
    fn from(inner: UniquePtr<ffi::Plaintext_mod_prime>) -> Self {
        Self { inner, _phantom: PhantomData }
    }
}

impl<C: CurveGroup> AsRef<ffi::Plaintext_mod_prime> for Plaintext<C> {
    fn as_ref(&self) -> &ffi::Plaintext_mod_prime {
        self.inner.as_ref().unwrap()
    }
}

impl<C: CurveGroup> ToBytes for Plaintext<C> {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_ref().to_rust_bytes()
    }
}

impl<C: CurveGroup> FromBytesWithParams<C> for Plaintext<C> {
    fn from_bytes(data: &[u8], params: &BGVParams<C>) -> Self {
        let inner = ffi::plaintext_from_rust_bytes(data, params.as_ref());
        Self { inner, _phantom: PhantomData }
    }
}

impl<C: CurveGroup> Plaintext<C> {
    /// Create a new plaintext
    pub fn new(params: &BGVParams<C>) -> Self {
        let inner = ffi::new_plaintext(params.as_ref());
        Self { inner, _phantom: PhantomData }
    }

    /// Randomize the plaintext
    pub fn randomize(&mut self) {
        ffi::randomize_plaintext(self.inner.pin_mut());
    }

    /// Get the number of slots in the plaintext
    pub fn num_slots(&self) -> usize {
        self.inner.num_slots() as usize
    }

    /// Create a plaintext given a batch of scalars
    pub fn from_scalars(scalars: &[Scalar<C>], params: &BGVParams<C>) -> Self {
        assert!(scalars.len() < params.plaintext_slots(), "not enough plaintext slots");

        let mut pt = Self::new(params);
        for (i, scalar) in scalars.iter().enumerate() {
            pt.set_element(i, *scalar);
        }

        pt
    }

    /// Get a vector of scalars from the plaintext slots
    pub fn to_scalars(&self) -> Vec<Scalar<C>> {
        let mut scalars = Vec::with_capacity(self.num_slots());
        for i in 0..self.num_slots() {
            scalars.push(self.get_element(i));
        }

        scalars
    }

    /// Set each slot with the given value
    pub fn set_all<T: Into<Scalar<C>>>(&mut self, value: T) {
        let val_bigint = scalar_to_ffi_bigint(value.into());
        for i in 0..self.num_slots() {
            ffi::set_element_bigint(self.inner.pin_mut(), i, val_bigint.as_ref().unwrap());
        }
    }

    /// Set the value of an element in the plaintext
    pub fn set_element<T: Into<Scalar<C>>>(&mut self, idx: usize, value: T) {
        let val_bigint = scalar_to_ffi_bigint(value.into());
        ffi::set_element_bigint(self.inner.pin_mut(), idx, val_bigint.as_ref().unwrap());
    }

    /// Get the value of an element in the plaintext
    pub fn get_element(&self, idx: usize) -> Scalar<C> {
        let val_bigint = ffi::get_element_bigint(self.as_ref(), idx);
        ffi_bigint_to_scalar(val_bigint.as_ref().unwrap())
    }
}

// --------------
// | Arithmetic |
// --------------

impl<C: CurveGroup> Add for &Plaintext<C> {
    type Output = Plaintext<C>;

    fn add(self, rhs: Self) -> Self::Output {
        ffi::add_plaintexts(self.as_ref(), rhs.as_ref()).into()
    }
}
impl<C: CurveGroup> Sub for &Plaintext<C> {
    type Output = Plaintext<C>;

    fn sub(self, rhs: Self) -> Self::Output {
        ffi::sub_plaintexts(self.as_ref(), rhs.as_ref()).into()
    }
}

impl<C: CurveGroup> Mul<&Plaintext<C>> for &Plaintext<C> {
    type Output = Plaintext<C>;

    fn mul(self, rhs: &Plaintext<C>) -> Self::Output {
        ffi::mul_plaintexts(self.as_ref(), rhs.as_ref()).into()
    }
}

// --------------------
// | Plaintext Vector |
// --------------------

/// A container for a vector of plaintexts
pub struct PlaintextVector<C: CurveGroup> {
    /// The wrapped MP-SPDZ `PlaintextVector`
    inner: UniquePtr<ffi::PlaintextVector>,
    /// Phantom data to tie the curve group type to this struct
    _phantom: PhantomData<C>,
}

impl<C: CurveGroup> From<&Plaintext<C>> for PlaintextVector<C> {
    fn from(pt: &Plaintext<C>) -> Self {
        ffi::new_plaintext_vector_single(pt.as_ref()).into()
    }
}

impl<C: CurveGroup> From<UniquePtr<ffi::PlaintextVector>> for PlaintextVector<C> {
    fn from(inner: UniquePtr<ffi::PlaintextVector>) -> Self {
        Self { inner, _phantom: PhantomData }
    }
}

impl<C: CurveGroup> PlaintextVector<C> {
    /// Create a new `PlaintextVector` with a specified size
    pub fn new(size: usize, params: &BGVParams<C>) -> Self {
        let inner = ffi::new_plaintext_vector(size, params.as_ref());
        Self { inner, _phantom: PhantomData }
    }

    /// Create a plaintext vector from a vector of scalars, packing them into
    /// slots
    pub fn from_scalars(scalars: &[Scalar<C>], params: &BGVParams<C>) -> Self {
        let mut pt = Self::empty();

        for chunk in scalars.chunks(params.plaintext_slots()) {
            let mut plaintext = Plaintext::new(params);
            for (i, scalar) in chunk.iter().enumerate() {
                plaintext.set_element(i, *scalar);
            }

            pt.push(&plaintext);
        }

        pt
    }

    /// Create a vector of scalars from the plaintext vector
    pub fn to_scalars(&self) -> Vec<Scalar<C>> {
        let mut scalars = Vec::with_capacity(self.total_slots());
        for i in 0..self.len() {
            let plaintext = self.get(i);
            scalars.extend(plaintext.to_scalars());
        }

        scalars
    }

    /// Create a new empty `PlaintextVector`
    pub fn empty() -> Self {
        Self { inner: ffi::new_empty_plaintext_vector(), _phantom: PhantomData }
    }

    /// Generate a random `PlaintextVector` with a specified size
    pub fn random(size: usize, params: &BGVParams<C>) -> Self {
        let inner = ffi::random_plaintext_vector(size, params.as_ref());
        Self { inner, _phantom: PhantomData }
    }

    /// Get the total number of slots in the `PlaintextVector`
    pub fn total_slots(&self) -> usize {
        if self.is_empty() {
            0
        } else {
            self.get(0).num_slots() * self.len()
        }
    }

    /// Generate a random `PlaintextVector` of size equal to the batching width
    /// of the plaintext PoK proof system
    pub fn random_pok_batch(params: &BGVParams<C>) -> Self {
        Self::random(DEFAULT_DROWN_SEC as usize, params)
    }

    /// Get a pinned mutable reference to the inner `PlaintextVector`
    pub fn pin_mut(&mut self) -> Pin<&mut ffi::PlaintextVector> {
        self.inner.pin_mut()
    }

    /// Get the size of the `PlaintextVector`
    pub fn len(&self) -> usize {
        ffi::plaintext_vector_size(self.inner.as_ref().unwrap())
    }

    /// Whether the vector is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Add a `Plaintext` to the end of the `PlaintextVector`
    pub fn push(&mut self, plaintext: &Plaintext<C>) {
        ffi::push_plaintext_vector(self.inner.pin_mut(), plaintext.as_ref());
    }

    /// Remove the last `Plaintext` from the `PlaintextVector`
    pub fn pop(&mut self) {
        ffi::pop_plaintext_vector(self.inner.pin_mut());
    }

    /// Randomize the `PlaintextVector`
    pub fn randomize(&mut self) {
        ffi::randomize_plaintext_vector(self.inner.pin_mut());
    }

    /// Get a `Plaintext` at a specific index from the `PlaintextVector`
    pub fn get(&self, index: usize) -> Plaintext<C> {
        let plaintext = ffi::get_plaintext_vector_element(self.inner.as_ref().unwrap(), index);
        Plaintext::from(plaintext)
    }

    /// Set a `Plaintext` at a specific index in the `PlaintextVector`
    pub fn set(&mut self, index: usize, plaintext: &Plaintext<C>) {
        ffi::set_plaintext_vector_element(self.inner.pin_mut(), index, plaintext.as_ref());
    }
}

impl<C: CurveGroup> From<Vec<Plaintext<C>>> for PlaintextVector<C> {
    fn from(plaintexts: Vec<Plaintext<C>>) -> Self {
        let mut pt_vector = Self::empty();
        for pt in plaintexts {
            pt_vector.push(&pt);
        }
        pt_vector
    }
}

// -------------------------------
// | Plaintext Vector Arithmetic |
// -------------------------------

impl<C: CurveGroup> Add for &PlaintextVector<C> {
    type Output = PlaintextVector<C>;

    #[cfg(not(feature = "parallel"))]
    fn add(self, other: Self) -> Self::Output {
        assert_eq!(self.len(), other.len(), "Vectors must be the same length");

        let mut result = PlaintextVector::empty();
        for i in 0..self.len() {
            let element = &self.get(i) + &other.get(i);
            result.push(&element);
        }
        result
    }

    #[cfg(feature = "parallel")]
    fn add(self, other: Self) -> Self::Output {
        use rayon::iter::{IntoParallelIterator, ParallelIterator};
        assert_eq!(self.len(), other.len(), "Vectors must be the same length");
        let res: Vec<Plaintext<C>> =
            (0..self.len()).into_par_iter().map(|i| &self.get(i) + &other.get(i)).collect();

        PlaintextVector::from(res)
    }
}

impl<C: CurveGroup> Sub for &PlaintextVector<C> {
    type Output = PlaintextVector<C>;

    #[cfg(not(feature = "parallel"))]
    fn sub(self, other: Self) -> Self::Output {
        assert_eq!(self.len(), other.len(), "Vectors must be the same length");
        let mut result = PlaintextVector::empty();
        for i in 0..self.len() {
            let element = &self.get(i) - &other.get(i);
            result.push(&element);
        }
        result
    }

    #[cfg(feature = "parallel")]
    fn sub(self, other: Self) -> Self::Output {
        use rayon::iter::{IntoParallelIterator, ParallelIterator};
        assert_eq!(self.len(), other.len(), "Vectors must be the same length");
        let res: Vec<Plaintext<C>> =
            (0..self.len()).into_par_iter().map(|i| &self.get(i) - &other.get(i)).collect();

        PlaintextVector::from(res)
    }
}

impl<C: CurveGroup> Mul for &PlaintextVector<C> {
    type Output = PlaintextVector<C>;

    #[cfg(not(feature = "parallel"))]
    fn mul(self, other: Self) -> Self::Output {
        assert_eq!(self.len(), other.len(), "Vectors must be the same length");
        let mut result = PlaintextVector::empty();
        for i in 0..self.len() {
            let element = &self.get(i) * &other.get(i);
            result.push(&element);
        }
        result
    }

    #[cfg(feature = "parallel")]
    fn mul(self, other: Self) -> Self::Output {
        use rayon::iter::{IntoParallelIterator, ParallelIterator};
        assert_eq!(self.len(), other.len(), "Vectors must be the same length");
        let res: Vec<Plaintext<C>> =
            (0..self.len()).into_par_iter().map(|i| &self.get(i) * &other.get(i)).collect();

        PlaintextVector::from(res)
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;
    use crate::{compare_bytes, TestCurve};

    /// A helper to get parameters for the tests
    fn get_params() -> BGVParams<TestCurve> {
        BGVParams::new(1 /* n_mults */)
    }

    /// Tests serialization and deserialization of a plaintext
    #[test]
    fn test_serde() {
        let params = get_params();
        let plaintext = Plaintext::new(&params);

        let serialized = plaintext.to_bytes();
        let deserialized = Plaintext::from_bytes(&serialized, &params);

        assert!(compare_bytes(&plaintext, &deserialized))
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
