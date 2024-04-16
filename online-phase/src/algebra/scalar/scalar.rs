//! Defines the scalar types that form the basis of the MPC algebra

// ----------------------------
// | Scalar Field Definitions |
// ----------------------------

use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign},
};

use ark_ec::CurveGroup;
use ark_ff::{batch_inversion, FftField, Field, One, PrimeField, Zero};
use ark_poly::EvaluationDomain;
use ark_std::UniformRand;
use itertools::Itertools;
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::algebra::{macros::*, ToBytes};
use crate::fabric::{ResultHandle, ResultValue};

// -----------
// | Helpers |
// -----------

/// Computes the number of bytes needed to represent  field element
#[inline]
pub const fn n_bytes_field<F: PrimeField>() -> usize {
    // We add 7 and divide by 8 to emulate a ceiling operation considering that u32
    // division is a floor
    let n_bits = F::MODULUS_BIT_SIZE as usize;
    (n_bits + 7) / 8
}

// ---------------------
// | Scalar Definition |
// ---------------------

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
/// A wrapper around the inner scalar that allows us to implement foreign traits
/// for the `Scalar`
pub struct Scalar<C: CurveGroup>(pub(crate) C::ScalarField);

impl<C: CurveGroup> Scalar<C> {
    /// The underlying field that the scalar wraps
    pub type Field = C::ScalarField;

    /// Construct a scalar from an inner field element
    pub fn new(inner: C::ScalarField) -> Self {
        Scalar(inner)
    }

    /// The scalar field's additive identity
    pub fn zero() -> Self {
        Scalar(C::ScalarField::from(0u8))
    }

    /// The scalar field's multiplicative identity
    pub fn one() -> Self {
        Scalar(C::ScalarField::from(1u8))
    }

    /// Get the inner value of the scalar
    pub fn inner(&self) -> C::ScalarField {
        self.0
    }

    /// Get the bit length of the scalar
    pub fn bit_length() -> usize {
        C::ScalarField::MODULUS_BIT_SIZE as usize
    }

    /// Sample a random field element
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(C::ScalarField::rand(rng))
    }

    /// Compute the multiplicative inverse of the scalar in its field
    pub fn inverse(&self) -> Self {
        Scalar(self.0.inverse().unwrap())
    }

    /// Compute the square root of the given scalar
    pub fn sqrt(&self) -> Option<Self> {
        self.0.sqrt().map(Scalar)
    }

    /// Compute the batch inversion of a list of Scalars
    pub fn batch_inverse(vals: &mut [Self]) {
        let mut values = vals.iter().map(|x| x.0).collect_vec();
        batch_inversion(&mut values);

        for (i, val) in vals.iter_mut().enumerate() {
            *val = Scalar(values[i]);
        }
    }

    /// Compute the exponentiation of the given scalar
    pub fn pow(&self, exp: u64) -> Self {
        Scalar::new(self.0.pow([exp]))
    }

    /// Construct a scalar from the given bytes and reduce modulo the field's
    /// modulus
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        let inner = C::ScalarField::from_be_bytes_mod_order(bytes);
        Scalar(inner)
    }

    /// Convert to big endian bytes
    ///
    /// Pad to the maximum amount of bytes needed so that the resulting bytes
    /// are of predictable length
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let val_biguint = self.to_biguint();
        let mut bytes = val_biguint.to_bytes_be();

        let n_bytes = n_bytes_field::<C::ScalarField>();
        let mut padding = vec![0u8; n_bytes - bytes.len()];
        padding.append(&mut bytes);

        padding
    }

    /// Convert the underlying value to a BigUint
    pub fn to_biguint(&self) -> BigUint {
        self.0.into()
    }

    /// Convert from a `BigUint`
    pub fn from_biguint(val: &BigUint) -> Self {
        let le_bytes = val.to_bytes_le();
        let inner = C::ScalarField::from_le_bytes_mod_order(&le_bytes);
        Scalar(inner)
    }
}

impl<C: CurveGroup> Zero for Scalar<C> {
    fn zero() -> Self {
        Self::zero()
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl<C: CurveGroup> One for Scalar<C> {
    fn one() -> Self {
        Self::one()
    }
}

impl<C: CurveGroup> ToBytes for Scalar<C> {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_be()
    }
}

impl<C: CurveGroup> Display for Scalar<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.to_biguint())
    }
}

impl<C: CurveGroup> Serialize for Scalar<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_bytes_be();
        bytes.serialize(serializer)
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for Scalar<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        let scalar = Scalar::from_be_bytes_mod_order(&bytes);
        Ok(scalar)
    }
}

/// A type alias for a result that resolves to a `Scalar`
pub type ScalarResult<C> = ResultHandle<C, Scalar<C>>;
/// A type alias for a result that resolves to a batch of `Scalar`s
pub type BatchScalarResult<C> = ResultHandle<C, Vec<Scalar<C>>>;

impl<C: CurveGroup> ScalarResult<C> {
    /// Exponentiation
    pub fn pow(&self, exp: u64) -> Self {
        self.fabric().new_gate_op(vec![self.id()], move |mut args| {
            let base: Scalar<C> = args.next().unwrap().into();
            let res = base.inner().pow([exp]);

            ResultValue::Scalar(Scalar::new(res))
        })
    }
}

// --------------
// | Arithmetic |
// --------------

impl<C: CurveGroup> ScalarResult<C> {
    /// Compute the multiplicative inverse of the scalar in its field
    pub fn inverse(&self) -> ScalarResult<C> {
        self.fabric.new_gate_op(vec![self.id], |mut args| {
            let val: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(val.0.inverse().unwrap()))
        })
    }

    /// Compute the inverse of a batch of values
    pub fn batch_inverse(values: &[ScalarResult<C>]) -> Vec<ScalarResult<C>> {
        let n = values.len();
        let fabric = &values[0].fabric;
        let ids = values.iter().map(|v| v.id).collect_vec();

        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let mut scalars: Vec<Scalar<C>> = args.into_iter().map(Into::into).collect_vec();
            Scalar::batch_inverse(&mut scalars);

            scalars.into_iter().map(ResultValue::Scalar).collect_vec()
        })
    }
}

// === Addition === //

impl<C: CurveGroup> Add<&Scalar<C>> for &Scalar<C> {
    type Output = Scalar<C>;

    fn add(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        Scalar(self.0 + rhs.0)
    }
}
impl_borrow_variants!(Scalar<C>, Add, add, +, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&Scalar<C>> for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn add(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(lhs.0 + rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Add, add, +, Scalar<C>, C: CurveGroup);
impl_commutative!(ScalarResult<C>, Add, add, +, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&ScalarResult<C>> for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn add(self, rhs: &ScalarResult<C>) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            let rhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(lhs.0 + rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Add, add, +, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> ScalarResult<C> {
    /// Add two batches of `ScalarResult<C>`s
    pub fn batch_add(a: &[ScalarResult<C>], b: &[ScalarResult<C>]) -> Vec<ScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");

        let n = a.len();
        let fabric = &a[0].fabric;

        let lhs = a.iter().map(|v| v.id);
        let rhs = b.iter().map(|v| v.id);
        let ids = lhs.interleave(rhs).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let mut res = Vec::with_capacity(n);

            for mut chunk in &args.map(Scalar::from).chunks(2) {
                let lhs = chunk.next().unwrap();
                let rhs = chunk.next().unwrap();

                res.push(ResultValue::Scalar(Scalar(lhs.0 + rhs.0)));
            }

            res
        })
    }

    /// Add a batch of `ScalarResult`s to a batch of `Scalar`s
    pub fn batch_add_constant(a: &[ScalarResult<C>], b: &[Scalar<C>]) -> Vec<ScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add constant requires equal length inputs");

        let n = a.len();
        let fabric = &a[0].fabric;
        let b = b.to_vec();

        let ids = a.iter().map(|v| v.id).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let a_vals = args.into_iter().map(Scalar::from).collect_vec();
            a_vals
                .into_iter()
                .zip(b.iter())
                .map(|(a, b)| a + b)
                .map(ResultValue::Scalar)
                .collect_vec()
        })
    }
}

// === AddAssign === //

impl<C: CurveGroup> AddAssign for Scalar<C> {
    fn add_assign(&mut self, rhs: Scalar<C>) {
        *self = *self + rhs;
    }
}

// === Subtraction === //

impl<C: CurveGroup> Sub<&Scalar<C>> for &Scalar<C> {
    type Output = Scalar<C>;

    fn sub(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        Scalar(self.0 - rhs.0)
    }
}
impl_borrow_variants!(Scalar<C>, Sub, sub, -, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&Scalar<C>> for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn sub(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(lhs.0 - rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Sub, sub, -, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&ScalarResult<C>> for &Scalar<C> {
    type Output = ScalarResult<C>;

    fn sub(self, rhs: &ScalarResult<C>) -> Self::Output {
        let lhs = *self;
        rhs.fabric.new_gate_op(vec![rhs.id], move |mut args| {
            let rhs: Scalar<C> = args.next().unwrap().to_owned().into();
            ResultValue::Scalar(lhs - rhs)
        })
    }
}
impl_borrow_variants!(Scalar<C>, Sub, sub, -, ScalarResult<C>, Output=ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&ScalarResult<C>> for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn sub(self, rhs: &ScalarResult<C>) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            let rhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(lhs.0 - rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Sub, sub, -, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> ScalarResult<C> {
    /// Subtract two batches of `ScalarResult`s
    pub fn batch_sub(a: &[ScalarResult<C>], b: &[ScalarResult<C>]) -> Vec<ScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch sub requires equal length inputs");

        let n = a.len();
        let fabric = &a[0].fabric;

        let lhs = a.iter().map(|v| v.id);
        let rhs = b.iter().map(|v| v.id);
        let ids = lhs.interleave(rhs).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let mut res = Vec::with_capacity(n);
            for mut chunk in &args.map(Scalar::from).chunks(2) {
                let lhs = chunk.next().unwrap();
                let rhs = chunk.next().unwrap();

                res.push(ResultValue::Scalar(Scalar(lhs.0 - rhs.0)));
            }

            res
        })
    }

    /// Subtract a batch of `Scalar`s from a batch of `ScalarResult`s
    pub fn batch_sub_constant(a: &[ScalarResult<C>], b: &[Scalar<C>]) -> Vec<ScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add constant requires equal length inputs");

        let n = a.len();
        let fabric = &a[0].fabric;
        let b = b.to_vec();

        let ids = a.iter().map(|v| v.id).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let a_vals = args.into_iter().map(Scalar::from).collect_vec();
            a_vals
                .into_iter()
                .zip(b.iter())
                .map(|(a, b)| a - b)
                .map(ResultValue::Scalar)
                .collect_vec()
        })
    }
}

// === SubAssign === //

impl<C: CurveGroup> SubAssign for Scalar<C> {
    fn sub_assign(&mut self, rhs: Scalar<C>) {
        *self = *self - rhs;
    }
}

// === Multiplication === //

impl<C: CurveGroup> Mul<&Scalar<C>> for &Scalar<C> {
    type Output = Scalar<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        Scalar(self.0 * rhs.0)
    }
}
impl_borrow_variants!(Scalar<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&Scalar<C>> for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(lhs.0 * rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
impl_commutative!(ScalarResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&ScalarResult<C>> for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn mul(self, rhs: &ScalarResult<C>) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            let rhs: Scalar<C> = args.next().unwrap().into();

            ResultValue::Scalar(Scalar(lhs.0 * rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> ScalarResult<C> {
    /// Multiply two batches of `ScalarResult`s
    pub fn batch_mul(a: &[ScalarResult<C>], b: &[ScalarResult<C>]) -> Vec<ScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch mul requires equal length inputs");

        let n = a.len();
        let fabric = &a[0].fabric;

        let lhs = a.iter().map(|v| v.id);
        let rhs = b.iter().map(|v| v.id);
        let ids = lhs.interleave(rhs).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let mut res = Vec::with_capacity(n);

            for mut chunk in &args.map(Scalar::from).chunks(2) {
                let lhs = chunk.next().unwrap();
                let rhs = chunk.next().unwrap();

                res.push(ResultValue::Scalar(Scalar(lhs.0 * rhs.0)));
            }

            res
        })
    }

    /// Multiply a batch of `ScalarResult`s by a batch of `Scalar`s
    pub fn batch_mul_constant(a: &[ScalarResult<C>], b: &[Scalar<C>]) -> Vec<ScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch mul constant requires equal length inputs");

        let n = a.len();
        let fabric = &a[0].fabric;
        let b = b.to_vec();

        let ids = a.iter().map(|v| v.id).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let a_vals = args.into_iter().map(Scalar::from).collect_vec();
            a_vals
                .into_iter()
                .zip(b.iter())
                .map(|(a, b)| a * b)
                .map(ResultValue::Scalar)
                .collect_vec()
        })
    }
}

impl<C: CurveGroup> Neg for &Scalar<C> {
    type Output = Scalar<C>;

    fn neg(self) -> Self::Output {
        Scalar(-self.0)
    }
}
impl_borrow_variants!(Scalar<C>, Neg, neg, -, C: CurveGroup);

impl<C: CurveGroup> Neg for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn neg(self) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id], |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(-lhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Neg, neg, -, C: CurveGroup);

impl<C: CurveGroup> ScalarResult<C> {
    /// Negate a batch of `ScalarResult`s
    pub fn batch_neg(a: &[ScalarResult<C>]) -> Vec<ScalarResult<C>> {
        let n = a.len();
        let fabric = &a[0].fabric;
        let ids = a.iter().map(|v| v.id).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            args.into_iter().map(Scalar::from).map(|x| -x).map(ResultValue::Scalar).collect_vec()
        })
    }
}

// === MulAssign === //

impl<C: CurveGroup> MulAssign for Scalar<C> {
    fn mul_assign(&mut self, rhs: Scalar<C>) {
        *self = *self * rhs;
    }
}

// === Division === //
impl<C: CurveGroup> Div<&Scalar<C>> for &Scalar<C> {
    type Output = Scalar<C>;

    fn div(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        Scalar(self.0 / rhs.0)
    }
}
impl_borrow_variants!(Scalar<C>, Div, div, /, Scalar<C>, C: CurveGroup);

// === FFT and IFFT === //
impl<C: CurveGroup> ScalarResult<C>
where
    C::ScalarField: FftField,
{
    /// Compute the fft of a sequence of `ScalarResult`s
    pub fn fft<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[ScalarResult<C>],
    ) -> Vec<ScalarResult<C>> {
        Self::fft_with_domain(x, D::new(x.len()).unwrap())
    }

    /// Compute the fft of a sequence of `ScalarResult`s with the given domain
    pub fn fft_with_domain<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[ScalarResult<C>],
        domain: D,
    ) -> Vec<ScalarResult<C>> {
        assert!(!x.is_empty(), "Cannot compute fft of empty sequence");
        let n = domain.size();

        let fabric = x[0].fabric();
        let ids = x.iter().map(|v| v.id).collect_vec();

        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let scalars = args.into_iter().map(Scalar::from).map(|x| x.0).collect_vec();

            domain
                .fft(&scalars)
                .into_iter()
                .map(|x| ResultValue::Scalar(Scalar::new(x)))
                .collect_vec()
        })
    }

    /// Compute the ifft of a sequence of `ScalarResult`s
    pub fn ifft<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[ScalarResult<C>],
    ) -> Vec<ScalarResult<C>> {
        Self::ifft_with_domain(x, D::new(x.len()).unwrap())
    }

    /// Compute the ifft of a sequence of `ScalarResult`s with the given domain
    pub fn ifft_with_domain<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[ScalarResult<C>],
        domain: D,
    ) -> Vec<ScalarResult<C>> {
        assert!(!x.is_empty(), "Cannot compute fft of empty sequence");
        let n = domain.size();

        let fabric = x[0].fabric();
        let ids = x.iter().map(|v| v.id).collect_vec();

        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let scalars = args.into_iter().map(Scalar::from).map(|x| x.0).collect_vec();

            domain
                .ifft(&scalars)
                .into_iter()
                .map(|x| ResultValue::Scalar(Scalar::new(x)))
                .collect_vec()
        })
    }
}

// ---------------
// | Conversions |
// ---------------

impl<C: CurveGroup> From<bool> for Scalar<C> {
    fn from(value: bool) -> Self {
        Scalar(C::ScalarField::from(value))
    }
}

impl<C: CurveGroup> From<u8> for Scalar<C> {
    fn from(value: u8) -> Self {
        Scalar(C::ScalarField::from(value))
    }
}

impl<C: CurveGroup> From<u16> for Scalar<C> {
    fn from(value: u16) -> Self {
        Scalar(C::ScalarField::from(value))
    }
}

impl<C: CurveGroup> From<u32> for Scalar<C> {
    fn from(value: u32) -> Self {
        Scalar(C::ScalarField::from(value))
    }
}

impl<C: CurveGroup> From<u64> for Scalar<C> {
    fn from(value: u64) -> Self {
        Scalar(C::ScalarField::from(value))
    }
}

impl<C: CurveGroup> From<u128> for Scalar<C> {
    fn from(value: u128) -> Self {
        Scalar(C::ScalarField::from(value))
    }
}

impl<C: CurveGroup> From<usize> for Scalar<C> {
    fn from(value: usize) -> Self {
        Scalar(C::ScalarField::from(value as u64))
    }
}

impl<C: CurveGroup> From<BigUint> for Scalar<C> {
    fn from(value: BigUint) -> Self {
        Scalar::from_biguint(&value)
    }
}

// -------------------
// | Iterator Traits |
// -------------------

impl<C: CurveGroup> Sum for Scalar<C> {
    fn sum<I: Iterator<Item = Scalar<C>>>(iter: I) -> Self {
        iter.fold(Scalar::zero(), |acc, x| acc + x)
    }
}

impl<C: CurveGroup> Product for Scalar<C> {
    fn product<I: Iterator<Item = Scalar<C>>>(iter: I) -> Self {
        iter.fold(Scalar::one(), |acc, x| acc * x)
    }
}

impl<C: CurveGroup> Product for ScalarResult<C> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let values: Vec<Self> = iter.collect_vec();
        assert!(!values.is_empty(), "Cannot compute product of empty iterator");

        let ids = values.iter().map(|v| v.id()).collect_vec();
        let fabric = values[0].fabric();

        fabric.new_gate_op(ids, move |args| {
            let res = args.map(Scalar::from).product();
            ResultValue::Scalar(res)
        })
    }
}

#[cfg(test)]
mod test {
    use crate::{
        algebra::{poly_test_helpers::TestPolyField, scalar::Scalar, ScalarResult},
        test_helpers::{execute_mock_mpc, mock_fabric, TestCurve},
    };
    use ark_ff::Field;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use futures::future;
    use itertools::Itertools;
    use rand::{thread_rng, Rng, RngCore};

    /// Tests addition of raw scalars in a circuit
    #[tokio::test]
    async fn test_scalar_add() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let expected_res = a + b;

        // Allocate the scalars in a fabric and add them together
        let fabric = mock_fabric();
        let a_alloc = fabric.allocate_scalar(a);
        let b_alloc = fabric.allocate_scalar(b);

        let res = &a_alloc + &b_alloc;
        let res_final = res.await;

        assert_eq!(res_final, expected_res);
        fabric.shutdown();
    }

    #[tokio::test]
    async fn test_batch_add_constant() {
        const N: usize = 1000;
        let mut rng = thread_rng();

        let a = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a + b).collect_vec();

        let (res, _) = execute_mock_mpc(move |fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a_alloc = a.iter().map(|x| fabric.allocate_scalar(*x)).collect_vec();

                let res = ScalarResult::batch_add_constant(&a_alloc, &b);
                future::join_all(res.into_iter()).await
            }
        })
        .await;

        assert_eq!(res, expected_res);
    }

    /// Tests subtraction of raw scalars in the circuit
    #[tokio::test]
    async fn test_scalar_sub() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let expected_res = a - b;

        // Allocate the scalars in a fabric and subtract them
        let fabric = mock_fabric();
        let a_alloc = fabric.allocate_scalar(a);
        let b_alloc = fabric.allocate_scalar(b);

        let res = a_alloc - b_alloc;
        let res_final = res.await;

        assert_eq!(res_final, expected_res);
        fabric.shutdown();
    }

    /// Tests batch subtraction with constant values
    #[tokio::test]
    async fn test_batch_sub_constant() {
        const N: usize = 1000;
        let mut rng = thread_rng();

        let a = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a - b).collect_vec();

        let (res, _) = execute_mock_mpc(move |fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a_alloc = a.iter().map(|x| fabric.allocate_scalar(*x)).collect_vec();

                let res = ScalarResult::batch_sub_constant(&a_alloc, &b);
                future::join_all(res.into_iter()).await
            }
        })
        .await;

        assert_eq!(res, expected_res);
    }

    /// Tests negation of raw scalars in a circuit
    #[tokio::test]
    async fn test_scalar_neg() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);

        let expected_res = -a;

        // Allocate the scalars in a fabric and subtract them
        let fabric = mock_fabric();
        let a_alloc = fabric.allocate_scalar(a);

        let res = -a_alloc;
        let res_final = res.await;

        assert_eq!(res_final, expected_res);
        fabric.shutdown();
    }

    /// Tests multiplication of raw scalars in a circuit
    #[tokio::test]
    async fn test_scalar_mul() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let expected_res = a * b;

        // Allocate the scalars in a fabric and multiply them together
        let fabric = mock_fabric();
        let a_alloc = fabric.allocate_scalar(a);
        let b_alloc = fabric.allocate_scalar(b);

        let res = a_alloc * b_alloc;
        let res_final = res.await;

        assert_eq!(res_final, expected_res);
        fabric.shutdown();
    }

    #[tokio::test]
    async fn test_batch_mul_constant() {
        const N: usize = 1000;
        let mut rng = thread_rng();

        let a = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a * b).collect_vec();

        let (res, _) = execute_mock_mpc(move |fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a_alloc = a.iter().map(|x| fabric.allocate_scalar(*x)).collect_vec();

                let res = ScalarResult::batch_mul_constant(&a_alloc, &b);
                future::join_all(res.into_iter()).await
            }
        })
        .await;

        assert_eq!(res, expected_res);
    }

    /// Tests exponentiation or raw scalars in a circuit
    #[tokio::test]
    async fn test_exp() {
        let mut rng = thread_rng();
        let base = Scalar::<TestCurve>::random(&mut rng);
        let exp = rng.next_u64();

        let expected_res = base.inner().pow([exp as u64]);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let base_allocated = fabric.allocate_scalar(base);
            let res = base_allocated.pow(exp);
            res.await
        })
        .await;

        assert_eq!(res, Scalar::new(expected_res));
    }

    /// Tests fft of scalars allocated in a circuit
    #[tokio::test]
    async fn test_circuit_fft() {
        let mut rng = thread_rng();
        let n: usize = rng.gen_range(1..=100);
        let domain_size = rng.gen_range(n..10 * n);

        let seq = (0..n).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();
        println!("seq.len() = {:?}", seq.len());

        let domain = Radix2EvaluationDomain::<TestPolyField>::new(domain_size).unwrap();
        let fft_res = domain.fft(&seq.iter().map(|s| s.inner()).collect_vec());
        let expected_res = fft_res.into_iter().map(Scalar::new).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let seq = seq.clone();
            async move {
                let seq_alloc = seq.iter().map(|x| fabric.allocate_scalar(*x)).collect_vec();

                let res = ScalarResult::fft_with_domain::<Radix2EvaluationDomain<TestPolyField>>(
                    &seq_alloc, domain,
                );
                future::join_all(res.into_iter()).await
            }
        })
        .await;

        println!("res.len() = {:?}", res.len());
        assert_eq!(res.len(), expected_res.len());
        assert_eq!(res, expected_res);
    }

    /// Tests the ifft of scalars allocated in a circuit
    #[tokio::test]
    async fn test_circuit_ifft() {
        let mut rng = thread_rng();
        let n: usize = rng.gen_range(1..=100);
        let domain_size = rng.gen_range(n..10 * n);

        let seq = (0..n).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();

        let domain = Radix2EvaluationDomain::<TestPolyField>::new(domain_size).unwrap();
        let ifft_res = domain.ifft(&seq.iter().map(|s| s.inner()).collect_vec());
        let expected_res = ifft_res.into_iter().map(Scalar::new).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let seq = seq.clone();
            async move {
                let seq_alloc = seq.iter().map(|x| fabric.allocate_scalar(*x)).collect_vec();

                let res = ScalarResult::ifft_with_domain::<Radix2EvaluationDomain<TestPolyField>>(
                    &seq_alloc, domain,
                );
                future::join_all(res.into_iter()).await
            }
        })
        .await;

        assert_eq!(res.len(), expected_res.len());
        assert_eq!(res, expected_res);
    }
}
