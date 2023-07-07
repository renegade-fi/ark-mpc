//! Defines the scalar types that form the basis of the Starknet algebra

// ----------------------------
// | Scalar Field Definitions |
// ----------------------------

use std::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use ark_ff::{batch_inversion, Field, Fp256, MontBackend, MontConfig, PrimeField};
use itertools::Itertools;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};

use crate::fabric::{cast_args, ResultHandle, ResultValue};

use super::macros::{impl_borrow_variants, impl_commutative};

/// The number of bytes needed to represent an element of the base field
pub const BASE_FIELD_BYTES: usize = 32;
/// The number of bytes in a `Scalar`
pub const SCALAR_BYTES: usize = 32;

/// The config for finite field that the Starknet curve is defined over
#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[generator = "3"]
pub struct StarknetFqConfig;
/// The finite field that the Starknet curve is defined over
pub type StarknetBaseFelt = Fp256<MontBackend<StarknetFqConfig, 4>>;

/// The config for the scalar field of the Starknet curve
#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105526743751716087489154079457884512865583"]
#[generator = "3"]
pub struct StarknetFrConfig;
/// The finite field representing the curve group of the Starknet curve
///
/// Note that this is not the field that the curve is defined over, but field of integers modulo
/// the order of the curve's group, see [here](https://crypto.stackexchange.com/questions/98124/is-the-stark-curve-a-safecurve)
/// for more information
pub(crate) type ScalarInner = Fp256<MontBackend<StarknetFrConfig, 4>>;
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
/// A wrapper around the inner scalar that allows us to implement foreign traits for the `Scalar`
pub struct Scalar(pub(crate) ScalarInner);

// -------------------
// | Implementations |
// -------------------

impl Scalar {
    /// The scalar field's additive identity
    pub fn zero() -> Scalar {
        Scalar(ScalarInner::from(0))
    }

    /// The scalar field's multiplicative identity
    pub fn one() -> Scalar {
        Scalar(ScalarInner::from(1))
    }

    /// Generate a random scalar
    ///
    /// n.b. The `rand::random` method uses `ThreadRng` type which implements
    /// the `CryptoRng` traits
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
        let inner: ScalarInner = rng.sample(rand::distributions::Standard);
        Scalar(inner)
    }

    /// Compute the multiplicative inverse of the scalar in its field
    pub fn inverse(&self) -> Scalar {
        Scalar(self.0.inverse().unwrap())
    }

    /// Compute the batch inversion of a list of Scalars
    pub fn batch_inverse(vals: &mut [Scalar]) {
        let mut values = vals.iter().map(|x| x.0).collect_vec();
        batch_inversion(&mut values);

        for (i, val) in vals.iter_mut().enumerate() {
            *val = Scalar(values[i]);
        }
    }

    /// Construct a scalar from the given bytes and reduce modulo the field's modulus
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Scalar {
        let inner = ScalarInner::from_be_bytes_mod_order(bytes);
        Scalar(inner)
    }

    /// Convert to big endian bytes
    ///
    /// Pad to the maximum amount of bytes needed so that the resulting bytes are
    /// of predictable length
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let val_biguint = self.to_biguint();
        let mut bytes = val_biguint.to_bytes_be();

        let mut padding = vec![0u8; SCALAR_BYTES - bytes.len()];
        padding.append(&mut bytes);

        padding
    }

    /// Convert the underlying value to a BigUint
    pub fn to_biguint(&self) -> BigUint {
        self.0.into()
    }

    /// Convert from a `BigUint`
    pub fn from_biguint(val: &BigUint) -> Scalar {
        let le_bytes = val.to_bytes_le();
        let inner = ScalarInner::from_le_bytes_mod_order(&le_bytes);
        Scalar(inner)
    }
}

impl Serialize for Scalar {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_bytes_be();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        let scalar = Scalar::from_be_bytes_mod_order(&bytes);
        Ok(scalar)
    }
}

// --------------
// | Arithmetic |
// --------------

// === Addition === //

/// A type alias for a result that resolves to a `Scalar`
pub type ScalarResult = ResultHandle<Scalar>;

impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        Scalar(self.0 + rhs.0)
    }
}
impl_borrow_variants!(Scalar, Add, add, +, Scalar);

impl Add<&Scalar> for &ScalarResult {
    type Output = ScalarResult;

    fn add(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let [lhs]: [Scalar; 1] = cast_args(args);
            ResultValue::Scalar(Scalar(lhs.0 + rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult, Add, add, +, Scalar);
impl_commutative!(ScalarResult, Add, add, +, Scalar);

impl Add<&ScalarResult> for &ScalarResult {
    type Output = ScalarResult;

    fn add(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            let [lhs, rhs]: [Scalar; 2] = cast_args(args);
            ResultValue::Scalar(Scalar(lhs.0 + rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult, Add, add, +, ScalarResult);

// === AddAssign === //

impl AddAssign for Scalar {
    fn add_assign(&mut self, rhs: Scalar) {
        *self = *self + rhs;
    }
}

// === Subtraction === //

impl Sub<&Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        Scalar(self.0 - rhs.0)
    }
}
impl_borrow_variants!(Scalar, Sub, sub, -, Scalar);

impl Sub<&Scalar> for &ScalarResult {
    type Output = ScalarResult;

    fn sub(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let [lhs]: [Scalar; 1] = cast_args(args);
            ResultValue::Scalar(Scalar(lhs.0 - rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult, Sub, sub, -, Scalar);
impl_commutative!(ScalarResult, Sub, sub, -, Scalar);

impl Sub<&ScalarResult> for &ScalarResult {
    type Output = ScalarResult;

    fn sub(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            let [lhs, rhs]: [Scalar; 2] = cast_args(args);
            ResultValue::Scalar(Scalar(lhs.0 - rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult, Sub, sub, -, ScalarResult);

// === SubAssign === //

impl SubAssign for Scalar {
    fn sub_assign(&mut self, rhs: Scalar) {
        *self = *self - rhs;
    }
}

// === Multiplication === //

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        Scalar(self.0 * rhs.0)
    }
}
impl_borrow_variants!(Scalar, Mul, mul, *, Scalar);

impl Mul<&Scalar> for &ScalarResult {
    type Output = ScalarResult;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let [lhs]: [Scalar; 1] = cast_args(args);
            ResultValue::Scalar(Scalar(lhs.0 * rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult, Mul, mul, *, Scalar);
impl_commutative!(ScalarResult, Mul, mul, *, Scalar);

impl Mul<&ScalarResult> for &ScalarResult {
    type Output = ScalarResult;

    fn mul(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            let [lhs, rhs]: [Scalar; 2] = cast_args(args);
            ResultValue::Scalar(Scalar(lhs.0 * rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult, Mul, mul, *, ScalarResult);

impl Neg for &Scalar {
    type Output = Scalar;

    fn neg(self) -> Self::Output {
        Scalar(-self.0)
    }
}
impl_borrow_variants!(Scalar, Neg, neg, -);

impl Neg for &ScalarResult {
    type Output = ScalarResult;

    fn neg(self) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id], |args| {
            let [lhs]: [Scalar; 1] = cast_args(args);
            ResultValue::Scalar(Scalar(-lhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult, Neg, neg, -);

// === MulAssign === //

impl MulAssign for Scalar {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = *self * rhs;
    }
}

// ---------------
// | Conversions |
// ---------------

impl<T: Into<ScalarInner>> From<T> for Scalar {
    fn from(val: T) -> Self {
        Scalar(val.into())
    }
}

// -------------------
// | Iterator Traits |
// -------------------

impl Sum for Scalar {
    fn sum<I: Iterator<Item = Scalar>>(iter: I) -> Self {
        iter.fold(Scalar::zero(), |acc, x| acc + x)
    }
}

impl Product for Scalar {
    fn product<I: Iterator<Item = Scalar>>(iter: I) -> Self {
        iter.fold(Scalar::one(), |acc, x| acc * x)
    }
}

#[cfg(test)]
mod test {
    use super::StarknetBaseFelt;
    use crate::algebra::scalar::{Scalar, BASE_FIELD_BYTES, SCALAR_BYTES};
    use num_bigint::BigUint;
    use rand::thread_rng;

    /// Tests serializing and deserializing a scalar
    #[test]
    fn test_scalar_serialize() {
        // Sample a random scalar and convert it to bytes
        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let bytes = scalar.to_bytes_be();

        assert_eq!(bytes.len(), SCALAR_BYTES);

        // Deserialize and validate the scalar
        let scalar_deserialized = Scalar::from_be_bytes_mod_order(&bytes);
        assert_eq!(scalar, scalar_deserialized);
    }

    /// Tests that the constant `BASE_FIELD_BYTES` is correct
    #[test]
    fn test_base_field_bytes() {
        let mut rng = thread_rng();
        let elem = Scalar::random(&mut rng);
        let elem_bytes = elem.to_bytes_be();
        let biguint = BigUint::from_bytes_be(&elem_bytes);
        let base_elem: StarknetBaseFelt = biguint.into();

        let base_elem_bytes = Into::<BigUint>::into(base_elem).to_bytes_be();
        assert_eq!(base_elem_bytes.len(), BASE_FIELD_BYTES);
    }
}
