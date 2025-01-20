//! Defines the scalar types that form the basis of the MPC algebra

// ----------------------------
// | Scalar Field Definitions |
// ----------------------------

use std::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign},
};

use ark_ec::CurveGroup;
use ark_ff::{batch_inversion, Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Num;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::algebra::{macros::*, ToBytes};

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

    /// Convert from a decimal string
    pub fn from_decimal_string(s: &str) -> Result<Self, String> {
        Self::from_radix_string(s, 10)
    }

    /// Convert from a hexadecimal string
    pub fn from_hex_string(s: &str) -> Result<Self, String> {
        let trimmed = s.trim_start_matches("0x");
        Self::from_radix_string(trimmed, 16)
    }

    /// Convert from a string in the given radix
    fn from_radix_string(s: &str, radix: u32) -> Result<Self, String> {
        let bigint_val = BigUint::from_str_radix(s, radix).map_err(|e| e.to_string())?;
        Ok(Self::from_biguint(&bigint_val))
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
        let mut bytes = Vec::with_capacity(n_bytes_field::<C::ScalarField>());
        self.0.serialize_uncompressed(&mut bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for Scalar<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        let inner = C::ScalarField::deserialize_uncompressed(bytes.as_slice())
            .map_err(serde::de::Error::custom)?;
        Ok(Scalar(inner))
    }
}

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl<C: CurveGroup> Add<&Scalar<C>> for &Scalar<C> {
    type Output = Scalar<C>;

    fn add(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        Scalar(self.0 + rhs.0)
    }
}
impl_borrow_variants!(Scalar<C>, Add, add, +, Scalar<C>, C: CurveGroup);

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

impl<C: CurveGroup> Neg for &Scalar<C> {
    type Output = Scalar<C>;

    fn neg(self) -> Self::Output {
        Scalar(-self.0)
    }
}
impl_borrow_variants!(Scalar<C>, Neg, neg, -, C: CurveGroup);

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

impl<C: CurveGroup> From<Scalar<C>> for BigUint {
    fn from(value: Scalar<C>) -> Self {
        value.0.into()
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

impl<C: CurveGroup> PartialOrd for Scalar<C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<C: CurveGroup> Ord for Scalar<C> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
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

    /// Tests serialization and deserialization of scalars
    #[test]
    fn test_scalar_serialization() {
        let mut rng = thread_rng();
        let scalar = Scalar::<TestCurve>::random(&mut rng);

        let bytes = serde_json::to_vec(&scalar).unwrap();
        let deserialized: Scalar<TestCurve> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(scalar, deserialized);
    }

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
