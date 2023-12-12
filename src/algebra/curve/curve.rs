//! Defines the `CurvePoint` type, a wrapper around a generic curve that allows
//! us to bring curve arithmetic into the execution graph

use std::{
    iter::Sum,
    mem::size_of,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use ark_ec::{
    hashing::{
        curve_maps::swu::{SWUConfig, SWUMap},
        map_to_curve_hasher::MapToCurve,
        HashToCurveError,
    },
    short_weierstrass::Projective,
    AffineRepr, CurveGroup,
};
use ark_ff::PrimeField;

use ark_serialize::SerializationError;
use itertools::Itertools;
use serde::{de::Error as DeError, Deserialize, Serialize};

use crate::{
    algebra::{
        macros::*, n_bytes_field, scalar::*, ToBytes, AUTHENTICATED_POINT_RESULT_LEN,
        AUTHENTICATED_SCALAR_RESULT_LEN,
    },
    fabric::{ResultHandle, ResultValue},
};

use super::{authenticated_curve::AuthenticatedPointResult, mpc_curve::MpcPointResult};

/// The number of points and scalars to pull from an iterated MSM when
/// performing a multiscalar multiplication
const MSM_CHUNK_SIZE: usize = 1 << 16;
/// The threshold at which we call out to the Arkworks MSM implementation
///
/// MSM sizes below this threshold are computed serially as the parallelism
/// overhead is too significant
const MSM_SIZE_THRESHOLD: usize = 10;

/// The security level used in the hash-to-curve implementation, in bytes
pub const HASH_TO_CURVE_SECURITY: usize = 16; // 128 bit security

/// A wrapper around the inner point that allows us to define foreign traits on
/// the point
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CurvePoint<C: CurveGroup>(pub(crate) C);
impl<C: CurveGroup> Unpin for CurvePoint<C> {}

impl<C: CurveGroup> Serialize for CurvePoint<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_bytes();
        bytes.serialize(serializer)
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for CurvePoint<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        CurvePoint::from_bytes(&bytes)
            .map_err(|err| DeError::custom(format!("Failed to deserialize point: {err:?}")))
    }
}

// ------------------------
// | Misc Implementations |
// ------------------------

impl<C: CurveGroup> CurvePoint<C> {
    /// The base field that the curve is defined over, i.e. the field in which
    /// the curve equation's coefficients lie
    pub type BaseField = C::BaseField;
    /// The scalar field of the curve, i.e. Z/rZ where r is the curve group's
    /// order
    pub type ScalarField = C::ScalarField;

    /// The additive identity in the curve group
    pub fn identity() -> CurvePoint<C> {
        CurvePoint(C::zero())
    }

    /// Check whether the given point is the identity point in the group
    pub fn is_identity(&self) -> bool {
        self == &CurvePoint::identity()
    }

    /// Return the wrapped type
    pub fn inner(&self) -> C {
        self.0
    }

    /// Convert the point to affine
    pub fn to_affine(&self) -> C::Affine {
        self.0.into_affine()
    }

    /// The group generator
    pub fn generator() -> CurvePoint<C> {
        CurvePoint(C::generator())
    }

    /// Serialize this point to a byte buffer
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(size_of::<CurvePoint<C>>());
        self.0.serialize_compressed(&mut out).expect("Failed to serialize point");

        out
    }

    /// Deserialize a point from a byte buffer
    pub fn from_bytes(bytes: &[u8]) -> Result<CurvePoint<C>, SerializationError> {
        let point = C::deserialize_compressed(bytes)?;
        Ok(CurvePoint(point))
    }
}

impl<C: CurveGroup> CurvePoint<C>
where
    C::BaseField: PrimeField,
{
    /// Get the number of bytes needed to represent a point, this is exactly the
    /// number of bytes for one base field element, as we can simply use the
    /// x-coordinate and set a high bit for the `y`
    pub fn n_bytes() -> usize {
        n_bytes_field::<C::BaseField>()
    }
}

impl<C: CurveGroup> CurvePoint<C>
where
    C::Config: SWUConfig,
    C::BaseField: PrimeField,
{
    /// Convert a uniform byte buffer to a `CurvePoint<C>` via the SWU
    /// map-to-curve approach:
    ///
    /// See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-09#simple-swu
    /// for a description of the setup. Essentially, we assume that the buffer
    /// provided is the result of an `extend_message` implementation that
    /// gives us its uniform digest. From here we construct two field
    /// elements, map to curve, and add the points to give a uniformly
    /// distributed curve point
    pub fn from_uniform_bytes(
        buf: Vec<u8>,
    ) -> Result<CurvePoint<Projective<C::Config>>, HashToCurveError> {
        let n_bytes = Self::n_bytes();
        assert_eq!(
            buf.len(),
            2 * n_bytes,
            "Invalid buffer length, must represent two curve points"
        );

        // Sample two base field elements from the buffer
        let f1 = Self::hash_to_field(&buf[..n_bytes / 2]);
        let f2 = Self::hash_to_field(&buf[n_bytes / 2..]);

        // Map to curve
        let mapper = SWUMap::<C::Config>::new()?;
        let p1 = mapper.map_to_curve(f1)?;
        let p2 = mapper.map_to_curve(f2)?;

        // Clear the cofactor
        let p1_clear = p1.clear_cofactor();
        let p2_clear = p2.clear_cofactor();

        Ok(CurvePoint(p1_clear + p2_clear))
    }

    /// A helper that converts an arbitrarily long byte buffer to a field
    /// element
    fn hash_to_field(buf: &[u8]) -> C::BaseField {
        Self::BaseField::from_be_bytes_mod_order(buf)
    }
}

impl<C: CurveGroup> ToBytes for CurvePoint<C> {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl<C: CurveGroup> From<C> for CurvePoint<C> {
    fn from(p: C) -> Self {
        CurvePoint(p)
    }
}

// ------------------------------------
// | Curve Arithmetic Implementations |
// ------------------------------------

// === Addition === //

impl<C: CurveGroup> Add<&C> for &CurvePoint<C> {
    type Output = CurvePoint<C>;

    fn add(self, rhs: &C) -> Self::Output {
        CurvePoint(self.0 + rhs)
    }
}
impl_borrow_variants!(CurvePoint<C>, Add, add, +, C, C: CurveGroup);

impl<C: CurveGroup> Add<&CurvePoint<C>> for &CurvePoint<C> {
    type Output = CurvePoint<C>;

    fn add(self, rhs: &CurvePoint<C>) -> Self::Output {
        CurvePoint(self.0 + rhs.0)
    }
}
impl_borrow_variants!(CurvePoint<C>, Add, add, +, CurvePoint<C>, C: CurveGroup);

/// A type alias for a result that resolves to a `CurvePoint<C>`
pub type CurvePointResult<C> = ResultHandle<C, CurvePoint<C>>;
/// A type alias for a result that resolves to a batch of `CurvePoint<C>`s
pub type BatchCurvePointResult<C> = ResultHandle<C, Vec<CurvePoint<C>>>;

impl<C: CurveGroup> Add<&CurvePointResult<C>> for &CurvePointResult<C> {
    type Output = CurvePointResult<C>;

    fn add(self, rhs: &CurvePointResult<C>) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: CurvePoint<C> = args.next().unwrap().into();
            let rhs: CurvePoint<C> = args.next().unwrap().into();
            ResultValue::Point(CurvePoint(lhs.0 + rhs.0))
        })
    }
}
impl_borrow_variants!(CurvePointResult<C>, Add, add, +, CurvePointResult<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&CurvePoint<C>> for &CurvePointResult<C> {
    type Output = CurvePointResult<C>;

    fn add(self, rhs: &CurvePoint<C>) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |mut args| {
            let lhs: CurvePoint<C> = args.next().unwrap().into();
            ResultValue::Point(CurvePoint(lhs.0 + rhs.0))
        })
    }
}
impl_borrow_variants!(CurvePointResult<C>, Add, add, +, CurvePoint<C>, C: CurveGroup);
impl_commutative!(CurvePointResult<C>, Add, add, +, CurvePoint<C>, C: CurveGroup);

impl<C: CurveGroup> CurvePointResult<C> {
    /// Add two batches of `CurvePoint<C>`s together
    pub fn batch_add(
        a: &[CurvePointResult<C>],
        b: &[CurvePointResult<C>],
    ) -> Vec<CurvePointResult<C>> {
        assert_eq!(a.len(), b.len(), "batch_add cannot compute on vectors of unequal length");

        let n = a.len();
        let fabric = a[0].fabric();

        let lhs = a.iter().map(|r| r.id);
        let rhs = b.iter().map(|r| r.id);
        let all_ids = lhs.interleave(rhs).collect_vec();
        fabric.new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
            let mut res = Vec::with_capacity(n);
            for mut chunk in &args.map(CurvePoint::from).chunks(2) {
                let lhs = chunk.next().unwrap();
                let rhs = chunk.next().unwrap();

                res.push(ResultValue::Point(lhs + rhs));
            }

            res
        })
    }
}

// === AddAssign === //

impl<C: CurveGroup> AddAssign for CurvePoint<C> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

// === Subtraction === //

impl<C: CurveGroup> Sub<&CurvePoint<C>> for &CurvePoint<C> {
    type Output = CurvePoint<C>;

    fn sub(self, rhs: &CurvePoint<C>) -> Self::Output {
        CurvePoint(self.0 - rhs.0)
    }
}
impl_borrow_variants!(CurvePoint<C>, Sub, sub, -, CurvePoint<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&CurvePointResult<C>> for &CurvePointResult<C> {
    type Output = CurvePointResult<C>;

    fn sub(self, rhs: &CurvePointResult<C>) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: CurvePoint<C> = args.next().unwrap().into();
            let rhs: CurvePoint<C> = args.next().unwrap().into();
            ResultValue::Point(CurvePoint(lhs.0 - rhs.0))
        })
    }
}
impl_borrow_variants!(CurvePointResult<C>, Sub, sub, -, CurvePointResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&CurvePoint<C>> for &CurvePointResult<C> {
    type Output = CurvePointResult<C>;

    fn sub(self, rhs: &CurvePoint<C>) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |mut args| {
            let lhs: CurvePoint<C> = args.next().unwrap().into();
            ResultValue::Point(CurvePoint(lhs.0 - rhs.0))
        })
    }
}
impl_borrow_variants!(CurvePointResult<C>, Sub, sub, -, CurvePoint<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&CurvePointResult<C>> for &CurvePoint<C> {
    type Output = CurvePointResult<C>;

    fn sub(self, rhs: &CurvePointResult<C>) -> Self::Output {
        let self_owned = *self;
        rhs.fabric.new_gate_op(vec![rhs.id], move |mut args| {
            let rhs: CurvePoint<C> = args.next().unwrap().into();
            ResultValue::Point(CurvePoint(self_owned.0 - rhs.0))
        })
    }
}

impl<C: CurveGroup> CurvePointResult<C> {
    /// Subtract two batches of `CurvePoint<C>`s
    pub fn batch_sub(
        a: &[CurvePointResult<C>],
        b: &[CurvePointResult<C>],
    ) -> Vec<CurvePointResult<C>> {
        assert_eq!(a.len(), b.len(), "batch_sub cannot compute on vectors of unequal length");

        let n = a.len();
        let fabric = a[0].fabric();

        let lhs = a.iter().map(|v| v.id);
        let rhs = b.iter().map(|v| v.id);
        let all_ids = lhs.interleave(rhs).collect_vec();
        fabric.new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
            let mut res = Vec::with_capacity(n);
            for mut chunk in &args.map(CurvePoint::from).chunks(2) {
                let lhs = chunk.next().unwrap();
                let rhs = chunk.next().unwrap();

                res.push(ResultValue::Point(lhs - rhs));
            }

            res
        })
    }
}

// === SubAssign === //

impl<C: CurveGroup> SubAssign for CurvePoint<C> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

// === Negation === //

impl<C: CurveGroup> Neg for &CurvePoint<C> {
    type Output = CurvePoint<C>;

    fn neg(self) -> Self::Output {
        CurvePoint(-self.0)
    }
}
impl_borrow_variants!(CurvePoint<C>, Neg, neg, -, C: CurveGroup);

impl<C: CurveGroup> Neg for &CurvePointResult<C> {
    type Output = CurvePointResult<C>;

    fn neg(self) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id], |mut args| {
            let lhs: CurvePoint<C> = args.next().unwrap().into();
            ResultValue::Point(CurvePoint(-lhs.0))
        })
    }
}
impl_borrow_variants!(CurvePointResult<C>, Neg, neg, -, C:CurveGroup);

impl<C: CurveGroup> CurvePointResult<C> {
    /// Negate a batch of `CurvePoint<C>`s
    pub fn batch_neg(a: &[CurvePointResult<C>]) -> Vec<CurvePointResult<C>> {
        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().map(|r| r.id).collect_vec();

        fabric.new_batch_gate_op(all_ids, n /* output_arity */, |args| {
            args.map(CurvePoint::from).map(CurvePoint::neg).map(ResultValue::Point).collect_vec()
        })
    }
}

// === Scalar Multiplication === //

impl<C: CurveGroup> Mul<&Scalar<C>> for &CurvePoint<C> {
    type Output = CurvePoint<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        CurvePoint(self.0 * rhs.0)
    }
}
impl_borrow_variants!(CurvePoint<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
impl_commutative!(CurvePoint<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&Scalar<C>> for &CurvePointResult<C> {
    type Output = CurvePointResult<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |mut args| {
            let lhs: CurvePoint<C> = args.next().unwrap().into();
            ResultValue::Point(CurvePoint(lhs.0 * rhs.0))
        })
    }
}
impl_borrow_variants!(CurvePointResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
impl_commutative!(CurvePointResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&ScalarResult<C>> for &CurvePoint<C> {
    type Output = CurvePointResult<C>;

    fn mul(self, rhs: &ScalarResult<C>) -> Self::Output {
        let self_owned = *self;
        rhs.fabric.new_gate_op(vec![rhs.id], move |mut args| {
            let rhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Point(CurvePoint(self_owned.0 * rhs.0))
        })
    }
}
impl_borrow_variants!(CurvePoint<C>, Mul, mul, *, ScalarResult<C>, Output=CurvePointResult<C>, C: CurveGroup);
impl_commutative!(CurvePoint<C>, Mul, mul, *, ScalarResult<C>, Output=CurvePointResult<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&ScalarResult<C>> for &CurvePointResult<C> {
    type Output = CurvePointResult<C>;

    fn mul(self, rhs: &ScalarResult<C>) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: CurvePoint<C> = args.next().unwrap().into();
            let rhs: Scalar<C> = args.next().unwrap().into();

            ResultValue::Point(CurvePoint(lhs.0 * rhs.0))
        })
    }
}
impl_borrow_variants!(CurvePointResult<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);
impl_commutative!(CurvePointResult<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> CurvePointResult<C> {
    /// Multiply a batch of `CurvePointResult<C>`s with a batch of
    /// `ScalarResult`s
    pub fn batch_mul(a: &[ScalarResult<C>], b: &[CurvePointResult<C>]) -> Vec<CurvePointResult<C>> {
        assert_eq!(a.len(), b.len(), "batch_mul cannot compute on vectors of unequal length");

        let n = a.len();
        let fabric = a[0].fabric();

        let lhs = a.iter().map(|r| r.id);
        let rhs = b.iter().map(|r| r.id);
        let all_ids = lhs.interleave(rhs).collect_vec();
        fabric.new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
            let mut res = Vec::with_capacity(n);
            for mut chunk in &args.chunks(2) {
                let lhs: Scalar<C> = chunk.next().unwrap().into();
                let rhs: CurvePoint<C> = chunk.next().unwrap().into();

                res.push(ResultValue::Point(lhs * rhs));
            }

            res
        })
    }

    /// Multiply a batch of `MpcScalarResult`s with a batch of
    /// `CurvePointResult<C>`s
    pub fn batch_mul_shared(
        a: &[MpcScalarResult<C>],
        b: &[CurvePointResult<C>],
    ) -> Vec<MpcPointResult<C>> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_mul_shared cannot compute on vectors of unequal length"
        );

        let n = a.len();
        let fabric = a[0].fabric();

        let lhs = a.iter().map(|r| r.id());
        let rhs = b.iter().map(|r| r.id);
        let all_ids = lhs.interleave(rhs).collect_vec();
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
                let mut res = Vec::with_capacity(n);
                for mut chunk in &args.chunks(2) {
                    let lhs: Scalar<C> = chunk.next().unwrap().into();
                    let rhs: CurvePoint<C> = chunk.next().unwrap().into();

                    res.push(ResultValue::Point(lhs * rhs));
                }

                res
            })
            .into_iter()
            .map(MpcPointResult::from)
            .collect_vec()
    }

    /// Multiply a batch of `AuthenticatedScalarResult`s with a batch of
    /// `CurvePointResult<C>`s
    pub fn batch_mul_authenticated(
        a: &[AuthenticatedScalarResult<C>],
        b: &[CurvePointResult<C>],
    ) -> Vec<AuthenticatedPointResult<C>> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_mul_authenticated cannot compute on vectors of unequal length"
        );

        let n = a.len();
        let fabric = a[0].fabric();

        let chunk_size = AUTHENTICATED_SCALAR_RESULT_LEN + 1;
        let mut all_ids = Vec::with_capacity(n * chunk_size);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.extend(a.ids());
            all_ids.push(b.id);
        }

        let results = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_POINT_RESULT_LEN * n, // output_arity
            move |args| {
                let mut results = Vec::with_capacity(n * AUTHENTICATED_POINT_RESULT_LEN);
                for mut chunk in &args.chunks(chunk_size) {
                    let share = Scalar::from(&chunk.next().unwrap());
                    let mac = Scalar::from(&chunk.next().unwrap());
                    let public_modifier = Scalar::from(&chunk.next().unwrap());
                    let point = CurvePoint::from(&chunk.next().unwrap());

                    results.push(ResultValue::Point(point * share));
                    results.push(ResultValue::Point(point * mac));
                    results.push(ResultValue::Point(point * public_modifier));
                }

                results
            },
        );

        AuthenticatedPointResult::from_flattened_iterator(results.into_iter())
    }
}

// === MulAssign === //

impl<C: CurveGroup> MulAssign<&Scalar<C>> for CurvePoint<C> {
    fn mul_assign(&mut self, rhs: &Scalar<C>) {
        self.0 *= rhs.0;
    }
}

// -------------------
// | Iterator Traits |
// -------------------

impl<C: CurveGroup> Sum for CurvePoint<C> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(CurvePoint::identity(), |acc, x| acc + x)
    }
}

impl<C: CurveGroup> Sum for CurvePointResult<C> {
    /// Assumes the iterator is non-empty
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        let first = iter.next().expect("empty iterator");
        iter.fold(first, |acc, x| acc + x)
    }
}

/// MSM Implementation
impl<C: CurveGroup> CurvePoint<C> {
    /// Compute the multiscalar multiplication of the given scalars and points
    pub fn msm(scalars: &[Scalar<C>], points: &[CurvePoint<C>]) -> CurvePoint<C> {
        assert_eq!(scalars.len(), points.len(), "msm cannot compute on vectors of unequal length");

        let n = scalars.len();
        if n < MSM_SIZE_THRESHOLD {
            return scalars.iter().zip(points.iter()).map(|(s, p)| s * p).sum();
        }

        let affine_points = points.iter().map(|p| p.0.into_affine()).collect_vec();
        let stripped_scalars = scalars.iter().map(|s| s.0).collect_vec();
        C::msm(&affine_points, &stripped_scalars).map(CurvePoint).unwrap()
    }

    /// Compute the multiscalar multiplication of the given scalars and points
    /// represented as streaming iterators
    pub fn msm_iter<I, J>(scalars: I, points: J) -> CurvePoint<C>
    where
        I: IntoIterator<Item = Scalar<C>>,
        J: IntoIterator<Item = CurvePoint<C>>,
    {
        let mut res = CurvePoint::identity();
        for (scalar_chunk, point_chunk) in scalars
            .into_iter()
            .chunks(MSM_CHUNK_SIZE)
            .into_iter()
            .zip(points.into_iter().chunks(MSM_CHUNK_SIZE).into_iter())
        {
            let scalars: Vec<Scalar<C>> = scalar_chunk.collect();
            let points: Vec<CurvePoint<C>> = point_chunk.collect();
            let chunk_res = CurvePoint::msm(&scalars, &points);

            res += chunk_res;
        }

        res
    }

    /// Compute the multiscalar multiplication of the given points with
    /// `ScalarResult`s
    pub fn msm_results(
        scalars: &[ScalarResult<C>],
        points: &[CurvePoint<C>],
    ) -> CurvePointResult<C> {
        assert_eq!(scalars.len(), points.len(), "msm cannot compute on vectors of unequal length");

        let fabric = scalars[0].fabric();
        let scalar_ids = scalars.iter().map(|s| s.id()).collect_vec();

        // Clone `points` so that the gate closure may capture it
        let points = points.to_vec();
        fabric.new_gate_op(scalar_ids, move |args| {
            let scalars = args.map(Scalar::from).collect_vec();

            ResultValue::Point(CurvePoint::msm(&scalars, &points))
        })
    }

    /// Compute the multiscalar multiplication of the given points with
    /// `ScalarResult`s as iterators. Assumes the iterators are non-empty
    pub fn msm_results_iter<I, J>(scalars: I, points: J) -> CurvePointResult<C>
    where
        I: IntoIterator<Item = ScalarResult<C>>,
        J: IntoIterator<Item = CurvePoint<C>>,
    {
        Self::msm_results(&scalars.into_iter().collect_vec(), &points.into_iter().collect_vec())
    }

    /// Compute the multiscalar multiplication of the given authenticated
    /// scalars and plaintext points
    pub fn msm_authenticated(
        scalars: &[AuthenticatedScalarResult<C>],
        points: &[CurvePoint<C>],
    ) -> AuthenticatedPointResult<C> {
        assert_eq!(scalars.len(), points.len(), "msm cannot compute on vectors of unequal length");

        let n = scalars.len();
        let fabric = scalars[0].fabric();
        let scalar_ids = scalars.iter().flat_map(|s| s.ids()).collect_vec();

        // Clone points to let the gate closure take ownership
        let points = points.to_vec();
        let res: Vec<CurvePointResult<C>> = fabric.new_batch_gate_op(
            scalar_ids,
            AUTHENTICATED_SCALAR_RESULT_LEN, // output_arity
            move |args| {
                let mut shares = Vec::with_capacity(n);
                let mut macs = Vec::with_capacity(n);
                let mut modifiers = Vec::with_capacity(n);

                for mut chunk in &args.map(Scalar::from).chunks(AUTHENTICATED_SCALAR_RESULT_LEN) {
                    shares.push(chunk.next().unwrap());
                    macs.push(chunk.next().unwrap());
                    modifiers.push(chunk.next().unwrap());
                }

                // Compute the MSM of the point
                vec![
                    CurvePoint::msm(&shares, &points),
                    CurvePoint::msm(&macs, &points),
                    CurvePoint::msm(&modifiers, &points),
                ]
                .into_iter()
                .map(ResultValue::Point)
                .collect_vec()
            },
        );

        AuthenticatedPointResult {
            share: res[0].to_owned().into(),
            mac: res[1].to_owned().into(),
            public_modifier: res[2].to_owned(),
        }
    }

    /// Compute the multiscalar multiplication of the given authenticated
    /// scalars and plaintext points as iterators
    /// This method assumes that the iterators are of the same length
    pub fn msm_authenticated_iter<I, J>(scalars: I, points: J) -> AuthenticatedPointResult<C>
    where
        I: IntoIterator<Item = AuthenticatedScalarResult<C>>,
        J: IntoIterator<Item = CurvePoint<C>>,
    {
        let scalars: Vec<AuthenticatedScalarResult<C>> = scalars.into_iter().collect();
        let points: Vec<CurvePoint<C>> = points.into_iter().collect();

        Self::msm_authenticated(&scalars, &points)
    }
}

impl<C: CurveGroup> CurvePointResult<C> {
    /// Compute the multiscalar multiplication of the given scalars and points
    pub fn msm_results(
        scalars: &[ScalarResult<C>],
        points: &[CurvePointResult<C>],
    ) -> CurvePointResult<C> {
        assert!(!scalars.is_empty(), "msm cannot compute on an empty vector");
        assert_eq!(scalars.len(), points.len(), "msm cannot compute on vectors of unequal length");

        let n = scalars.len();
        let fabric = scalars[0].fabric();

        let lhs = scalars.iter().map(|s| s.id());
        let rhs = points.iter().map(|p| p.id);
        let all_ids = lhs.interleave(rhs).collect_vec();
        fabric.new_gate_op(all_ids, move |args| {
            let mut scalars = Vec::with_capacity(n);
            let mut points = Vec::with_capacity(n);
            for mut chunk in &args.chunks(2) {
                scalars.push(chunk.next().unwrap().into());
                points.push(chunk.next().unwrap().into());
            }

            let res = CurvePoint::msm(&scalars, &points);
            ResultValue::Point(res)
        })
    }

    /// Compute the multiscalar multiplication of the given scalars and points
    /// represented as streaming iterators
    ///
    /// Assumes the iterator is non-empty
    pub fn msm_results_iter<I, J>(scalars: I, points: J) -> CurvePointResult<C>
    where
        I: IntoIterator<Item = ScalarResult<C>>,
        J: IntoIterator<Item = CurvePointResult<C>>,
    {
        Self::msm_results(&scalars.into_iter().collect_vec(), &points.into_iter().collect_vec())
    }

    /// Compute the multiscalar multiplication of the given
    /// `AuthenticatedScalarResult`s and points
    pub fn msm_authenticated(
        scalars: &[AuthenticatedScalarResult<C>],
        points: &[CurvePointResult<C>],
    ) -> AuthenticatedPointResult<C> {
        assert_eq!(scalars.len(), points.len(), "msm cannot compute on vectors of unequal length");

        let n = scalars.len();
        let fabric = scalars[0].fabric();

        let chunk_size = AUTHENTICATED_SCALAR_RESULT_LEN + 1;
        let mut all_ids = Vec::with_capacity(n * chunk_size);

        for (a, b) in scalars.iter().zip(points.iter()) {
            all_ids.extend(a.ids());
            all_ids.push(b.id);
        }

        let res = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_POINT_RESULT_LEN, // output_arity
            move |args| {
                let mut shares = Vec::with_capacity(n);
                let mut macs = Vec::with_capacity(n);
                let mut modifiers = Vec::with_capacity(n);
                let mut points = Vec::with_capacity(n);
                for mut chunk in &args.chunks(chunk_size) {
                    shares.push(chunk.next().unwrap().into());
                    macs.push(chunk.next().unwrap().into());
                    modifiers.push(chunk.next().unwrap().into());
                    points.push(chunk.next().unwrap().into());
                }

                vec![
                    CurvePoint::msm(&shares, &points),
                    CurvePoint::msm(&macs, &points),
                    CurvePoint::msm(&modifiers, &points),
                ]
                .into_iter()
                .map(ResultValue::Point)
                .collect_vec()
            },
        );

        AuthenticatedPointResult {
            share: res[0].to_owned().into(),
            mac: res[1].to_owned().into(),
            public_modifier: res[2].to_owned(),
        }
    }

    /// Compute the multiscalar multiplication of the given
    /// `AuthenticatedScalarResult`s and points represented as streaming
    /// iterators
    pub fn msm_authenticated_iter<I, J>(scalars: I, points: J) -> AuthenticatedPointResult<C>
    where
        I: IntoIterator<Item = AuthenticatedScalarResult<C>>,
        J: IntoIterator<Item = CurvePointResult<C>>,
    {
        let scalars: Vec<AuthenticatedScalarResult<C>> = scalars.into_iter().collect();
        let points: Vec<CurvePointResult<C>> = points.into_iter().collect();

        Self::msm_authenticated(&scalars, &points)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use crate::{test_helpers::mock_fabric, test_helpers::TestCurve};

    use super::*;

    /// A curve point on the test curve
    pub type TestCurvePoint = CurvePoint<TestCurve>;

    /// Generate a random point, by multiplying the basepoint with a random
    /// scalar
    pub fn random_point() -> TestCurvePoint {
        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let point = TestCurvePoint::generator() * scalar;
        point * scalar
    }

    /// Tests point addition
    #[tokio::test]
    async fn test_point_addition() {
        let fabric = mock_fabric();

        let p1 = random_point();
        let p2 = random_point();

        let p1_res = fabric.allocate_point(p1);
        let p2_res = fabric.allocate_point(p2);

        let res = (p1_res + p2_res).await;
        let expected_res = p1 + p2;

        assert_eq!(res, expected_res);
        fabric.shutdown();
    }

    /// Tests scalar multiplication
    #[tokio::test]
    async fn test_scalar_mul() {
        let fabric = mock_fabric();

        let mut rng = thread_rng();
        let s1 = Scalar::<TestCurve>::random(&mut rng);
        let p1 = random_point();

        let s1_res = fabric.allocate_scalar(s1);
        let p1_res = fabric.allocate_point(p1);

        let res = (s1_res * p1_res).await;
        let expected_res = s1 * p1;

        assert_eq!(res, expected_res);
        fabric.shutdown();
    }

    /// Tests addition with the additive identity
    #[tokio::test]
    async fn test_additive_identity() {
        let fabric = mock_fabric();

        let p1 = random_point();

        let p1_res = fabric.allocate_point(p1);
        let identity_res = fabric.curve_identity();

        let res = (p1_res + identity_res).await;
        let expected_res = p1;

        assert_eq!(res, expected_res);
        fabric.shutdown();
    }
}
