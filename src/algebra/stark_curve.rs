//! Defines the `Scalar` type of the Starknet field

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
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig, CurveGroup, Group, VariableBaseMSM,
};
use ark_ff::{BigInt, MontFp, PrimeField, Zero};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use itertools::Itertools;
use num_bigint::BigUint;
use serde::{de::Error as DeError, Deserialize, Serialize};

use crate::{
    algebra::{
        authenticated_scalar::AUTHENTICATED_SCALAR_RESULT_LEN,
        authenticated_stark_point::AUTHENTICATED_STARK_POINT_RESULT_LEN,
    },
    fabric::{ResultHandle, ResultValue},
};

use super::{
    authenticated_scalar::AuthenticatedScalarResult,
    authenticated_stark_point::AuthenticatedStarkPointResult,
    macros::{impl_borrow_variants, impl_commutative},
    mpc_scalar::MpcScalarResult,
    mpc_stark_point::MpcStarkPointResult,
    scalar::{Scalar, ScalarInner, ScalarResult, StarknetBaseFelt, BASE_FIELD_BYTES},
};

/// The number of points and scalars to pull from an iterated MSM when
/// performing a multiscalar multiplication
const MSM_CHUNK_SIZE: usize = 1 << 16;
/// The threshold at which we call out to the Arkworks MSM implementation
///
/// MSM sizes below this threshold are computed serially as the parallelism overhead is
/// too significant
const MSM_SIZE_THRESHOLD: usize = 10;

/// The security level used in the hash-to-curve implementation, in bytes
pub const HASH_TO_CURVE_SECURITY: usize = 16; // 128 bit security
/// The number of bytes needed to serialize a `StarkPoint`
pub const STARK_POINT_BYTES: usize = 32;
/// The number of uniformly distributed bytes needed to construct a uniformly
/// distributed Stark point
pub const STARK_UNIFORM_BYTES: usize = 2 * (BASE_FIELD_BYTES + HASH_TO_CURVE_SECURITY);

/// The Stark curve in the arkworks short Weierstrass curve representation
pub struct StarknetCurveConfig;
impl CurveConfig for StarknetCurveConfig {
    type BaseField = StarknetBaseFelt;
    type ScalarField = ScalarInner;

    const COFACTOR: &'static [u64] = &[1];
    const COFACTOR_INV: Self::ScalarField = MontFp!("1");
}

/// See https://docs.starkware.co/starkex/crypto/stark-curve.html
/// for curve parameters
impl SWCurveConfig for StarknetCurveConfig {
    const COEFF_A: Self::BaseField = MontFp!("1");
    const COEFF_B: Self::BaseField =
        MontFp!("3141592653589793238462643383279502884197169399375105820974944592307816406665");

    const GENERATOR: Affine<Self> = Affine {
        x: MontFp!("874739451078007766457464989774322083649278607533249481151382481072868806602"),
        y: MontFp!("152666792071518830868575557812948353041420400780739481342941381225525861407"),
        infinity: false,
    };
}

/// Defines the \zeta constant for the SWU map to curve implementation
impl SWUConfig for StarknetCurveConfig {
    const ZETA: Self::BaseField = MontFp!("3");
}

/// A type alias for a projective curve point on the Stark curve
pub(crate) type StarkPointInner = Projective<StarknetCurveConfig>;
/// A wrapper around the inner point that allows us to define foreign traits on the point
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StarkPoint(pub(crate) StarkPointInner);

impl Serialize for StarkPoint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_bytes();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StarkPoint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        StarkPoint::from_bytes(&bytes)
            .map_err(|err| DeError::custom(format!("Failed to deserialize point: {err:?}")))
    }
}

// ------------------------
// | Misc Implementations |
// ------------------------

impl StarkPoint {
    /// The additive identity in the curve group
    pub fn identity() -> StarkPoint {
        StarkPoint(StarkPointInner::zero())
    }

    /// Check whether the given point is the identity point in the group
    pub fn is_identity(&self) -> bool {
        self == &StarkPoint::identity()
    }

    /// Convert the point to affine
    pub fn to_affine(&self) -> Affine<StarknetCurveConfig> {
        self.0.into_affine()
    }

    /// Construct a `StarkPoint` from its affine coordinates
    pub fn from_affine_coords(x: BigUint, y: BigUint) -> Self {
        let x_bigint = BigInt::try_from(x).unwrap();
        let y_bigint = BigInt::try_from(y).unwrap();
        let x = StarknetBaseFelt::from(x_bigint);
        let y = StarknetBaseFelt::from(y_bigint);

        let aff = Affine {
            x,
            y,
            infinity: false,
        };
        assert!(aff.is_on_curve(), "invalid affine coordinates");

        Self(aff.into())
    }

    /// The group generator
    pub fn generator() -> StarkPoint {
        StarkPoint(StarkPointInner::generator())
    }

    /// Serialize this point to a byte buffer
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(size_of::<StarkPoint>());
        self.0
            .serialize_compressed(&mut out)
            .expect("Failed to serialize point");

        out
    }

    /// Deserialize a point from a byte buffer
    pub fn from_bytes(bytes: &[u8]) -> Result<StarkPoint, SerializationError> {
        let point = StarkPointInner::deserialize_compressed(bytes)?;
        Ok(StarkPoint(point))
    }

    /// Convert a uniform byte buffer to a `StarkPoint` via the SWU map-to-curve approach:
    ///
    /// See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-09#simple-swu
    /// for a description of the setup. Essentially, we assume that the buffer provided is the
    /// result of an `extend_message` implementation that gives us its uniform digest. From here
    /// we construct two field elements, map to curve, and add the points to give a uniformly
    /// distributed curve point
    pub fn from_uniform_bytes(
        buf: [u8; STARK_UNIFORM_BYTES],
    ) -> Result<StarkPoint, HashToCurveError> {
        // Sample two base field elements from the buffer
        let f1 = Self::hash_to_field(&buf[..STARK_UNIFORM_BYTES / 2]);
        let f2 = Self::hash_to_field(&buf[STARK_UNIFORM_BYTES / 2..]);

        // Map to curve
        let mapper = SWUMap::<StarknetCurveConfig>::new()?;
        let p1 = mapper.map_to_curve(f1)?;
        let p2 = mapper.map_to_curve(f2)?;

        // The IETF spec above requires that we clear the cofactor. However, the STARK curve has cofactor
        // h = 1, so no works needs to be done
        Ok(StarkPoint(p1 + p2))
    }

    /// A helper that converts an arbitrarily long byte buffer to a field element
    fn hash_to_field(buf: &[u8]) -> StarknetBaseFelt {
        StarknetBaseFelt::from_be_bytes_mod_order(buf)
    }
}

impl From<StarkPointInner> for StarkPoint {
    fn from(p: StarkPointInner) -> Self {
        StarkPoint(p)
    }
}

// ------------------------------------
// | Curve Arithmetic Implementations |
// ------------------------------------

// === Addition === //

impl Add<&StarkPointInner> for &StarkPoint {
    type Output = StarkPoint;

    fn add(self, rhs: &StarkPointInner) -> Self::Output {
        StarkPoint(self.0 + rhs)
    }
}
impl_borrow_variants!(StarkPoint, Add, add, +, StarkPointInner);
impl_commutative!(StarkPoint, Add, add, +, StarkPointInner);

impl Add<&StarkPoint> for &StarkPoint {
    type Output = StarkPoint;

    fn add(self, rhs: &StarkPoint) -> Self::Output {
        StarkPoint(self.0 + rhs.0)
    }
}
impl_borrow_variants!(StarkPoint, Add, add, +, StarkPoint);

/// A type alias for a result that resolves to a `StarkPoint`
pub type StarkPointResult = ResultHandle<StarkPoint>;
/// A type alias for a result that resolves to a batch of `StarkPoint`s
pub type BatchStarkPointResult = ResultHandle<Vec<StarkPoint>>;

impl Add<&StarkPointResult> for &StarkPointResult {
    type Output = StarkPointResult;

    fn add(self, rhs: &StarkPointResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            let lhs: StarkPoint = args[0].to_owned().into();
            let rhs: StarkPoint = args[1].to_owned().into();
            ResultValue::Point(StarkPoint(lhs.0 + rhs.0))
        })
    }
}
impl_borrow_variants!(StarkPointResult, Add, add, +, StarkPointResult);

impl Add<&StarkPoint> for &StarkPointResult {
    type Output = StarkPointResult;

    fn add(self, rhs: &StarkPoint) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let lhs: StarkPoint = args[0].to_owned().into();
            ResultValue::Point(StarkPoint(lhs.0 + rhs.0))
        })
    }
}
impl_borrow_variants!(StarkPointResult, Add, add, +, StarkPoint);
impl_commutative!(StarkPointResult, Add, add, +, StarkPoint);

impl StarkPointResult {
    /// Add two batches of `StarkPoint`s together
    pub fn batch_add(a: &[StarkPointResult], b: &[StarkPointResult]) -> Vec<StarkPointResult> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_add cannot compute on vectors of unequal length"
        );

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().chain(b.iter()).map(|r| r.id).collect_vec();

        fabric.new_batch_gate_op(all_ids, n /* output_arity */, move |mut args| {
            let a = args.drain(..n).map(StarkPoint::from).collect_vec();
            let b = args.into_iter().map(StarkPoint::from).collect_vec();

            a.into_iter()
                .zip(b.into_iter())
                .map(|(a, b)| a + b)
                .map(ResultValue::Point)
                .collect_vec()
        })
    }
}

// === AddAssign === //

impl AddAssign for StarkPoint {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

// === Subtraction === //

impl Sub<&StarkPoint> for &StarkPoint {
    type Output = StarkPoint;

    fn sub(self, rhs: &StarkPoint) -> Self::Output {
        StarkPoint(self.0 - rhs.0)
    }
}
impl_borrow_variants!(StarkPoint, Sub, sub, -, StarkPoint);

impl Sub<&StarkPointResult> for &StarkPointResult {
    type Output = StarkPointResult;

    fn sub(self, rhs: &StarkPointResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            let lhs: StarkPoint = args[0].to_owned().into();
            let rhs: StarkPoint = args[1].to_owned().into();
            ResultValue::Point(StarkPoint(lhs.0 - rhs.0))
        })
    }
}
impl_borrow_variants!(StarkPointResult, Sub, sub, -, StarkPointResult);

impl Sub<&StarkPoint> for &StarkPointResult {
    type Output = StarkPointResult;

    fn sub(self, rhs: &StarkPoint) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let lhs: StarkPoint = args[0].to_owned().into();
            ResultValue::Point(StarkPoint(lhs.0 - rhs.0))
        })
    }
}
impl_borrow_variants!(StarkPointResult, Sub, sub, -, StarkPoint);

impl Sub<&StarkPointResult> for &StarkPoint {
    type Output = StarkPointResult;

    fn sub(self, rhs: &StarkPointResult) -> Self::Output {
        let self_owned = *self;
        rhs.fabric.new_gate_op(vec![rhs.id], move |args| {
            let rhs: StarkPoint = args[0].to_owned().into();
            ResultValue::Point(StarkPoint(self_owned.0 - rhs.0))
        })
    }
}

impl StarkPointResult {
    /// Subtract two batches of `StarkPoint`s
    pub fn batch_sub(a: &[StarkPointResult], b: &[StarkPointResult]) -> Vec<StarkPointResult> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_sub cannot compute on vectors of unequal length"
        );

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().chain(b.iter()).map(|r| r.id).collect_vec();

        fabric.new_batch_gate_op(all_ids, n /* output_arity */, move |mut args| {
            let a = args.drain(..n).map(StarkPoint::from).collect_vec();
            let b = args.into_iter().map(StarkPoint::from).collect_vec();

            a.into_iter()
                .zip(b.into_iter())
                .map(|(a, b)| a - b)
                .map(ResultValue::Point)
                .collect_vec()
        })
    }
}

// === SubAssign === //

impl SubAssign for StarkPoint {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

// === Negation === //

impl Neg for &StarkPoint {
    type Output = StarkPoint;

    fn neg(self) -> Self::Output {
        StarkPoint(-self.0)
    }
}
impl_borrow_variants!(StarkPoint, Neg, neg, -);

impl Neg for &StarkPointResult {
    type Output = StarkPointResult;

    fn neg(self) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id], |args| {
            let lhs: StarkPoint = args[0].to_owned().into();
            ResultValue::Point(StarkPoint(-lhs.0))
        })
    }
}
impl_borrow_variants!(StarkPointResult, Neg, neg, -);

impl StarkPointResult {
    /// Negate a batch of `StarkPoint`s
    pub fn batch_neg(a: &[StarkPointResult]) -> Vec<StarkPointResult> {
        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().map(|r| r.id).collect_vec();

        fabric.new_batch_gate_op(all_ids, n /* output_arity */, |args| {
            args.into_iter()
                .map(StarkPoint::from)
                .map(StarkPoint::neg)
                .map(ResultValue::Point)
                .collect_vec()
        })
    }
}

// === Scalar Multiplication === //

impl Mul<&Scalar> for &StarkPoint {
    type Output = StarkPoint;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        StarkPoint(self.0 * rhs.0)
    }
}
impl_borrow_variants!(StarkPoint, Mul, mul, *, Scalar);
impl_commutative!(StarkPoint, Mul, mul, *, Scalar);

impl Mul<&Scalar> for &StarkPointResult {
    type Output = StarkPointResult;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let lhs: StarkPoint = args[0].to_owned().into();
            ResultValue::Point(StarkPoint(lhs.0 * rhs.0))
        })
    }
}
impl_borrow_variants!(StarkPointResult, Mul, mul, *, Scalar);
impl_commutative!(StarkPointResult, Mul, mul, *, Scalar);

impl Mul<&ScalarResult> for &StarkPoint {
    type Output = StarkPointResult;

    fn mul(self, rhs: &ScalarResult) -> Self::Output {
        let self_owned = *self;
        rhs.fabric.new_gate_op(vec![rhs.id], move |args| {
            let rhs: Scalar = args[0].to_owned().into();
            ResultValue::Point(StarkPoint(self_owned.0 * rhs.0))
        })
    }
}
impl_borrow_variants!(StarkPoint, Mul, mul, *, ScalarResult, Output=StarkPointResult);
impl_commutative!(StarkPoint, Mul, mul, *, ScalarResult, Output=StarkPointResult);

impl Mul<&ScalarResult> for &StarkPointResult {
    type Output = StarkPointResult;

    fn mul(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: StarkPoint = args.remove(0).into();
            let rhs: Scalar = args.remove(0).into();

            ResultValue::Point(StarkPoint(lhs.0 * rhs.0))
        })
    }
}
impl_borrow_variants!(StarkPointResult, Mul, mul, *, ScalarResult);
impl_commutative!(StarkPointResult, Mul, mul, *, ScalarResult);

impl StarkPointResult {
    /// Multiply a batch of `StarkPointResult`s with a batch of `ScalarResult`s
    pub fn batch_mul(a: &[ScalarResult], b: &[StarkPointResult]) -> Vec<StarkPointResult> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_mul cannot compute on vectors of unequal length"
        );

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a
            .iter()
            .map(|a| a.id())
            .chain(b.iter().map(|b| b.id()))
            .collect_vec();

        fabric.new_batch_gate_op(all_ids, n /* output_arity */, move |mut args| {
            let a = args.drain(..n).map(Scalar::from).collect_vec();
            let b = args.into_iter().map(StarkPoint::from).collect_vec();

            a.into_iter()
                .zip(b.into_iter())
                .map(|(a, b)| a * b)
                .map(ResultValue::Point)
                .collect_vec()
        })
    }

    /// Multiply a batch of `MpcScalarResult`s with a batch of `StarkPointResult`s
    pub fn batch_mul_shared(
        a: &[MpcScalarResult],
        b: &[StarkPointResult],
    ) -> Vec<MpcStarkPointResult> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_mul_shared cannot compute on vectors of unequal length"
        );

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a
            .iter()
            .map(|a| a.id())
            .chain(b.iter().map(|b| b.id()))
            .collect_vec();

        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |mut args| {
                let a = args.drain(..n).map(Scalar::from).collect_vec();
                let b = args.into_iter().map(StarkPoint::from).collect_vec();

                a.into_iter()
                    .zip(b.into_iter())
                    .map(|(a, b)| a * b)
                    .map(ResultValue::Point)
                    .collect_vec()
            })
            .into_iter()
            .map(MpcStarkPointResult::from)
            .collect_vec()
    }

    /// Multiply a batch of `AuthenticatedScalarResult`s with a batch of `StarkPointResult`s
    pub fn batch_mul_authenticated(
        a: &[AuthenticatedScalarResult],
        b: &[StarkPointResult],
    ) -> Vec<AuthenticatedStarkPointResult> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_mul_authenticated cannot compute on vectors of unequal length"
        );

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = b
            .iter()
            .map(|b| b.id())
            .chain(a.iter().flat_map(|a| a.ids()))
            .collect_vec();

        let results = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_STARK_POINT_RESULT_LEN * n, /* output_arity */
            move |mut args| {
                let points: Vec<StarkPoint> = args.drain(..n).map(StarkPoint::from).collect_vec();

                let mut results = Vec::with_capacity(AUTHENTICATED_STARK_POINT_RESULT_LEN * n);

                for (scalars, point) in args
                    .chunks_exact(AUTHENTICATED_SCALAR_RESULT_LEN)
                    .zip(points.into_iter())
                {
                    let share = Scalar::from(&scalars[0]);
                    let mac = Scalar::from(&scalars[1]);
                    let public_modifier = Scalar::from(&scalars[2]);

                    results.push(ResultValue::Point(point * share));
                    results.push(ResultValue::Point(point * mac));
                    results.push(ResultValue::Point(point * public_modifier));
                }

                results
            },
        );

        AuthenticatedStarkPointResult::from_flattened_iterator(results.into_iter())
    }
}

// === MulAssign === //

impl MulAssign<&Scalar> for StarkPoint {
    fn mul_assign(&mut self, rhs: &Scalar) {
        self.0 *= rhs.0;
    }
}

// -------------------
// | Iterator Traits |
// -------------------

impl Sum for StarkPoint {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(StarkPoint::identity(), |acc, x| acc + x)
    }
}

impl Sum for StarkPointResult {
    /// Assumes the iterator is non-empty
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        let first = iter.next().expect("empty iterator");
        iter.fold(first, |acc, x| acc + x)
    }
}

/// MSM Implementation
impl StarkPoint {
    /// Compute the multiscalar multiplication of the given scalars and points
    pub fn msm(scalars: &[Scalar], points: &[StarkPoint]) -> StarkPoint {
        assert_eq!(
            scalars.len(),
            points.len(),
            "msm cannot compute on vectors of unequal length"
        );

        let n = scalars.len();
        if n < MSM_SIZE_THRESHOLD {
            return scalars.iter().zip(points.iter()).map(|(s, p)| s * p).sum();
        }

        let affine_points = points.iter().map(|p| p.0.into_affine()).collect_vec();
        let stripped_scalars = scalars.iter().map(|s| s.0).collect_vec();
        StarkPointInner::msm(&affine_points, &stripped_scalars)
            .map(StarkPoint)
            .unwrap()
    }

    /// Compute the multiscalar multiplication of the given scalars and points
    /// represented as streaming iterators
    pub fn msm_iter<I, J>(scalars: I, points: J) -> StarkPoint
    where
        I: IntoIterator<Item = Scalar>,
        J: IntoIterator<Item = StarkPoint>,
    {
        let mut res = StarkPoint::identity();
        for (scalar_chunk, point_chunk) in scalars
            .into_iter()
            .chunks(MSM_CHUNK_SIZE)
            .into_iter()
            .zip(points.into_iter().chunks(MSM_CHUNK_SIZE).into_iter())
        {
            let scalars: Vec<Scalar> = scalar_chunk.collect();
            let points: Vec<StarkPoint> = point_chunk.collect();
            let chunk_res = StarkPoint::msm(&scalars, &points);

            res += chunk_res;
        }

        res
    }

    /// Compute the multiscalar multiplication of the given points with `ScalarResult`s
    pub fn msm_results(scalars: &[ScalarResult], points: &[StarkPoint]) -> StarkPointResult {
        assert_eq!(
            scalars.len(),
            points.len(),
            "msm cannot compute on vectors of unequal length"
        );

        let fabric = scalars[0].fabric();
        let scalar_ids = scalars.iter().map(|s| s.id()).collect_vec();

        // Clone `points` so that the gate closure may capture it
        let points = points.to_vec();
        fabric.new_gate_op(scalar_ids, move |args| {
            let scalars = args.into_iter().map(Scalar::from).collect_vec();

            ResultValue::Point(StarkPoint::msm(&scalars, &points))
        })
    }

    /// Compute the multiscalar multiplication of the given points with `ScalarResult`s
    /// as iterators. Assumes the iterators are non-empty
    pub fn msm_results_iter<I, J>(scalars: I, points: J) -> StarkPointResult
    where
        I: IntoIterator<Item = ScalarResult>,
        J: IntoIterator<Item = StarkPoint>,
    {
        Self::msm_results(
            &scalars.into_iter().collect_vec(),
            &points.into_iter().collect_vec(),
        )
    }

    /// Compute the multiscalar multiplication of the given authenticated scalars and plaintext points
    pub fn msm_authenticated(
        scalars: &[AuthenticatedScalarResult],
        points: &[StarkPoint],
    ) -> AuthenticatedStarkPointResult {
        assert_eq!(
            scalars.len(),
            points.len(),
            "msm cannot compute on vectors of unequal length"
        );

        let n = scalars.len();
        let fabric = scalars[0].fabric();
        let scalar_ids = scalars.iter().flat_map(|s| s.ids()).collect_vec();

        // Clone points to let the gate closure take ownership
        let points = points.to_vec();
        let res: Vec<StarkPointResult> = fabric.new_batch_gate_op(
            scalar_ids,
            AUTHENTICATED_SCALAR_RESULT_LEN, /* output_arity */
            move |args| {
                let mut shares = Vec::with_capacity(n);
                let mut macs = Vec::with_capacity(n);
                let mut modifiers = Vec::with_capacity(n);

                for chunk in args.chunks_exact(AUTHENTICATED_SCALAR_RESULT_LEN) {
                    shares.push(Scalar::from(chunk[0].to_owned()));
                    macs.push(Scalar::from(chunk[1].to_owned()));
                    modifiers.push(Scalar::from(chunk[2].to_owned()));
                }

                // Compute the MSM of the point
                vec![
                    StarkPoint::msm(&shares, &points),
                    StarkPoint::msm(&macs, &points),
                    StarkPoint::msm(&modifiers, &points),
                ]
                .into_iter()
                .map(ResultValue::Point)
                .collect_vec()
            },
        );

        AuthenticatedStarkPointResult {
            share: res[0].to_owned().into(),
            mac: res[1].to_owned().into(),
            public_modifier: res[2].to_owned(),
        }
    }

    /// Compute the multiscalar multiplication of the given authenticated scalars and plaintext points
    /// as iterators
    /// This method assumes that the iterators are of the same length
    pub fn msm_authenticated_iter<I, J>(scalars: I, points: J) -> AuthenticatedStarkPointResult
    where
        I: IntoIterator<Item = AuthenticatedScalarResult>,
        J: IntoIterator<Item = StarkPoint>,
    {
        let scalars: Vec<AuthenticatedScalarResult> = scalars.into_iter().collect();
        let points: Vec<StarkPoint> = points.into_iter().collect();

        Self::msm_authenticated(&scalars, &points)
    }
}

impl StarkPointResult {
    /// Compute the multiscalar multiplication of the given scalars and points
    pub fn msm_results(scalars: &[ScalarResult], points: &[StarkPointResult]) -> StarkPointResult {
        assert!(!scalars.is_empty(), "msm cannot compute on an empty vector");
        assert_eq!(
            scalars.len(),
            points.len(),
            "msm cannot compute on vectors of unequal length"
        );

        let n = scalars.len();
        let fabric = scalars[0].fabric();
        let all_ids = scalars
            .iter()
            .map(|s| s.id())
            .chain(points.iter().map(|p| p.id()))
            .collect_vec();

        fabric.new_gate_op(all_ids, move |mut args| {
            let scalars = args.drain(..n).map(Scalar::from).collect_vec();
            let points = args.into_iter().map(StarkPoint::from).collect_vec();

            let res = StarkPoint::msm(&scalars, &points);
            ResultValue::Point(res)
        })
    }

    /// Compute the multiscalar multiplication of the given scalars and points
    /// represented as streaming iterators
    ///
    /// Assumes the iterator is non-empty
    pub fn msm_results_iter<I, J>(scalars: I, points: J) -> StarkPointResult
    where
        I: IntoIterator<Item = ScalarResult>,
        J: IntoIterator<Item = StarkPointResult>,
    {
        Self::msm_results(
            &scalars.into_iter().collect_vec(),
            &points.into_iter().collect_vec(),
        )
    }

    /// Compute the multiscalar multiplication of the given `AuthenticatedScalar`s and points
    pub fn msm_authenticated(
        scalars: &[AuthenticatedScalarResult],
        points: &[StarkPointResult],
    ) -> AuthenticatedStarkPointResult {
        assert_eq!(
            scalars.len(),
            points.len(),
            "msm cannot compute on vectors of unequal length"
        );

        let n = scalars.len();
        let fabric = scalars[0].fabric();
        let all_ids = scalars
            .iter()
            .flat_map(|s| s.ids())
            .chain(points.iter().map(|p| p.id()))
            .collect_vec();

        let res = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_STARK_POINT_RESULT_LEN, /* output_arity */
            move |mut args| {
                let mut shares = Vec::with_capacity(n);
                let mut macs = Vec::with_capacity(n);
                let mut modifiers = Vec::with_capacity(n);

                for mut chunk in args
                    .drain(..AUTHENTICATED_SCALAR_RESULT_LEN * n)
                    .map(Scalar::from)
                    .chunks(AUTHENTICATED_SCALAR_RESULT_LEN)
                    .into_iter()
                {
                    shares.push(chunk.next().unwrap());
                    macs.push(chunk.next().unwrap());
                    modifiers.push(chunk.next().unwrap());
                }

                let points = args.into_iter().map(StarkPoint::from).collect_vec();

                vec![
                    StarkPoint::msm(&shares, &points),
                    StarkPoint::msm(&macs, &points),
                    StarkPoint::msm(&modifiers, &points),
                ]
                .into_iter()
                .map(ResultValue::Point)
                .collect_vec()
            },
        );

        AuthenticatedStarkPointResult {
            share: res[0].to_owned().into(),
            mac: res[1].to_owned().into(),
            public_modifier: res[2].to_owned(),
        }
    }

    /// Compute the multiscalar multiplication of the given `AuthenticatedScalar`s and points
    /// represented as streaming iterators
    pub fn msm_authenticated_iter<I, J>(scalars: I, points: J) -> AuthenticatedStarkPointResult
    where
        I: IntoIterator<Item = AuthenticatedScalarResult>,
        J: IntoIterator<Item = StarkPointResult>,
    {
        let scalars: Vec<AuthenticatedScalarResult> = scalars.into_iter().collect();
        let points: Vec<StarkPointResult> = points.into_iter().collect();

        Self::msm_authenticated(&scalars, &points)
    }
}

// ---------
// | Tests |
// ---------

/// We test our config against a known implementation of the Stark curve:
///     https://github.com/xJonathanLEI/starknet-rs
#[cfg(test)]
mod test {
    use rand::{thread_rng, RngCore};
    use starknet_curve::{curve_params::GENERATOR, ProjectivePoint};

    use crate::algebra::test_helper::{
        arkworks_point_to_starknet, compare_points, prime_field_to_starknet_felt, random_point,
        starknet_rs_scalar_mul,
    };

    use super::*;
    /// Test that the generators are the same between the two curve representations
    #[test]
    fn test_generators() {
        let generator_1 = StarkPoint::generator();
        let generator_2 = ProjectivePoint::from_affine_point(&GENERATOR);

        assert!(compare_points(&generator_1, &generator_2));
    }

    /// Tests point addition
    #[test]
    fn test_point_addition() {
        let p1 = random_point();
        let q1 = random_point();

        let p2 = arkworks_point_to_starknet(&p1);
        let q2 = arkworks_point_to_starknet(&q1);

        let r1 = p1 + q1;

        // Only `AddAssign` is implemented on `ProjectivePoint`
        let mut r2 = p2;
        r2 += &q2;

        assert!(compare_points(&r1, &r2));
    }

    /// Tests scalar multiplication
    #[test]
    fn test_scalar_mul() {
        let mut rng = thread_rng();
        let s1 = Scalar::random(&mut rng);
        let p1 = random_point();

        let s2 = prime_field_to_starknet_felt(&s1.0);
        let p2 = arkworks_point_to_starknet(&p1);

        let r1 = p1 * s1;
        let r2 = starknet_rs_scalar_mul(&s2, &p2);

        assert!(compare_points(&r1, &r2));
    }

    /// Tests addition with the additive identity
    #[test]
    fn test_additive_identity() {
        let p1 = random_point();
        let res = p1 + StarkPoint::identity();

        assert_eq!(p1, res);
    }

    /// Tests the size of the curve point serialization
    #[test]
    fn test_point_serialized() {
        // Sample a random point and serialize it to bytes
        let point = random_point();
        let res = point.to_bytes();

        assert_eq!(res.len(), STARK_POINT_BYTES);

        // Deserialize and verify the points are equal
        let deserialized = StarkPoint::from_bytes(&res).unwrap();
        assert_eq!(point, deserialized);
    }

    /// Tests the hash-to-curve implementation `StarkPoint::from_uniform_bytes`
    #[test]
    fn test_hash_to_curve() {
        // Sample random bytes into a buffer
        let mut rng = thread_rng();
        let mut buf = [0u8; STARK_UNIFORM_BYTES];
        rng.fill_bytes(&mut buf);

        // As long as the method does not error, the test is successful
        let res = StarkPoint::from_uniform_bytes(buf);
        assert!(res.is_ok())
    }

    /// Tests converting to and from affine coordinates
    #[test]
    fn test_to_from_affine_coords() {
        let projective = random_point();
        let affine = projective.to_affine();

        let x = BigUint::from(affine.x);
        let y = BigUint::from(affine.y);
        let recovered = StarkPoint::from_affine_coords(x, y);

        assert_eq!(projective, recovered);
    }
}
