//! Defines the `Scalar` type of the Starknet field

use std::ops::{Add, Mul, Neg, Sub};

use ark_ec::{
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{
    fields::{Fp256, MontBackend, MontConfig},
    MontFp, PrimeField,
};
use num_bigint::BigUint;

use crate::fabric::{cast_args, ResultHandle, ResultValue};

use super::macros::{impl_borrow_variants, impl_commutative};

// -----------
// | Helpers |
// -----------

/// Convert a scalar to a `BigUint`
pub fn scalar_to_biguint<F: PrimeField>(scalar: &F) -> num_bigint::BigUint {
    (*scalar).into()
}

/// Convert a `BigUint` to a scalar
pub fn biguint_to_scalar<F: PrimeField>(biguint: &BigUint) -> F {
    let bytes = biguint.to_bytes_le();
    F::from_le_bytes_mod_order(&bytes)
}

// -------------------------------
// | Curve and Scalar Definition |
// -------------------------------

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
pub type Scalar = Fp256<MontBackend<StarknetFrConfig, 4>>;

/// A type alias for a projective curve point on the Stark curve
pub type StarkPoint = Projective<StarknetCurveConfig>;

/// The Stark curve in the arkworks short Weierstrass curve representation
pub struct StarknetCurveConfig;
impl CurveConfig for StarknetCurveConfig {
    type BaseField = StarknetBaseFelt;
    type ScalarField = Scalar;

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

// -----------------------------
// | Circuit Result Definition |
// -----------------------------

/// A type alias for a result that resolves to a `Scalar`
pub type ScalarResult = ResultHandle<Scalar>;

impl Add<&Scalar> for &ScalarResult {
    type Output = ScalarResult;

    fn add(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let [lhs]: [Scalar; 1] = cast_args(args);
            ResultValue::Scalar(lhs + rhs)
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
            ResultValue::Scalar(lhs + rhs)
        })
    }
}
impl_borrow_variants!(ScalarResult, Add, add, +, ScalarResult);

impl Sub<&Scalar> for &ScalarResult {
    type Output = ScalarResult;

    fn sub(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let [lhs]: [Scalar; 1] = cast_args(args);
            ResultValue::Scalar(lhs - rhs)
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
            ResultValue::Scalar(lhs - rhs)
        })
    }
}
impl_borrow_variants!(ScalarResult, Sub, sub, -, ScalarResult);

impl Mul<&Scalar> for &ScalarResult {
    type Output = ScalarResult;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let [lhs]: [Scalar; 1] = cast_args(args);
            ResultValue::Scalar(lhs * rhs)
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
            ResultValue::Scalar(lhs * rhs)
        })
    }
}
impl_borrow_variants!(ScalarResult, Mul, mul, *, ScalarResult);

impl Neg for &ScalarResult {
    type Output = ScalarResult;

    fn neg(self) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id], |args| {
            let [lhs]: [Scalar; 1] = cast_args(args);
            ResultValue::Scalar(-lhs)
        })
    }
}
impl_borrow_variants!(ScalarResult, Neg, neg, -);

/// A type alias for a result that resolves to a `StarkPoint`
pub type StarkPointResult = ResultHandle<StarkPoint>;

impl Add<&StarkPointResult> for &StarkPointResult {
    type Output = StarkPointResult;

    fn add(self, rhs: &StarkPointResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            let [lhs, rhs]: [StarkPoint; 2] = cast_args(args);
            ResultValue::Point(lhs + rhs)
        })
    }
}
impl_borrow_variants!(StarkPointResult, Add, add, +, StarkPointResult);

impl Sub<&StarkPointResult> for &StarkPointResult {
    type Output = StarkPointResult;

    fn sub(self, rhs: &StarkPointResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            let [lhs, rhs]: [StarkPoint; 2] = cast_args(args);
            ResultValue::Point(lhs - rhs)
        })
    }
}
impl_borrow_variants!(StarkPointResult, Sub, sub, -, StarkPointResult);

impl Neg for &StarkPointResult {
    type Output = StarkPointResult;

    fn neg(self) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id], |args| {
            let [lhs]: [StarkPoint; 1] = cast_args(args);
            ResultValue::Point(-lhs)
        })
    }
}
impl_borrow_variants!(StarkPointResult, Neg, neg, -);

impl Mul<&Scalar> for &StarkPointResult {
    type Output = StarkPointResult;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let [lhs]: [StarkPoint; 1] = cast_args(args);
            ResultValue::Point(lhs * rhs)
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
            let [rhs]: [Scalar; 1] = cast_args(args);
            ResultValue::Point(self_owned * rhs)
        })
    }
}

impl Mul<&ScalarResult> for &StarkPointResult {
    type Output = StarkPointResult;

    fn mul(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: StarkPoint = args.remove(0).into();
            let rhs: Scalar = args.remove(0).into();

            ResultValue::Point(lhs * rhs)
        })
    }
}
impl_borrow_variants!(StarkPointResult, Mul, mul, *, ScalarResult);
impl_commutative!(StarkPointResult, Mul, mul, *, ScalarResult);

// ---------
// | Tests |
// ---------

/// We test our config against a known implementation of the Stark curve:
///     https://github.com/xJonathanLEI/starknet-rs
#[cfg(test)]
mod test {
    use ark_ec::short_weierstrass::Projective;
    use starknet_curve::{curve_params::GENERATOR, ProjectivePoint};

    use crate::{
        algebra::test_helper::{
            arkworks_point_to_starknet, compare_points, random_point, scalar_to_starknet_felt,
            starknet_rs_scalar_mul,
        },
        random_scalar,
    };

    use super::*;
    /// Test that the generators are the same between the two curve representations
    #[test]
    fn test_generators() {
        let generator_1 = Projective::from(StarknetCurveConfig::GENERATOR);
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
        let s1 = random_scalar();
        let p1 = random_point();

        let s2 = scalar_to_starknet_felt(&s1);
        let p2 = arkworks_point_to_starknet(&p1);

        let r1 = p1 * s1;
        let r2 = starknet_rs_scalar_mul(&s2, &p2);

        assert!(compare_points(&r1, &r2));
    }
}
