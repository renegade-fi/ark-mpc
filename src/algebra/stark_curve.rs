//! Defines the `Scalar` type of the Starknet field

use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{
    fields::{Fp256, MontBackend, MontConfig},
    MontFp, PrimeField,
};

// -----------
// | Helpers |
// -----------

/// Convert a scalar to a `BigUint`
pub fn scalar_to_biguint<F: PrimeField>(scalar: &F) -> num_bigint::BigUint {
    (*scalar).into()
}

/// Convert a `BigUint` to a scalar
pub fn biguint_to_scalar<F: PrimeField>(biguint: num_bigint::BigUint) -> F {
    let bytes = biguint.to_bytes_le();
    F::from_le_bytes_mod_order(&bytes)
}

// -------------------------------
// | Curve and Scalar Definition |
// -------------------------------

/// The finite field that the Starknet curve is defined over
#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[generator = "3"]
pub struct StarknetFqConfig;
pub type StarknetBaseFelt = Fp256<MontBackend<StarknetFqConfig, 4>>;

/// The finite field representing the curve group of the Starknet curve
///
/// Note that this is not the field that the curve is defined over, but field of integers modulo
/// the order of the curve's group, see [here](https://crypto.stackexchange.com/questions/98124/is-the-stark-curve-a-safecurve)
/// for more information
#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105526743751716087489154079457884512865583"]
#[generator = "3"]
pub struct StarknetFrConfig;
pub type Scalar = Fp256<MontBackend<StarknetFrConfig, 4>>;

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

// ---------
// | Tests |
// ---------

/// We test our config against a known implementation of the Stark curve:
///     https://github.com/xJonathanLEI/starknet-rs
#[cfg(test)]
mod test {
    use ark_ec::{short_weierstrass::Projective, CurveGroup};
    use ark_ff::PrimeField;
    use num_bigint::BigUint;
    use starknet::core::types::FieldElement as StarknetFelt;
    use starknet_curve::{curve_params::GENERATOR, AffinePoint, ProjectivePoint};

    use super::*;

    // -----------
    // | Helpers |
    // -----------

    /// Generate a random scalar
    fn random_scalar() -> Scalar {
        let bytes: [u8; 32] = rand::random();
        Scalar::from_be_bytes_mod_order(&bytes)
    }

    /// Generate a random point, by multiplying the basepoint with a random scalar
    fn random_point() -> Projective<StarknetCurveConfig> {
        let scalar = random_scalar();
        let point = StarknetCurveConfig::GENERATOR * scalar;
        point * scalar
    }

    /// Convert a starknet felt to a BigUint
    fn starknet_felt_to_biguint(felt: &StarknetFelt) -> BigUint {
        BigUint::from_bytes_be(&felt.to_bytes_be())
    }

    /// Convert a `BigUint` to a starknet felt
    fn biguint_to_starknet_felt(biguint: &BigUint) -> StarknetFelt {
        let bytes = biguint.to_bytes_be();
        StarknetFelt::from_bytes_be(&bytes.try_into().unwrap()).unwrap()
    }

    /// Convert a `Scalar` to a `StarknetFelt`
    fn scalar_to_starknet_felt<F: PrimeField>(scalar: &F) -> StarknetFelt {
        biguint_to_starknet_felt(&scalar_to_biguint(scalar))
    }

    /// Convert a point in the arkworks representation to a point in the starknet representation
    fn arkworks_point_to_starknet(point: &Projective<StarknetCurveConfig>) -> ProjectivePoint {
        let affine = point.into_affine();
        let x = scalar_to_starknet_felt(&affine.x);
        let y = scalar_to_starknet_felt(&affine.y);

        ProjectivePoint::from_affine_point(&AffinePoint {
            x,
            y,
            infinity: false,
        })
    }

    /// Multiply a point in the starknet-rs `ProjectivePoint` representation with a scalar
    ///
    /// Multiplication is only implemented for a point and `&[bool]`, so this method essentially
    /// provides the bit decomposition  
    fn starknet_rs_scalar_mul(scalar: &StarknetFelt, point: &ProjectivePoint) -> ProjectivePoint {
        let bits = scalar.to_bits_le();
        point * &bits
    }

    /// Compare scalars from the two curve implementations
    fn compare_scalars<F: PrimeField>(s1: &F, s2: &StarknetFelt) -> bool {
        let s1_biguint = scalar_to_biguint(s1);
        let s2_biguint = starknet_felt_to_biguint(s2);

        s1_biguint == s2_biguint
    }

    /// Compare curve points between the two implementation
    fn compare_points(p1: &Projective<StarknetCurveConfig>, p2: &ProjectivePoint) -> bool {
        // Convert the points to affine coordinates
        let p1_affine = p1.into_affine();
        let x_1 = p1_affine.x;
        let y_1 = p1_affine.y;

        let z_inv = p2.z.invert().unwrap();
        let x_2 = p2.x * z_inv;
        let y_2 = p2.y * z_inv;

        compare_scalars(&x_1, &x_2) && compare_scalars(&y_1, &y_2)
    }

    // ---------
    // | Tests |
    // ---------

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
