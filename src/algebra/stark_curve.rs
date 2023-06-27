//! Defines the `Scalar` type of the Starknet field

use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{
    fields::{Fp256, MontBackend, MontConfig},
    MontFp,
};

use lazy_static::lazy_static;

// -------------
// | Constants |
// -------------

/// The `b` value in the short Weierstrass equation of the Starknet curve
/// serialized as a hex string
const STARKNET_CURVE_B_HEX: &str =
    "0x6F21413EFBE40DE150E596D72F7A8C5609AD26C15C915C1F4CDFCB99CEE9E89";

// lazy_static! {
//     /// The `a` value in the short Weierstrass equation of the Starknet curve
//     // static ref STARKNET_CURVE_A: FieldElement<Scalar> = FieldElement::from(1);
//     /// The `b` value in the short Weierstrass equation of the Starknet curve
//     // static ref STARKNET_CURVE_B: FieldElement<Scalar> = FieldElement::from_hex(STARKNET_CURVE_B_HEX).unwrap();
// }

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
