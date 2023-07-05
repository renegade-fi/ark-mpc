//! Defines an malicious secure wrapper around an `MpcStarkPoint` type that includes a MAC
//! for ensuring computational integrity of an opened point

use std::ops::{Add, Mul, Neg, Sub};

use ark_ec::Group;
use ark_ff::Zero;

use crate::{
    algebra::stark_curve::StarkPoint,
    fabric::{MpcFabric, ResultValue},
    PARTY0,
};

use super::{
    authenticated_scalar::AuthenticatedScalarResult,
    macros::{impl_borrow_variants, impl_commutative},
    mpc_stark_point::MpcStarkPointResult,
    stark_curve::{Scalar, ScalarResult, StarkPointResult},
};

/// A maliciously secure wrapper around `MpcStarkPoint` that includes a MAC as per
/// the SPDZ protocol: https://eprint.iacr.org/2011/535.pdf
#[derive(Clone)]
pub struct AuthenticatedStarkPointResult {
    /// The local secret share of the underlying authenticated point
    pub(crate) value: MpcStarkPointResult,
    /// A SPDZ style, unconditionally secure MAC of the value
    /// This is used to ensure computational integrity of the opened value
    /// See the doc comment in `AuthenticatedScalar` for more details
    pub(crate) mac: MpcStarkPointResult,
    /// The public modifier tracks additions and subtractions of public values to the shares
    ///
    /// Only the first party adds/subtracts public values to their share, but the other parties
    /// must track this to validate the MAC when it is opened
    pub(crate) public_modifier: StarkPointResult,
    /// A reference to the underlying fabric
    pub(crate) fabric: MpcFabric,
}

impl AuthenticatedStarkPointResult {
    /// Creates a new `AuthenticatedStarkPoint` from a given underlying point
    pub fn new_shared(value: StarkPointResult) -> AuthenticatedStarkPointResult {
        // Create an `MpcStarkPoint` from the value
        let fabric_clone = value.fabric.clone();

        let mpc_value = MpcStarkPointResult::new_shared(value, fabric_clone.clone());
        let mac = fabric_clone.borrow_mac_key() * &mpc_value;

        // Allocate a zero point for the public modifier
        let public_modifier = fabric_clone.allocate_value(ResultValue::Point(StarkPoint::zero()));

        Self {
            value: mpc_value,
            mac,
            public_modifier,
            fabric: fabric_clone,
        }
    }

    /// Open the value without checking the MAC
    pub fn open(&self) -> StarkPointResult {
        self.value.open()
    }

    /// Open the value and check the MAC
    ///
    /// This follows the protocol detailed in
    ///     https://securecomputation.org/docs/pragmaticmpc.pdf
    pub fn open_authenticated(&self) {
        todo!()
    }
}

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl Add<&StarkPoint> for &AuthenticatedStarkPointResult {
    type Output = AuthenticatedStarkPointResult;

    fn add(self, other: &StarkPoint) -> AuthenticatedStarkPointResult {
        let new_share = if self.fabric.party_id() == PARTY0 {
            // Party zero adds the public value to their share
            &self.value + other
        } else {
            // Other parties just add the identity to the value to allocate a new op and keep
            // in sync with party 0
            &self.value + StarkPoint::zero()
        };

        // Add the public value to the MAC
        let new_modifier = &self.public_modifier - other;
        AuthenticatedStarkPointResult {
            value: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedStarkPointResult, Add, add, +, StarkPoint);
impl_commutative!(AuthenticatedStarkPointResult, Add, add, +, StarkPoint);

impl Add<&StarkPointResult> for &AuthenticatedStarkPointResult {
    type Output = AuthenticatedStarkPointResult;

    fn add(self, other: &StarkPointResult) -> AuthenticatedStarkPointResult {
        let new_share = if self.fabric.party_id() == PARTY0 {
            // Party zero adds the public value to their share
            &self.value + other
        } else {
            // Other parties just add the identity to the value to allocate a new op and keep
            // in sync with party 0
            &self.value + StarkPoint::zero()
        };

        // Add the public value to the MAC
        let new_modifier = &self.public_modifier - other;
        AuthenticatedStarkPointResult {
            value: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedStarkPointResult, Add, add, +, StarkPointResult);
impl_commutative!(AuthenticatedStarkPointResult, Add, add, +, StarkPointResult);

impl Add<&AuthenticatedStarkPointResult> for &AuthenticatedStarkPointResult {
    type Output = AuthenticatedStarkPointResult;

    fn add(self, other: &AuthenticatedStarkPointResult) -> AuthenticatedStarkPointResult {
        let new_share = &self.value + &other.value;

        // Add the public value to the MAC
        let new_mac = &self.mac + &other.mac;
        AuthenticatedStarkPointResult {
            value: new_share,
            mac: new_mac,
            public_modifier: self.public_modifier.clone(),
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedStarkPointResult, Add, add, +, AuthenticatedStarkPointResult);

// === Subtraction === //

impl Sub<&StarkPoint> for &AuthenticatedStarkPointResult {
    type Output = AuthenticatedStarkPointResult;

    fn sub(self, other: &StarkPoint) -> AuthenticatedStarkPointResult {
        let new_share = if self.fabric.party_id() == PARTY0 {
            // Party zero subtracts the public value from their share
            &self.value - other
        } else {
            // Other parties just subtract the identity from the value to allocate a new op and keep
            // in sync with party 0
            &self.value - StarkPoint::zero()
        };

        // Subtract the public value from the MAC
        let new_modifier = &self.public_modifier + other;
        AuthenticatedStarkPointResult {
            value: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedStarkPointResult, Sub, sub, -, StarkPoint);
impl_commutative!(AuthenticatedStarkPointResult, Sub, sub, -, StarkPoint);

impl Sub<&StarkPointResult> for &AuthenticatedStarkPointResult {
    type Output = AuthenticatedStarkPointResult;

    fn sub(self, other: &StarkPointResult) -> AuthenticatedStarkPointResult {
        let new_share = if self.fabric.party_id() == PARTY0 {
            // Party zero subtracts the public value from their share
            &self.value - other
        } else {
            // Other parties just subtract the identity from the value to allocate a new op and keep
            // in sync with party 0
            &self.value - StarkPoint::zero()
        };

        // Subtract the public value from the MAC
        let new_modifier = &self.public_modifier + other;
        AuthenticatedStarkPointResult {
            value: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedStarkPointResult, Sub, sub, -, StarkPointResult);
impl_commutative!(AuthenticatedStarkPointResult, Sub, sub, -, StarkPointResult);

impl Sub<&AuthenticatedStarkPointResult> for &AuthenticatedStarkPointResult {
    type Output = AuthenticatedStarkPointResult;

    fn sub(self, other: &AuthenticatedStarkPointResult) -> AuthenticatedStarkPointResult {
        let new_share = &self.value - &other.value;

        // Subtract the public value from the MAC
        let new_mac = &self.mac - &other.mac;
        AuthenticatedStarkPointResult {
            value: new_share,
            mac: new_mac,
            public_modifier: self.public_modifier.clone(),
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedStarkPointResult, Sub, sub, -, AuthenticatedStarkPointResult);

// === Negation == //

impl Neg for &AuthenticatedStarkPointResult {
    type Output = AuthenticatedStarkPointResult;

    fn neg(self) -> AuthenticatedStarkPointResult {
        let new_share = -&self.value;

        // Negate the public value in the MAC
        let new_mac = -&self.mac;
        AuthenticatedStarkPointResult {
            value: new_share,
            mac: new_mac,
            public_modifier: self.public_modifier.clone(),
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedStarkPointResult, Neg, neg, -);

// === Scalar Multiplication === //

impl Mul<&Scalar> for &AuthenticatedStarkPointResult {
    type Output = AuthenticatedStarkPointResult;

    fn mul(self, other: &Scalar) -> AuthenticatedStarkPointResult {
        let new_share = &self.value * other;

        // Multiply the public value in the MAC
        let new_mac = &self.mac * other;
        let new_modifier = &self.public_modifier * other;
        AuthenticatedStarkPointResult {
            value: new_share,
            mac: new_mac,
            public_modifier: new_modifier,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedStarkPointResult, Mul, mul, *, Scalar);
impl_commutative!(AuthenticatedStarkPointResult, Mul, mul, *, Scalar);

impl Mul<&ScalarResult> for &AuthenticatedStarkPointResult {
    type Output = AuthenticatedStarkPointResult;

    fn mul(self, other: &ScalarResult) -> AuthenticatedStarkPointResult {
        let new_share = &self.value * other;

        // Multiply the public value in the MAC
        let new_mac = &self.mac * other;
        let new_modifier = &self.public_modifier * other;
        AuthenticatedStarkPointResult {
            value: new_share,
            mac: new_mac,
            public_modifier: new_modifier,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedStarkPointResult, Mul, mul, *, ScalarResult);
impl_commutative!(AuthenticatedStarkPointResult, Mul, mul, *, ScalarResult);

impl Mul<&AuthenticatedScalarResult> for &AuthenticatedStarkPointResult {
    type Output = AuthenticatedStarkPointResult;

    // Beaver trick
    fn mul(self, rhs: &AuthenticatedScalarResult) -> AuthenticatedStarkPointResult {
        // Sample a beaver triple
        let generator = StarkPoint::generator();
        let (a, b, c) = self.fabric.next_authenticated_beaver_triple();

        // Open the values d = [rhs - a] and e = [lhs - bG] for curve group generator G
        let masked_rhs = rhs - &a;
        let masked_lhs = self - (&generator * &b);

        #[allow(non_snake_case)]
        let eG_open = masked_lhs.open();
        let d_open = masked_rhs.open();

        // Identity [x * yG] = deG + d[bG] + [a]eG + [c]G
        &d_open * &eG_open + &d_open * &(&generator * &b) + &a * eG_open + &c * generator
    }
}
impl_borrow_variants!(AuthenticatedStarkPointResult, Mul, mul, *, AuthenticatedScalarResult);
impl_commutative!(AuthenticatedStarkPointResult, Mul, mul, *, AuthenticatedScalarResult);
