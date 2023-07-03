//! Defines the authenticated (malicious secure) variant of the MPC scalar type

use std::ops::{Add, Mul, Neg, Sub};

use crate::{
    fabric::{MpcFabric, ResultValue},
    PARTY0,
};

use super::{
    macros::{impl_borrow_variants, impl_commutative},
    mpc_scalar::MpcScalarResult,
    stark_curve::{Scalar, ScalarResult},
};

/// A maliciously secure wrapper around an `MpcScalar`, includes a MAC as per the
/// SPDZ protocol: https://eprint.iacr.org/2011/535.pdf
/// that ensures security against a malicious adversary
#[derive(Clone)]
pub struct AuthenticatedScalarResult {
    /// The secret shares of the underlying value
    pub value: MpcScalarResult,
    /// The SPDZ style, unconditionally secure MAC of the value
    ///
    /// If the value is `x`, parties hold secret shares of the value
    /// \delta * x for the global MAC key `\delta`. The parties individually
    /// hold secret shares of this MAC key [\delta], so we can very naturally
    /// extend the secret share arithmetic of the underlying `MpcScalar` to
    /// the MAC updates as well
    pub mac: MpcScalarResult,
    /// The public modifier tracks additions and subtractions of public values to the
    /// underlying value. This is necessary because in the case of a public addition, only the first
    /// party adds the public value to their share, so the second party must track this up
    /// until the point that the value is opened and the MAC is checked
    pub public_modifier: ScalarResult,
    /// A reference to the underlying fabric
    fabric: MpcFabric,
}

impl AuthenticatedScalarResult {
    /// Create a new result from the given shared value
    pub fn new_shared(value: ScalarResult) -> Self {
        // Create an `MpcScalar` to represent the fact that this is a shared value
        let fabric = value.fabric.clone();

        let mpc_value = MpcScalarResult::new_shared(value);
        let mac = fabric.borrow_mac_key() * mpc_value.clone();

        // Allocate a zero for the public modifier
        let public_modifier = fabric.allocate_value(ResultValue::Scalar(Scalar::from(0)));

        Self {
            value: mpc_value,
            mac,
            public_modifier,
            fabric,
        }
    }

    /// Open the value without checking its MAC
    pub fn open(&self) -> ScalarResult {
        self.value.open()
    }
}

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl Add<&Scalar> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn add(self, rhs: &Scalar) -> Self::Output {
        let new_share = if self.fabric.party_id() == PARTY0 {
            &self.value + rhs
        } else {
            self.value.clone() + Scalar::from(0)
        };

        // Both parties add the public value to their modifier, and the MACs do not change
        // when adding a public value
        let new_modifier = &self.public_modifier + rhs;
        AuthenticatedScalarResult {
            value: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Add, add, +, Scalar, Output=AuthenticatedScalarResult);
impl_commutative!(AuthenticatedScalarResult, Add, add, +, Scalar, Output=AuthenticatedScalarResult);

impl Add<&ScalarResult> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn add(self, rhs: &ScalarResult) -> Self::Output {
        // As above, only party 0 adds the public value to their share, but both parties
        // track this with the modifier
        //
        // Party 1 adds a zero value to their share to allocate a new ID for the result
        let new_share = if self.fabric.party_id() == PARTY0 {
            &self.value + rhs
        } else {
            self.value.clone() + Scalar::from(0)
        };

        let new_modifier = &self.public_modifier + rhs;
        AuthenticatedScalarResult {
            value: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Add, add, +, ScalarResult, Output=AuthenticatedScalarResult);
impl_commutative!(AuthenticatedScalarResult, Add, add, +, ScalarResult, Output=AuthenticatedScalarResult);

impl Add<&AuthenticatedScalarResult> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn add(self, rhs: &AuthenticatedScalarResult) -> Self::Output {
        AuthenticatedScalarResult {
            value: &self.value + &rhs.value,
            mac: &self.mac + &rhs.mac,
            public_modifier: self.public_modifier.clone(),
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Add, add, +, AuthenticatedScalarResult, Output=AuthenticatedScalarResult);

// === Subtraction === //

impl Sub<&Scalar> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    /// As in the case for addition, only party 0 subtracts the public value from their share,
    /// but both parties track this in the public modifier
    fn sub(self, rhs: &Scalar) -> Self::Output {
        // Party 1 subtracts a zero value from their share to allocate a new ID for the result
        // and stay in sync with party 0
        let new_share = if self.fabric.party_id() == PARTY0 {
            &self.value - rhs
        } else {
            self.value.clone() - Scalar::from(0)
        };

        // Both parties add the public value to their modifier, and the MACs do not change
        // when adding a public value
        let new_modifier = &self.public_modifier - rhs;
        AuthenticatedScalarResult {
            value: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Sub, sub, -, Scalar, Output=AuthenticatedScalarResult);
impl_commutative!(AuthenticatedScalarResult, Sub, sub, -, Scalar, Output=AuthenticatedScalarResult);

impl Sub<&ScalarResult> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn sub(self, rhs: &ScalarResult) -> Self::Output {
        // Party 1 subtracts a zero value from their share to allocate a new ID for the result
        // and stay in sync with party 0
        let new_share = if self.fabric.party_id() == PARTY0 {
            &self.value - rhs
        } else {
            self.value.clone() - Scalar::from(0)
        };

        // Both parties add the public value to their modifier, and the MACs do not change
        // when adding a public value
        let new_modifier = &self.public_modifier - rhs;
        AuthenticatedScalarResult {
            value: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Sub, sub, -, ScalarResult, Output=AuthenticatedScalarResult);
impl_commutative!(AuthenticatedScalarResult, Sub, sub, -, ScalarResult, Output=AuthenticatedScalarResult);

impl Sub<&AuthenticatedScalarResult> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn sub(self, rhs: &AuthenticatedScalarResult) -> Self::Output {
        AuthenticatedScalarResult {
            value: &self.value - &rhs.value,
            mac: &self.mac - &rhs.mac,
            public_modifier: self.public_modifier.clone(),
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Sub, sub, -, AuthenticatedScalarResult, Output=AuthenticatedScalarResult);

// === Negation === //

impl Neg for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn neg(self) -> Self::Output {
        AuthenticatedScalarResult {
            value: -&self.value,
            mac: -&self.mac,
            public_modifier: -&self.public_modifier,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Neg, neg, -);

// === Multiplication === //

impl Mul<&Scalar> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        AuthenticatedScalarResult {
            value: &self.value * rhs,
            mac: &self.mac * rhs,
            public_modifier: &self.public_modifier * rhs,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Mul, mul, *, Scalar, Output=AuthenticatedScalarResult);
impl_commutative!(AuthenticatedScalarResult, Mul, mul, *, Scalar, Output=AuthenticatedScalarResult);

impl Mul<&ScalarResult> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn mul(self, rhs: &ScalarResult) -> Self::Output {
        AuthenticatedScalarResult {
            value: &self.value * rhs,
            mac: &self.mac * rhs,
            public_modifier: &self.public_modifier * rhs,
            fabric: self.fabric.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Mul, mul, *, ScalarResult, Output=AuthenticatedScalarResult);
impl_commutative!(AuthenticatedScalarResult, Mul, mul, *, ScalarResult, Output=AuthenticatedScalarResult);

impl Mul<&AuthenticatedScalarResult> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    // Use the Beaver trick
    fn mul(self, rhs: &AuthenticatedScalarResult) -> Self::Output {
        // Sample a beaver triplet
        let (a, b, c) = self.fabric.next_authenticated_beaver_triple();

        // Mask the left and right hand sides
        let masked_lhs = self - &a;
        let masked_rhs = rhs - &b;

        // Open these values to get d = lhs - a, e = rhs - b
        let d = masked_lhs.open();
        let e = masked_rhs.open();

        // Use the same beaver identify as in the `MpcScalar` case, but now the public
        // multiplications are applied to the MACs and the public modifiers as well
        // Identity: [x * y] = de + d[b] + e[a] + [c]
        &d * &e + d * b + e * a + c
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Mul, mul, *, AuthenticatedScalarResult, Output=AuthenticatedScalarResult);
