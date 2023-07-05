//! Defines the authenticated (malicious secure) variant of the MPC scalar type

use std::{
    ops::{Add, Mul, Neg, Sub},
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Future, FutureExt};

use crate::{
    commitment::{PedersenCommitment, PedersenCommitmentResult},
    error::MpcError,
    fabric::{MpcFabric, ResultId, ResultValue},
    PARTY0,
};

use super::{
    authenticated_stark_point::AuthenticatedStarkPointResult,
    macros::{impl_borrow_variants, impl_commutative},
    mpc_scalar::{MpcScalar, MpcScalarResult},
    stark_curve::{Scalar, ScalarResult, StarkPoint, StarkPointResult},
};

/// A maliciously secure wrapper around an `MpcScalar`, includes a MAC as per the
/// SPDZ protocol: https://eprint.iacr.org/2011/535.pdf
/// that ensures security against a malicious adversary
#[derive(Clone)]
pub struct AuthenticatedScalarResult {
    /// The secret shares of the underlying value
    pub(crate) value: MpcScalarResult,
    /// The SPDZ style, unconditionally secure MAC of the value
    ///
    /// If the value is `x`, parties hold secret shares of the value
    /// \delta * x for the global MAC key `\delta`. The parties individually
    /// hold secret shares of this MAC key [\delta], so we can very naturally
    /// extend the secret share arithmetic of the underlying `MpcScalar` to
    /// the MAC updates as well
    pub(crate) mac: MpcScalarResult,
    /// The public modifier tracks additions and subtractions of public values to the
    /// underlying value. This is necessary because in the case of a public addition, only the first
    /// party adds the public value to their share, so the second party must track this up
    /// until the point that the value is opened and the MAC is checked
    pub(crate) public_modifier: ScalarResult,
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

    /// Get the ids of the results that must be awaited
    /// before the value is ready
    pub fn ids(&self) -> Vec<ResultId> {
        vec![self.value.id, self.mac.id, self.public_modifier.id]
    }

    /// Open the value without checking its MAC
    pub fn open(&self) -> ScalarResult {
        self.value.open()
    }

    /// Open the value and check its MAC
    ///
    /// This follows the protocol detailed in:
    ///     https://securecomputation.org/docs/pragmaticmpc.pdf
    /// Section 6.6.2
    pub fn open_authenticated(&self) -> AuthenticatedScalarOpenResult {
        // Both parties open the underlying value
        let recovered_value = self.value.open();

        // Add a gate to compute the MAC check value: `key_share * opened_value - mac_share`
        let mac_check_value: ScalarResult = self.fabric.new_gate_op(
            vec![
                self.fabric.borrow_mac_key().id,
                recovered_value.id,
                self.public_modifier.id,
                self.mac.id,
            ],
            move |mut args| {
                let mac_key: MpcScalar = args.remove(0).into();
                let value: Scalar = args.remove(0).into();
                let modifier: Scalar = args.remove(0).into();
                let mac: MpcScalar = args.remove(0).into();

                ResultValue::Scalar(mac_key.value * (value + modifier) - mac.value)
            },
        );

        // Compute a commitment to this value and share it with the peer
        let my_comm = PedersenCommitmentResult::commit(mac_check_value);
        let peer_commit = self.fabric.exchange_value(my_comm.commitment);

        // Once the parties have exchanged their commitments, they can open them, they have already exchanged
        // the underlying values and their commitments so all that is left is the blinder
        let peer_mac_check = self.fabric.exchange_value(my_comm.value.clone());

        let blinder_result: ScalarResult = self
            .fabric
            .allocate_value(ResultValue::Scalar(my_comm.blinder));
        let peer_blinder = self.fabric.exchange_value(blinder_result);

        // Check the commitment and the MAC result
        let commitment_check: ScalarResult = self.fabric.new_gate_op(
            vec![
                my_comm.value.id,
                peer_mac_check.id,
                peer_blinder.id,
                peer_commit.id,
            ],
            |mut args| {
                let my_comm_value: Scalar = args.remove(0).into();
                let peer_value: Scalar = args.remove(0).into();
                let blinder: Scalar = args.remove(0).into();
                let commitment: StarkPoint = args.remove(0).into();

                // Build a commitment from the gate inputs
                let their_comm = PedersenCommitment {
                    value: peer_value,
                    blinder,
                    commitment,
                };

                // Verify that the commitment to the MAC check opens correctly
                if !their_comm.verify() {
                    return ResultValue::Scalar(Scalar::from(0));
                }

                // Sum of the commitments should be zero
                if peer_value + my_comm_value != Scalar::from(0) {
                    return ResultValue::Scalar(Scalar::from(0));
                }

                ResultValue::Scalar(Scalar::from(1))
            },
        );

        AuthenticatedScalarOpenResult {
            value: recovered_value,
            mac_check: commitment_check,
        }
    }
}

/// The value that results from opening an `AuthenticatedScalarResult` and checking its
/// MAC. This encapsulates both the underlying value and the result of the MAC check
#[derive(Clone)]
pub struct AuthenticatedScalarOpenResult {
    /// The underlying value
    pub value: ScalarResult,
    /// The result of the MAC check
    pub mac_check: ScalarResult,
}

impl Future for AuthenticatedScalarOpenResult {
    type Output = Result<Scalar, MpcError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Await both of the underlying values
        let value = futures::ready!(self.as_mut().value.poll_unpin(cx));
        let mac_check = futures::ready!(self.as_mut().mac_check.poll_unpin(cx));

        if mac_check == Scalar::from(1) {
            Poll::Ready(Ok(value))
        } else {
            Poll::Ready(Err(MpcError::AuthenticationError))
        }
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
        let new_modifier = &self.public_modifier - rhs;
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

        let new_modifier = &self.public_modifier - rhs;
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
        let new_modifier = &self.public_modifier + rhs;
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
        let new_modifier = &self.public_modifier + rhs;
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

// === Curve Scalar Multiplication === //

impl Mul<&AuthenticatedScalarResult> for &StarkPoint {
    type Output = AuthenticatedStarkPointResult;

    fn mul(self, rhs: &AuthenticatedScalarResult) -> Self::Output {
        AuthenticatedStarkPointResult {
            value: self * &rhs.value,
            mac: self * &rhs.mac,
            public_modifier: self * &rhs.public_modifier,
            fabric: rhs.fabric.clone(),
        }
    }
}
impl_commutative!(StarkPoint, Mul, mul, *, AuthenticatedScalarResult, Output=AuthenticatedStarkPointResult);

impl Mul<&AuthenticatedScalarResult> for &StarkPointResult {
    type Output = AuthenticatedStarkPointResult;

    fn mul(self, rhs: &AuthenticatedScalarResult) -> Self::Output {
        AuthenticatedStarkPointResult {
            value: self * &rhs.value,
            mac: self * &rhs.mac,
            public_modifier: self * &rhs.public_modifier,
            fabric: rhs.fabric.clone(),
        }
    }
}
impl_borrow_variants!(StarkPointResult, Mul, mul, *, AuthenticatedScalarResult, Output=AuthenticatedStarkPointResult);
impl_commutative!(StarkPointResult, Mul, mul, *, AuthenticatedScalarResult, Output=AuthenticatedStarkPointResult);