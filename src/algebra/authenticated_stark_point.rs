//! Defines an malicious secure wrapper around an `MpcStarkPoint` type that includes a MAC
//! for ensuring computational integrity of an opened point

use std::{
    ops::{Add, Mul, Neg, Sub},
    pin::Pin,
    task::{Context, Poll},
};

use ark_ec::Group;
use ark_ff::Zero;
use futures::{Future, FutureExt};

use crate::{
    algebra::{mpc_scalar::MpcScalar, mpc_stark_point::MpcStarkPoint, stark_curve::StarkPoint},
    commitment::{HashCommitment, HashCommitmentResult},
    error::MpcError,
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
    pub fn open_authenticated(&self) -> AuthenticatedStarkPointOpenResult {
        // Both parties open the underlying value
        let recovered_value = self.value.open();

        // Add a gate to compute hte MAC check value: `key_share * opened_value - mac_share`
        let mac_check: StarkPointResult = self.fabric.new_gate_op(
            vec![
                self.fabric.borrow_mac_key().id,
                recovered_value.id,
                self.public_modifier.id,
                self.mac.id,
            ],
            |mut args| {
                let mac_key: MpcScalar = args.remove(0).into();
                let value: StarkPoint = args.remove(0).into();
                let modifier: StarkPoint = args.remove(0).into();
                let mac: MpcStarkPoint = args.remove(0).into();

                ResultValue::Point((value + modifier) * mac_key.value - mac.value)
            },
        );

        // Compute a commitment to this value and share it with the peer
        let my_comm = HashCommitmentResult::commit(mac_check.clone());
        let peer_commit = self.fabric.exchange_value(my_comm.commitment);

        // Once the parties have exchanged their commitments, they can open the underlying MAC check value
        // as they are bound by the commitment
        let peer_mac_check = self.fabric.exchange_value(my_comm.value.clone());
        let blinder_result: ScalarResult = self
            .fabric
            .allocate_value(ResultValue::Scalar(my_comm.blinder));
        let peer_blinder = self.fabric.exchange_value(blinder_result);

        // Check the peer's commitment and the sum of the MAC checks
        let commitment_check: ScalarResult = self.fabric.new_gate_op(
            vec![
                mac_check.id,
                peer_mac_check.id,
                peer_blinder.id,
                peer_commit.id,
            ],
            |mut args| {
                let my_mac_check: StarkPoint = args.remove(0).into();
                let peer_mac_check: StarkPoint = args.remove(0).into();
                let peer_blinder: Scalar = args.remove(0).into();
                let peer_commitment: Scalar = args.remove(0).into();

                // Check that the MAC check value is the correct opening of the
                // given commitment
                let peer_comm = HashCommitment {
                    value: peer_mac_check,
                    blinder: peer_blinder,
                    commitment: peer_commitment,
                };
                if !peer_comm.verify() {
                    return ResultValue::Scalar(Scalar::from(0));
                }

                // Check that the MAC check shares add up to the additive identity in
                // the Starknet curve group
                if my_mac_check + peer_mac_check != StarkPoint::zero() {
                    return ResultValue::Scalar(Scalar::from(0));
                }

                ResultValue::Scalar(Scalar::from(1))
            },
        );

        AuthenticatedStarkPointOpenResult {
            value: recovered_value,
            mac_check: commitment_check,
        }
    }
}

/// The value that results from opening an `AuthenticatedStarkPointResult` and checking its MAC. This encapsulates
/// both the underlying value and the result of the MAC check
#[derive(Clone)]
pub struct AuthenticatedStarkPointOpenResult {
    /// The underlying value
    pub(crate) value: StarkPointResult,
    /// The result of the MAC check
    pub(crate) mac_check: ScalarResult,
}

impl Future for AuthenticatedStarkPointOpenResult {
    type Output = Result<StarkPoint, MpcError>;

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

// ----------------
// | Test Helpers |
// ----------------

/// Defines testing helpers for testing secure opening, these methods are not safe to use
/// outside of tests
#[cfg(feature = "test_helpers")]
pub mod test_helpers {
    use crate::{
        algebra::{mpc_stark_point::MpcStarkPoint, stark_curve::StarkPoint},
        fabric::ResultValue,
    };

    use super::AuthenticatedStarkPointResult;

    /// Corrupt the MAC of a given authenticated point
    pub fn modify_mac(point: &mut AuthenticatedStarkPointResult, new_mac: StarkPoint) {
        point.mac = point
            .fabric
            .new_gate_op(vec![point.mac.id], move |mut args| {
                let mut mac: MpcStarkPoint = args.remove(0).into();
                mac.value = new_mac;

                ResultValue::MpcStarkPoint(mac)
            })
    }

    /// Corrupt the underlying secret share of a given authenticated point
    pub fn modify_share(point: &mut AuthenticatedStarkPointResult, new_share: StarkPoint) {
        point.value = point
            .fabric
            .new_gate_op(vec![point.value.id], move |mut args| {
                let mut share: MpcStarkPoint = args.remove(0).into();
                share.value = new_share;

                ResultValue::MpcStarkPoint(share)
            })
    }

    /// Corrupt the public modifier of a given authenticated point
    pub fn modify_public_modifier(
        point: &mut AuthenticatedStarkPointResult,
        new_modifier: StarkPoint,
    ) {
        point.public_modifier = point
            .fabric
            .new_gate_op(vec![], move |_args| ResultValue::Point(new_modifier));
    }
}
