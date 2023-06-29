//! Defines an unauthenticated shared scalar type which forms the basis of the
//! authenticated scalar type

use std::ops::{Add, Neg, Sub};

use crate::{
    fabric::{cast_args, MpcFabric, ResultHandle, ResultValue},
    network::NetworkPayload,
    Visibility, Visible, PARTY0,
};

use super::stark_curve::Scalar;

/// Defines a secret shared type over th `Scalar` field
#[derive(Clone, Debug)]
pub struct MpcScalar {
    /// The underlying value held by the local party
    ///
    /// If this is a private or public value, the value is held
    /// in the clear. Otherwise this represents a secret share of the
    /// underlying value
    value: Scalar,
    /// The visibility of the value, this determines whether the value is
    /// secret shared or not
    visibility: Visibility,
    /// A reference to the underlying fabric that this value is allocated in
    fabric: MpcFabric,
}

impl Visible for MpcScalar {
    fn visibility(&self) -> Visibility {
        self.visibility
    }
}

/// Defines the result handle type that represents a future result of an `MpcScalar`
pub type MpcScalarResult = ResultHandle<MpcScalar>;
impl MpcScalarResult {
    /// Creates an MPC scalar from a given underlying scalar assumed to be a secret share
    pub fn new_shared(value: ResultHandle<Scalar>, fabric: MpcFabric) -> ResultHandle<MpcScalar> {
        let fabric_clone = fabric.clone();
        fabric.new_gate_op(vec![value.id], move |args| {
            // Cast the args
            let [value]: [Scalar; 1] = cast_args(args);
            ResultValue::MpcScalar(MpcScalar {
                value,
                visibility: Visibility::Shared,
                fabric: fabric_clone,
            })
        })
    }

    /// Open the value; both parties send their shares to the counterparty
    pub fn open(&self) -> ResultHandle<Scalar> {
        // Party zero sends first then receives
        let (val0, val1) = if self.fabric.party_id() == PARTY0 {
            let party0_value: ResultHandle<Scalar> =
                self.fabric.new_network_op(vec![self.id], |args| {
                    let [mpc_value]: [MpcScalar; 1] = cast_args(args);
                    NetworkPayload::Scalar(mpc_value.value)
                });
            let party1_value: ResultHandle<Scalar> = self.fabric.receive_value();

            (party0_value, party1_value)
        } else {
            let party0_value: ResultHandle<Scalar> = self.fabric.receive_value();
            let party1_value: ResultHandle<Scalar> =
                self.fabric.new_network_op(vec![self.id], |args| {
                    let [mpc_value]: [MpcScalar; 1] = cast_args(args);
                    NetworkPayload::Scalar(mpc_value.value)
                });

            (party0_value, party1_value)
        };

        // Create the new value by combining the additive shares
        &val0 + &val1
    }
}

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl Add<&Scalar> for &MpcScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 adds the plaintext value as we do not secret share it
    fn add(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            // Cast the args
            let [lhs]: [MpcScalar; 1] = cast_args(args);

            if lhs.fabric.party_id() == PARTY0 {
                ResultValue::MpcScalar(MpcScalar {
                    value: lhs.value + rhs,
                    visibility: lhs.visibility,
                    fabric: lhs.fabric,
                })
            } else {
                ResultValue::MpcScalar(lhs)
            }
        })
    }
}

impl Add<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn add(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            // Cast the args
            let [lhs, rhs]: [MpcScalar; 2] = cast_args(args);
            ResultValue::MpcScalar(MpcScalar {
                value: lhs.value + rhs.value,
                visibility: Visibility::min_visibility_two(&lhs, &rhs),
                fabric: lhs.fabric.clone(),
            })
        })
    }
}

// === Subtraction === //

impl Sub<&Scalar> for &MpcScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            // Cast the args
            let [lhs]: [MpcScalar; 1] = cast_args(args);

            if lhs.fabric.party_id() == PARTY0 {
                ResultValue::MpcScalar(MpcScalar {
                    value: lhs.value - rhs,
                    visibility: lhs.visibility,
                    fabric: lhs.fabric,
                })
            } else {
                ResultValue::MpcScalar(lhs)
            }
        })
    }
}

impl Sub<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn sub(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            // Cast the args
            let [lhs, rhs]: [MpcScalar; 2] = cast_args(args);
            ResultValue::MpcScalar(MpcScalar {
                value: lhs.value - rhs.value,
                visibility: Visibility::min_visibility_two(&lhs, &rhs),
                fabric: lhs.fabric.clone(),
            })
        })
    }
}

impl Neg for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn neg(self) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id], |args| {
            // Cast the args
            let [lhs]: [MpcScalar; 1] = cast_args(args);
            ResultValue::MpcScalar(MpcScalar {
                value: -lhs.value,
                visibility: lhs.visibility,
                fabric: lhs.fabric,
            })
        })
    }
}
