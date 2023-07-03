//! Defines an unauthenticated shared curve point type which forms the basis
//! of the authenticated curve point type

use std::ops::{Add, Mul, Neg, Sub};

use ark_ec::Group;

use crate::{
    fabric::{cast_args, MpcFabric, ResultHandle, ResultValue},
    network::NetworkPayload,
    PARTY0,
};

use super::{
    macros::{impl_borrow_variants, impl_commutative},
    mpc_scalar::MpcScalarResult,
    stark_curve::{Scalar, ScalarResult, StarkPoint, StarkPointResult},
};

/// Defines a secret shared type of a curve point
#[derive(Clone, Debug)]
pub struct MpcStarkPoint {
    /// The underlying value held by the local party
    pub(crate) value: StarkPoint,
    /// A reference to the underlying fabric that this value is allocated in
    pub(crate) fabric: MpcFabric,
}

/// Defines the result handle type that represents a future result of an `MpcStarkPoint`
pub type MpcStarkPointResult = ResultHandle<MpcStarkPoint>;
impl MpcStarkPointResult {
    /// Creates an `MpcStarkPoint` from a given underlying point assumed to be a secret share
    pub fn new_shared(
        value: ResultHandle<StarkPoint>,
        fabric: MpcFabric,
    ) -> ResultHandle<MpcStarkPoint> {
        let fabric_clone = fabric.clone();
        fabric.new_gate_op(vec![value.id], move |args| {
            // Cast the args
            let [value]: [StarkPoint; 1] = cast_args(args);
            ResultValue::MpcStarkPoint(MpcStarkPoint {
                value,
                fabric: fabric_clone,
            })
        })
    }

    /// Open the value; both parties send their shares to the counterparty
    pub fn open(&self) -> ResultHandle<StarkPoint> {
        // Party zero sends first then receives
        let (share0, share1) = if self.fabric.party_id() == PARTY0 {
            let party0_value: ResultHandle<StarkPoint> =
                self.fabric.new_network_op(vec![self.id], |args| {
                    let [mpc_value]: [MpcStarkPoint; 1] = cast_args(args);
                    NetworkPayload::Point(mpc_value.value)
                });
            let party1_value = self.fabric.receive_value();

            (party0_value, party1_value)
        } else {
            let party0_value = self.fabric.receive_value();
            let party1_value: ResultHandle<StarkPoint> =
                self.fabric.new_network_op(vec![self.id], |args| {
                    let [mpc_value]: [MpcStarkPoint; 1] = cast_args(args);
                    NetworkPayload::Point(mpc_value.value)
                });

            (party0_value, party1_value)
        };

        share0 + share1
    }
}

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl Add<&StarkPoint> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    // Only party 0 adds the plaintext value to its share
    fn add(self, rhs: &StarkPoint) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let [lhs]: [MpcStarkPoint; 1] = cast_args(args);

            if lhs.fabric.party_id() == PARTY0 {
                ResultValue::MpcStarkPoint(MpcStarkPoint {
                    value: lhs.value + rhs,
                    fabric: lhs.fabric,
                })
            } else {
                ResultValue::MpcStarkPoint(lhs)
            }
        })
    }
}
impl_borrow_variants!(MpcStarkPointResult, Add, add, +, StarkPoint);
impl_commutative!(MpcStarkPointResult, Add, add, +, StarkPoint);

impl Add<&StarkPointResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    // Only party 0 adds the plaintext value to its share
    fn add(self, rhs: &StarkPointResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: MpcStarkPoint = args.remove(0).into();
            let rhs: StarkPoint = args.remove(0).into();

            if lhs.fabric.party_id() == PARTY0 {
                ResultValue::MpcStarkPoint(MpcStarkPoint {
                    value: lhs.value + rhs,
                    fabric: lhs.fabric,
                })
            } else {
                ResultValue::MpcStarkPoint(lhs)
            }
        })
    }
}
impl_borrow_variants!(MpcStarkPointResult, Add, add, +, StarkPointResult);
impl_commutative!(MpcStarkPointResult, Add, add, +, StarkPointResult);

impl Add<&MpcStarkPointResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn add(self, rhs: &MpcStarkPointResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            let [lhs, rhs]: [MpcStarkPoint; 2] = cast_args(args);

            ResultValue::MpcStarkPoint(MpcStarkPoint {
                value: lhs.value + rhs.value,
                fabric: lhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcStarkPointResult, Add, add, +, MpcStarkPointResult);

// === Subtraction === //

impl Sub<&StarkPoint> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    // Only party 0 subtracts the plaintext value
    fn sub(self, rhs: &StarkPoint) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let [lhs]: [MpcStarkPoint; 1] = cast_args(args);

            if lhs.fabric.party_id() == PARTY0 {
                ResultValue::MpcStarkPoint(MpcStarkPoint {
                    value: lhs.value - rhs,
                    fabric: lhs.fabric,
                })
            } else {
                ResultValue::MpcStarkPoint(lhs)
            }
        })
    }
}
impl_borrow_variants!(MpcStarkPointResult, Sub, sub, -, StarkPoint);

impl Sub<&StarkPointResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn sub(self, rhs: &StarkPointResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: MpcStarkPoint = args.remove(0).into();
            let rhs: StarkPoint = args.remove(0).into();

            if lhs.fabric.party_id() == PARTY0 {
                ResultValue::MpcStarkPoint(MpcStarkPoint {
                    value: lhs.value - rhs,
                    fabric: lhs.fabric,
                })
            } else {
                ResultValue::MpcStarkPoint(lhs)
            }
        })
    }
}
impl_borrow_variants!(MpcStarkPointResult, Sub, sub, -, StarkPointResult);

impl Sub<&MpcStarkPointResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn sub(self, rhs: &MpcStarkPointResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            let [lhs, rhs]: [MpcStarkPoint; 2] = cast_args(args);

            ResultValue::MpcStarkPoint(MpcStarkPoint {
                value: lhs.value - rhs.value,
                fabric: lhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcStarkPointResult, Sub, sub, -, MpcStarkPointResult);

// === Negation === //

impl Neg for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn neg(self) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id], |mut args| {
            let mpc_val: MpcStarkPoint = args.remove(0).into();
            ResultValue::MpcStarkPoint(MpcStarkPoint {
                value: -mpc_val.value,
                fabric: mpc_val.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcStarkPointResult, Neg, neg, -);

// === Scalar Multiplication === //

impl Mul<&Scalar> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            let [lhs]: [MpcStarkPoint; 1] = cast_args(args);

            ResultValue::MpcStarkPoint(MpcStarkPoint {
                value: lhs.value * rhs,
                fabric: lhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcStarkPointResult, Mul, mul, *, Scalar);
impl_commutative!(MpcStarkPointResult, Mul, mul, *, Scalar);

impl Mul<&ScalarResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn mul(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: MpcStarkPoint = args.remove(0).into();
            let rhs: Scalar = args.remove(0).into();

            ResultValue::MpcStarkPoint(MpcStarkPoint {
                value: lhs.value * rhs,
                fabric: lhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcStarkPointResult, Mul, mul, *, ScalarResult);
impl_commutative!(MpcStarkPointResult, Mul, mul, *, ScalarResult);

impl Mul<&MpcScalarResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    // Use the beaver trick as in the scalar case
    fn mul(self, rhs: &MpcScalarResult) -> Self::Output {
        let generator = StarkPoint::generator();
        let (a, b, c) = self.fabric.next_beaver_triple();

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
