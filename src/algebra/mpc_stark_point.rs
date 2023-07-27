//! Defines an unauthenticated shared curve point type which forms the basis
//! of the authenticated curve point type

use std::ops::{Add, Mul, Neg, Sub};

use crate::{
    fabric::{ResultHandle, ResultValue},
    network::NetworkPayload,
    MpcFabric, ResultId, PARTY0,
};

use super::{
    macros::{impl_borrow_variants, impl_commutative},
    mpc_scalar::MpcScalarResult,
    scalar::{Scalar, ScalarResult},
    stark_curve::{StarkPoint, StarkPointResult},
};

/// Defines a secret shared type of a curve point
#[derive(Clone, Debug)]
pub struct MpcStarkPointResult {
    /// The underlying value held by the local party
    pub(crate) share: StarkPointResult,
}

impl From<StarkPointResult> for MpcStarkPointResult {
    fn from(value: StarkPointResult) -> Self {
        Self { share: value }
    }
}

/// Defines the result handle type that represents a future result of an `MpcStarkPoint`
impl MpcStarkPointResult {
    /// Creates an `MpcStarkPoint` from a given underlying point assumed to be a secret share
    pub fn new_shared(value: StarkPointResult) -> MpcStarkPointResult {
        MpcStarkPointResult { share: value }
    }

    /// Get the ID of the underlying share's result
    pub fn id(&self) -> ResultId {
        self.share.id
    }

    /// Borrow the fabric that this result is allocated in
    pub fn fabric(&self) -> &MpcFabric {
        self.share.fabric()
    }

    /// Open the value; both parties send their shares to the counterparty
    pub fn open(&self) -> ResultHandle<StarkPoint> {
        let send_my_share =
            |args: Vec<ResultValue>| NetworkPayload::Point(args[0].to_owned().into());

        // Party zero sends first then receives
        let (share0, share1): (StarkPointResult, StarkPointResult) =
            if self.fabric().party_id() == PARTY0 {
                let party0_value = self.fabric().new_network_op(vec![self.id()], send_my_share);
                let party1_value = self.fabric().receive_value();

                (party0_value, party1_value)
            } else {
                let party0_value = self.fabric().receive_value();
                let party1_value = self.fabric().new_network_op(vec![self.id()], send_my_share);

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
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id()], move |args| {
                let lhs: StarkPoint = args[0].to_owned().into();

                if party_id == PARTY0 {
                    ResultValue::Point(lhs + rhs)
                } else {
                    ResultValue::Point(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Add, add, +, StarkPoint);
impl_commutative!(MpcStarkPointResult, Add, add, +, StarkPoint);

impl Add<&StarkPointResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    // Only party 0 adds the plaintext value to its share
    fn add(self, rhs: &StarkPointResult) -> Self::Output {
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], move |mut args| {
                let lhs: StarkPoint = args.remove(0).into();
                let rhs: StarkPoint = args.remove(0).into();

                if party_id == PARTY0 {
                    ResultValue::Point(lhs + rhs)
                } else {
                    ResultValue::Point(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Add, add, +, StarkPointResult);
impl_commutative!(MpcStarkPointResult, Add, add, +, StarkPointResult);

impl Add<&MpcStarkPointResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn add(self, rhs: &MpcStarkPointResult) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |args| {
                let lhs: StarkPoint = args[0].to_owned().into();
                let rhs: StarkPoint = args[1].to_owned().into();

                ResultValue::Point(lhs + rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Add, add, +, MpcStarkPointResult);

// === Subtraction === //

impl Sub<&StarkPoint> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    // Only party 0 subtracts the plaintext value
    fn sub(self, rhs: &StarkPoint) -> Self::Output {
        let rhs = *rhs;
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id()], move |args| {
                let lhs: StarkPoint = args[0].to_owned().into();

                if party_id == PARTY0 {
                    ResultValue::Point(lhs - rhs)
                } else {
                    ResultValue::Point(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Sub, sub, -, StarkPoint);

impl Sub<&StarkPointResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn sub(self, rhs: &StarkPointResult) -> Self::Output {
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], move |mut args| {
                let lhs: StarkPoint = args.remove(0).into();
                let rhs: StarkPoint = args.remove(0).into();

                if party_id == PARTY0 {
                    ResultValue::Point(lhs - rhs)
                } else {
                    ResultValue::Point(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Sub, sub, -, StarkPointResult);

impl Sub<&MpcStarkPointResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn sub(self, rhs: &MpcStarkPointResult) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |args| {
                let lhs: StarkPoint = args[0].to_owned().into();
                let rhs: StarkPoint = args[1].to_owned().into();

                ResultValue::Point(lhs - rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Sub, sub, -, MpcStarkPointResult);

// === Negation === //

impl Neg for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn neg(self) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id()], |mut args| {
                let mpc_val: StarkPoint = args.remove(0).into();
                ResultValue::Point(-mpc_val)
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Neg, neg, -);

// === Scalar Multiplication === //

impl Mul<&Scalar> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric()
            .new_gate_op(vec![self.id()], move |args| {
                let lhs: StarkPoint = args[0].to_owned().into();
                ResultValue::Point(lhs * rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Mul, mul, *, Scalar);
impl_commutative!(MpcStarkPointResult, Mul, mul, *, Scalar);

impl Mul<&ScalarResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn mul(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |mut args| {
                let lhs: StarkPoint = args.remove(0).into();
                let rhs: Scalar = args.remove(0).into();

                ResultValue::Point(lhs * rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Mul, mul, *, ScalarResult);
impl_commutative!(MpcStarkPointResult, Mul, mul, *, ScalarResult);

impl Mul<&MpcScalarResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    // Use the beaver trick as in the scalar case
    fn mul(self, rhs: &MpcScalarResult) -> Self::Output {
        let generator = StarkPoint::generator();
        let (a, b, c) = self.fabric().next_beaver_triple();

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
impl_borrow_variants!(MpcStarkPointResult, Mul, mul, *, MpcScalarResult);
impl_commutative!(MpcStarkPointResult, Mul, mul, *, MpcScalarResult);
