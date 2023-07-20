//! Defines an unauthenticated shared scalar type which forms the basis of the
//! authenticated scalar type

use std::ops::{Add, Mul, Neg, Sub};

use crate::{
    fabric::{MpcFabric, ResultHandle, ResultValue},
    network::NetworkPayload,
    PARTY0,
};

use super::{
    macros::{impl_borrow_variants, impl_commutative},
    mpc_stark_point::{MpcStarkPoint, MpcStarkPointResult},
    scalar::{Scalar, ScalarResult},
    stark_curve::{StarkPoint, StarkPointResult},
};

/// Defines a secret shared type over the `Scalar` field
#[derive(Clone, Debug)]
pub struct MpcScalar {
    /// The underlying value held by the local party
    pub(crate) value: Scalar,
    /// A reference to the underlying fabric that this value is allocated in
    pub(crate) fabric: MpcFabric,
}

/// Defines the result handle type that represents a future result of an `MpcScalar`
pub type MpcScalarResult = ResultHandle<MpcScalar>;
impl MpcScalarResult {
    /// Creates an MPC scalar from a given underlying scalar assumed to be a secret share
    pub fn new_shared(value: ScalarResult) -> ResultHandle<MpcScalar> {
        let fabric_clone = value.fabric.clone();
        value.fabric.new_gate_op(vec![value.id], move |args| {
            // Cast the args
            let value: Scalar = args[0].to_owned().into();
            ResultValue::MpcScalar(MpcScalar {
                value,
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
                    let mpc_value: MpcScalar = args[0].to_owned().into();
                    NetworkPayload::Scalar(mpc_value.value)
                });
            let party1_value: ResultHandle<Scalar> = self.fabric.receive_value();

            (party0_value, party1_value)
        } else {
            let party0_value: ResultHandle<Scalar> = self.fabric.receive_value();
            let party1_value: ResultHandle<Scalar> =
                self.fabric.new_network_op(vec![self.id], |args| {
                    let mpc_value: MpcScalar = args[0].to_owned().into();
                    NetworkPayload::Scalar(mpc_value.value)
                });

            (party0_value, party1_value)
        };

        // Create the new value by combining the additive shares
        &val0 + &val1
    }

    /// Convert the underlying value to a `Scalar`
    pub fn to_scalar(&self) -> ScalarResult {
        self.fabric.new_gate_op(vec![self.id], |mut args| {
            let value: MpcScalar = args.remove(0).into();
            ResultValue::Scalar(value.value)
        })
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
            let lhs: MpcScalar = args[0].to_owned().into();
            if lhs.fabric.party_id() == PARTY0 {
                ResultValue::MpcScalar(MpcScalar {
                    value: lhs.value + rhs,
                    fabric: lhs.fabric,
                })
            } else {
                ResultValue::MpcScalar(lhs)
            }
        })
    }
}
impl_borrow_variants!(MpcScalarResult, Add, add, +, Scalar);
impl_commutative!(MpcScalarResult, Add, add, +, Scalar);

impl Add<&ScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 adds the plaintext value as we do not secret share it
    fn add(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric
            .new_gate_op(vec![self.id, rhs.id], move |mut args| {
                // Cast the args
                let lhs: MpcScalar = args.remove(0).into();
                let rhs: Scalar = args.remove(0).into();

                if lhs.fabric.party_id() == PARTY0 {
                    ResultValue::MpcScalar(MpcScalar {
                        value: lhs.value + rhs,
                        fabric: lhs.fabric,
                    })
                } else {
                    ResultValue::MpcScalar(lhs)
                }
            })
    }
}
impl_borrow_variants!(MpcScalarResult, Add, add, +, ScalarResult);
impl_commutative!(MpcScalarResult, Add, add, +, ScalarResult);

impl Add<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn add(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            // Cast the args
            let lhs: MpcScalar = args[0].to_owned().into();
            let rhs: MpcScalar = args[1].to_owned().into();

            ResultValue::MpcScalar(MpcScalar {
                value: lhs.value + rhs.value,
                fabric: lhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcScalarResult, Add, add, +, MpcScalarResult);

// === Subtraction === //

impl Sub<&Scalar> for &MpcScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            // Cast the args
            let lhs: MpcScalar = args[0].to_owned().into();

            if lhs.fabric.party_id() == PARTY0 {
                ResultValue::MpcScalar(MpcScalar {
                    value: lhs.value - rhs,
                    fabric: lhs.fabric,
                })
            } else {
                ResultValue::MpcScalar(lhs)
            }
        })
    }
}
impl_borrow_variants!(MpcScalarResult, Sub, sub, -, Scalar);

impl Sub<&ScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric
            .new_gate_op(vec![self.id, rhs.id], move |mut args| {
                // Cast the args
                let lhs: MpcScalar = args.remove(0).into();
                let rhs: Scalar = args.remove(0).into();

                if lhs.fabric.party_id() == PARTY0 {
                    ResultValue::MpcScalar(MpcScalar {
                        value: lhs.value - rhs,
                        fabric: lhs.fabric,
                    })
                } else {
                    ResultValue::MpcScalar(lhs)
                }
            })
    }
}
impl_borrow_variants!(MpcScalarResult, Sub, sub, -, ScalarResult);

impl Sub<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn sub(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            // Cast the args
            let lhs: MpcScalar = args[0].to_owned().into();
            let rhs: MpcScalar = args[1].to_owned().into();
            ResultValue::MpcScalar(MpcScalar {
                value: lhs.value - rhs.value,
                fabric: lhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcScalarResult, Sub, sub, -, MpcScalarResult);

// === Negation === //

impl Neg for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn neg(self) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id], |args| {
            // Cast the args
            let lhs: MpcScalar = args[0].to_owned().into();
            ResultValue::MpcScalar(MpcScalar {
                value: -lhs.value,
                fabric: lhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcScalarResult, Neg, neg, -);

// === Multiplication === //

impl Mul<&Scalar> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            // Cast the args
            let lhs: MpcScalar = args[0].to_owned().into();
            ResultValue::MpcScalar(MpcScalar {
                value: lhs.value * rhs,
                fabric: lhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcScalarResult, Mul, mul, *, Scalar);
impl_commutative!(MpcScalarResult, Mul, mul, *, Scalar);

impl Mul<&ScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn mul(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric
            .new_gate_op(vec![self.id, rhs.id], move |mut args| {
                // Cast the args
                let lhs: MpcScalar = args.remove(0).into();
                let rhs: Scalar = args.remove(0).into();

                ResultValue::MpcScalar(MpcScalar {
                    value: lhs.value * rhs,
                    fabric: lhs.fabric,
                })
            })
    }
}
impl_borrow_variants!(MpcScalarResult, Mul, mul, *, ScalarResult);
impl_commutative!(MpcScalarResult, Mul, mul, *, ScalarResult);

/// Use the beaver trick if both values are shared
impl Mul<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn mul(self, rhs: &MpcScalarResult) -> Self::Output {
        // Sample a beaver triplet
        let (a, b, c) = self.fabric.next_beaver_triple();

        // Open the values d = [lhs - a] and e = [rhs - b]
        let masked_lhs = self - &a;
        let masked_rhs = rhs - &b;

        let d_open = masked_lhs.open();
        let e_open = masked_rhs.open();

        // Identity: [x * y] = de + d[b] + e[a] + [c]
        &d_open * &b + &e_open * &a + c + &d_open * &e_open
    }
}
impl_borrow_variants!(MpcScalarResult, Mul, mul, *, MpcScalarResult);

// === Curve Scalar Multiplication === //

impl Mul<&MpcScalarResult> for &StarkPoint {
    type Output = MpcStarkPointResult;

    fn mul(self, rhs: &MpcScalarResult) -> Self::Output {
        let self_owned = *self;
        rhs.fabric.new_gate_op(vec![rhs.id], move |mut args| {
            let rhs: MpcScalar = args.remove(0).into();

            ResultValue::MpcStarkPoint(MpcStarkPoint {
                value: self_owned * rhs.value,
                fabric: rhs.fabric,
            })
        })
    }
}
impl_commutative!(StarkPoint, Mul, mul, *, MpcScalarResult, Output=MpcStarkPointResult);

impl Mul<&MpcScalarResult> for &StarkPointResult {
    type Output = MpcStarkPointResult;

    fn mul(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: StarkPoint = args.remove(0).into();
            let rhs: MpcScalar = args.remove(0).into();

            ResultValue::MpcStarkPoint(MpcStarkPoint {
                value: lhs * rhs.value,
                fabric: rhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(StarkPointResult, Mul, mul, *, MpcScalarResult, Output=MpcStarkPointResult);
impl_commutative!(StarkPointResult, Mul, mul, *, MpcScalarResult, Output=MpcStarkPointResult);
