//! Defines an unauthenticated shared scalar type which forms the basis of the
//! authenticated scalar type

use std::ops::{Add, Sub};

use crate::{
    fabric::{cast_args, MpcFabric, ResultHandle, ResultValue},
    Visibility, Visible,
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

impl MpcScalar {
    /// Creates a new `MpcScalar` from a `Scalar` value
    ///
    /// The visibility is assumed private
    pub fn new(value: Scalar, fabric: MpcFabric) -> MpcScalarResult {
        let val = Self {
            value,
            visibility: Visibility::Private,
            fabric: fabric.clone(),
        };

        fabric.new_value(ResultValue::MpcScalar(val))
    }
}

/// Defines the result handle type that represents a future result of an `MpcScalar`
pub type MpcScalarResult = ResultHandle<MpcScalar>;

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl Add<&Scalar> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn add(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_op(vec![self.id], move |args| {
            // Cast the args
            let [lhs]: [MpcScalar; 1] = cast_args(args);
            ResultValue::MpcScalar(MpcScalar {
                value: lhs.value + rhs,
                visibility: lhs.visibility,
                fabric: lhs.fabric,
            })
        })
    }
}

impl Add<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn add(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric.new_op(vec![self.id, rhs.id], |args| {
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

    fn sub(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_op(vec![self.id], move |args| {
            // Cast the args
            let [lhs]: [MpcScalar; 1] = cast_args(args);
            ResultValue::MpcScalar(MpcScalar {
                value: lhs.value - rhs,
                visibility: lhs.visibility,
                fabric: lhs.fabric,
            })
        })
    }
}

impl Sub<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn sub(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric.new_op(vec![self.id, rhs.id], |args| {
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
