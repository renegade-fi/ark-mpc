//! Scalar type arithmetic with shared authenticated, shared non-authenticated,
//! and plaintext types
#![allow(clippy::module_inception)]

mod authenticated_scalar;
mod scalar;
mod share;

use ark_ec::CurveGroup;
use ark_ff::Field;
pub use authenticated_scalar::*;
pub use scalar::*;
pub use share::*;

#[cfg(feature = "test_helpers")]
pub use authenticated_scalar::test_helpers as scalar_test_helpers;

/// Convert to a field element
///
/// This trait is used downstream to accept `Field`s or `Scalar`s
/// in an interface. The trait must be defined in this crate to avoid
/// conflicting implementations checks by an upstream crate
pub trait FieldWrapper<F: Field> {
    /// Convert a reference to a field element
    #[allow(clippy::wrong_self_convention)]
    fn into_field(&self) -> F;

    /// Convert from a field element
    fn from_field(f: &F) -> Self;
}

impl<F: Field> FieldWrapper<F> for F {
    fn into_field(&self) -> F {
        *self
    }

    fn from_field(f: &F) -> Self {
        *f
    }
}

impl<C: CurveGroup> FieldWrapper<C::ScalarField> for Scalar<C> {
    fn into_field(&self) -> C::ScalarField {
        self.inner()
    }

    fn from_field(f: &C::ScalarField) -> Self {
        Self::new(*f)
    }
}
