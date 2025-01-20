//! Scalar type arithmetic with shared authenticated, shared non-authenticated,
//! and plaintext types
#![allow(clippy::module_inception)]

mod scalar;

#[cfg(feature = "fabric")]
mod scalar_result;
#[cfg(feature = "fabric")]
pub use scalar_result::*;

#[cfg(feature = "fabric")]
mod authenticated_scalar;
#[cfg(feature = "test_helpers")]
pub use authenticated_scalar::test_helpers as scalar_test_helpers;
#[cfg(feature = "fabric")]
pub use authenticated_scalar::*;

#[cfg(feature = "fabric")]
mod share;
#[cfg(feature = "fabric")]
pub use share::*;

#[cfg(feature = "curve")]
use ark_ec::CurveGroup;

use ark_ff::Field;
pub use scalar::*;

/// Convert to a field element
///
/// This trait is used downstream to accept `Field`s or `Scalar`s
/// in an interface. The trait must be defined in this crate to avoid
/// conflicting implementations checks by an upstream crate
#[cfg(feature = "curve")]
pub trait FieldWrapper<F: Field> {
    /// Convert a reference to a field element
    #[allow(clippy::wrong_self_convention)]
    fn into_field(&self) -> F;

    /// Convert from a field element
    fn from_field(f: &F) -> Self;
}

#[cfg(feature = "curve")]
impl<F: Field> FieldWrapper<F> for F {
    fn into_field(&self) -> F {
        *self
    }

    fn from_field(f: &F) -> Self {
        *f
    }
}

#[cfg(feature = "curve")]
impl<C: CurveGroup> FieldWrapper<C::ScalarField> for Scalar<C> {
    fn into_field(&self) -> C::ScalarField {
        self.inner()
    }

    fn from_field(f: &C::ScalarField) -> Self {
        Self::new(*f)
    }
}
