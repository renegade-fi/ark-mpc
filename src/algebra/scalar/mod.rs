//! Scalar type arithmetic with shared authenticated, shared non-authenticated, and plaintext types
#![allow(clippy::module_inception)]

mod authenticated_scalar;
mod mpc_scalar;
mod scalar;

pub use authenticated_scalar::*;
pub use mpc_scalar::*;
pub use scalar::*;

#[cfg(feature = "test_helpers")]
pub use authenticated_scalar::test_helpers as scalar_test_helpers;
