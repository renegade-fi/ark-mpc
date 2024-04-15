//! Defines curve types for shared authenticated, shared unauthenticated, and
//! plaintext curve points
#![allow(clippy::module_inception)]

mod authenticated_curve;
mod curve;
mod share;

pub use authenticated_curve::*;
pub use curve::*;
pub use share::*;

#[cfg(feature = "test_helpers")]
pub use authenticated_curve::test_helpers as curve_test_helpers;
