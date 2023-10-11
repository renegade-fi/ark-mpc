//! Defines algebraic MPC types and operations on them

mod curve;
mod macros;
mod scalar;

#[cfg(feature = "poly")]
mod poly;
#[cfg(feature = "poly")]
pub use poly::*;

pub use curve::*;
pub use scalar::*;
