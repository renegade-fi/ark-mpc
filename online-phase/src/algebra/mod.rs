//! Defines algebraic MPC types and operations on them

#[cfg(feature = "curve")]
mod curve;
#[cfg(feature = "curve")]
pub use curve::*;

#[cfg(feature = "poly")]
mod poly;
#[cfg(feature = "poly")]
pub use poly::*;

#[cfg(feature = "scalar")]
mod scalar;
#[cfg(feature = "scalar")]
pub use scalar::*;

mod macros;

/// Abstracts the process of binary serialization, used for commitments
pub(crate) trait ToBytes {
    /// Serialize the value to bytes
    fn to_bytes(&self) -> Vec<u8>;
}
