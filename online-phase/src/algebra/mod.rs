//! Defines algebraic MPC types and operations on them

mod curve;
mod macros;
mod scalar;

mod poly;
pub use poly::*;

pub use curve::*;
pub use scalar::*;

/// Abstracts the process of binary serialization, used for commitments
pub(crate) trait ToBytes {
    /// Serialize the value to bytes
    fn to_bytes(&self) -> Vec<u8>;
}
