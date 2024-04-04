//! Defines rust FFI bindings for the LowGear implementation in MP-SPDZ
//! written in c++
//!
//! This library is intended to be a thin wrapper around the MP-SPDZ library,
//! and to internalize build and link procedure with the foreign ABI

pub mod ffi;
pub mod fhe;

#[cfg(test)]
mod test_helpers {
    /// The curve group to use for testing
    pub type TestCurve = ark_bn254::G1Projective;
}
#[cfg(test)]
pub(crate) use test_helpers::*;
