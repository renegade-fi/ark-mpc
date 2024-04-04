//! FHE primitives exported from MP-SPDZ
//!
//! Implements the BGV cryptosystem

use ark_ec::CurveGroup;
use ark_mpc::algebra::Scalar;
use cxx::UniquePtr;

use crate::ffi::{bigint, bigint_from_be_bytes, bigint_to_be_bytes};

pub mod ciphertext;
pub mod keys;
pub mod params;
pub mod plaintext;

/// A helper method to convert a `Scalar` to a `bigint`
pub fn scalar_to_ffi_bigint<C: CurveGroup>(x: Scalar<C>) -> UniquePtr<bigint> {
    let mut bytes = x.to_bytes_be();
    unsafe { bigint_from_be_bytes(bytes.as_mut_ptr(), bytes.len()) }
}

/// A helper method to convert a `bigint` to a `Scalar`
///
/// Reduces modulo the scalar field's modulus
pub fn ffi_bigint_to_scalar<C: CurveGroup>(x: &bigint) -> Scalar<C> {
    Scalar::from_be_bytes_mod_order(&bigint_to_be_bytes(x))
}
