//! Defines the abstractions over the result of an MPC operation, this can be a network
//! operation, a simple local computation, or a more complex operation like a
//! Beaver multiplication

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

/// An identifier for a result
pub type ResultId = usize;

/// The result of an MPC operation
pub struct OpResult {
    /// The ID of the result's output
    pub id: ResultId,
    /// The result's value
    pub value: ResultValue,
}

/// The value of a result
pub enum ResultValue {
    /// A scalar value
    Scalar(Scalar),
    /// A point on the curve
    Point(RistrettoPoint),
}
