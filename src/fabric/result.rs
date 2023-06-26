//! Defines the abstractions over the result of an MPC operation, this can be a network
//! operation, a simple local computation, or a more complex operation like a
//! Beaver multiplication

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use super::{FabricInner, MpcFabric};

/// An identifier for a result
pub type ResultId = usize;

/// The result of an MPC operation
#[derive(Debug)]
pub struct OpResult {
    /// The ID of the result's output
    pub id: ResultId,
    /// The result's value
    pub value: ResultValue,
    /// The underlying fabric that the result is allocated within
    pub fabric: FabricInner,
}

/// The value of a result
#[derive(Debug)]
pub enum ResultValue {
    /// A scalar value
    Scalars(Vec<Scalar>),
    /// A point on the curve
    Points(Vec<RistrettoPoint>),
}
