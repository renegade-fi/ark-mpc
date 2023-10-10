//! Defines algebraic MPC types and operations on them

pub mod authenticated_curve;
pub mod authenticated_scalar;
pub mod curve;
pub mod macros;
pub mod mpc_curve;
pub mod mpc_scalar;
pub mod scalar;

/// Helpers useful for testing throughout the `algebra` module
#[cfg(any(test, feature = "test_helpers"))]
pub(crate) mod test_helper {
    use ark_curve25519::EdwardsProjective as Curve25519Projective;

    /// A curve used for testing algebra implementations, set to curve25519
    pub type TestCurve = Curve25519Projective;
}
