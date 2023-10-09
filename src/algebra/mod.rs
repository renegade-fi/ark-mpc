//! Defines algebraic MPC types and operations on them

pub mod authenticated_curve;
pub mod authenticated_scalar;
pub mod curve;
pub mod macros;
pub mod mpc_curve;
pub mod mpc_scalar;
pub mod scalar;

/// Helpers useful for testing throughout the `algebra` module
#[cfg(test)]
pub(crate) mod test_helper {
    use std::iter;

    use super::scalar::Scalar;

    use ark_curve25519::EdwardsProjective as Curve25519Projective;
    use ark_ec::CurveGroup;
    use ark_ff::PrimeField;
    use num_bigint::BigUint;
    use rand::thread_rng;

    // -----------
    // | Helpers |
    // -----------

    /// A curve used for testing algebra implementations, set to curve25519
    pub type TestCurve = Curve25519Projective;

    /// Generate a random point, by multiplying the basepoint with a random scalar
    pub fn random_point() -> TestCurve {
        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let point = TestCurve::generator() * scalar;
        point * scalar
    }

    /// Convert a prime field element to a `BigUint`
    pub fn prime_field_to_biguint<F: PrimeField>(val: &F) -> BigUint {
        (*val).into()
    }
}
