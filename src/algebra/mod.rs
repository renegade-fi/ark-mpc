//! Defines algebraic MPC types and operations on them

pub mod authenticated_scalar;
pub mod authenticated_stark_point;
pub mod macros;
pub mod mpc_scalar;
pub mod mpc_stark_point;
pub mod scalar;
pub mod stark_curve;

/// Helpers useful for testing throughout the `algebra` module
#[cfg(test)]
pub(crate) mod test_helper {
    use std::iter;

    use crate::random_scalar;

    use super::stark_curve::StarkPoint;

    use ark_ec::CurveGroup;
    use ark_ff::PrimeField;
    use num_bigint::BigUint;
    use starknet::core::types::FieldElement as StarknetFelt;
    use starknet_curve::{AffinePoint, ProjectivePoint};

    // -----------
    // | Helpers |
    // -----------

    /// Generate a random point, by multiplying the basepoint with a random scalar
    pub fn random_point() -> StarkPoint {
        let scalar = random_scalar();
        let point = StarkPoint::generator() * scalar;
        point * scalar
    }

    /// Convert a starknet felt to a BigUint
    pub fn starknet_felt_to_biguint(felt: &StarknetFelt) -> BigUint {
        BigUint::from_bytes_be(&felt.to_bytes_be())
    }

    /// Convert a `BigUint` to a starknet felt
    pub fn biguint_to_starknet_felt(biguint: &BigUint) -> StarknetFelt {
        // Pad the bytes up to 32 by prepending zeros
        let bytes = biguint.to_bytes_be();
        let padded_bytes = iter::repeat(0u8)
            .take(32 - bytes.len())
            .chain(bytes.iter().cloned())
            .collect::<Vec<_>>();

        StarknetFelt::from_bytes_be(&padded_bytes.try_into().unwrap()).unwrap()
    }

    /// Convert a prime field element to a `BigUint`
    pub fn prime_field_to_biguint<F: PrimeField>(val: &F) -> BigUint {
        (*val).into()
    }

    /// Convert a `Scalar` to a `StarknetFelt`
    pub fn prime_field_to_starknet_felt<F: PrimeField>(scalar: &F) -> StarknetFelt {
        biguint_to_starknet_felt(&prime_field_to_biguint(scalar))
    }

    /// Convert a point in the arkworks representation to a point in the starknet representation
    pub fn arkworks_point_to_starknet(point: &StarkPoint) -> ProjectivePoint {
        let affine = point.0.into_affine();
        let x = prime_field_to_starknet_felt(&affine.x);
        let y = prime_field_to_starknet_felt(&affine.y);

        ProjectivePoint::from_affine_point(&AffinePoint {
            x,
            y,
            infinity: false,
        })
    }

    /// Multiply a point in the starknet-rs `ProjectivePoint` representation with a scalar
    ///
    /// Multiplication is only implemented for a point and `&[bool]`, so this method essentially
    /// provides the bit decomposition  
    pub fn starknet_rs_scalar_mul(
        scalar: &StarknetFelt,
        point: &ProjectivePoint,
    ) -> ProjectivePoint {
        let bits = scalar.to_bits_le();
        point * &bits
    }

    /// Compare scalars from the two curve implementations
    pub fn compare_scalars<F: PrimeField>(s1: &F, s2: &StarknetFelt) -> bool {
        let s1_biguint = prime_field_to_biguint(s1);
        let s2_biguint = starknet_felt_to_biguint(s2);

        s1_biguint == s2_biguint
    }

    /// Compare curve points between the two implementation
    pub fn compare_points(p1: &StarkPoint, p2: &ProjectivePoint) -> bool {
        // Convert the points to affine coordinates
        let p1_affine = p1.0.into_affine();
        let x_1 = p1_affine.x;
        let y_1 = p1_affine.y;

        let z_inv = p2.z.invert().unwrap();
        let x_2 = p2.x * z_inv;
        let y_2 = p2.y * z_inv;

        compare_scalars(&x_1, &x_2) && compare_scalars(&y_1, &y_2)
    }
}
