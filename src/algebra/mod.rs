//! Defines algebraic MPC types and operations on them

use std::mem::size_of;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{
    de::Error as DeserializeError, ser::Error as SerializeError, Deserialize, Deserializer,
    Serializer,
};

use self::stark_curve::{Scalar, StarkPoint};

pub mod stark_curve;

// -----------
// | Helpers |
// -----------

/// Serialize a `Scalar` type by calling out to the Arkworks implementation
pub fn serialize_scalar<S: Serializer>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error> {
    let mut out: Vec<u8> = Vec::with_capacity(size_of::<Scalar>());
    scalar
        .serialize_compressed(&mut out)
        .map_err(|err| SerializeError::custom(err.to_string()))?;

    serializer.serialize_bytes(&out)
}

/// Deserialize a `Scalar` by calling out to the Arkworks implementation
pub fn deserialize_scalar<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Scalar, D::Error> {
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    Scalar::deserialize_compressed(&bytes[..])
        .map_err(|err| DeserializeError::custom(err.to_string()))
}

/// Serialize a `StarkPoint` type by calling out to the Arkworks implementation
pub fn serialize_point<S: Serializer>(
    point: &StarkPoint,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut out: Vec<u8> = Vec::with_capacity(size_of::<stark_curve::StarkPoint>());
    point
        .serialize_uncompressed(&mut out)
        .map_err(|err| SerializeError::custom(err.to_string()))?;

    serializer.serialize_bytes(&out)
}

/// Deserialize a `StarkPoint` by calling out to the Arkworks implementation
pub fn deserialize_point<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<StarkPoint, D::Error> {
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    StarkPoint::deserialize_uncompressed(&bytes[..])
        .map_err(|err| DeserializeError::custom(err.to_string()))
}

/// Helpers useful for testing throughout the `algebra` module
#[cfg(test)]
pub(crate) mod test_helper {
    use super::stark_curve::{scalar_to_biguint, Scalar, StarknetCurveConfig};

    use ark_ec::{
        short_weierstrass::{Projective, SWCurveConfig},
        CurveGroup,
    };
    use ark_ff::PrimeField;
    use num_bigint::BigUint;
    use starknet::core::types::FieldElement as StarknetFelt;
    use starknet_curve::{AffinePoint, ProjectivePoint};

    // -----------
    // | Helpers |
    // -----------

    /// Generate a random scalar
    pub fn random_scalar() -> Scalar {
        let bytes: [u8; 32] = rand::random();
        Scalar::from_be_bytes_mod_order(&bytes)
    }

    /// Generate a random point, by multiplying the basepoint with a random scalar
    pub fn random_point() -> Projective<StarknetCurveConfig> {
        let scalar = random_scalar();
        let point = StarknetCurveConfig::GENERATOR * scalar;
        point * scalar
    }

    /// Convert a starknet felt to a BigUint
    pub fn starknet_felt_to_biguint(felt: &StarknetFelt) -> BigUint {
        BigUint::from_bytes_be(&felt.to_bytes_be())
    }

    /// Convert a `BigUint` to a starknet felt
    pub fn biguint_to_starknet_felt(biguint: &BigUint) -> StarknetFelt {
        let bytes = biguint.to_bytes_be();
        StarknetFelt::from_bytes_be(&bytes.try_into().unwrap()).unwrap()
    }

    /// Convert a `Scalar` to a `StarknetFelt`
    pub fn scalar_to_starknet_felt<F: PrimeField>(scalar: &F) -> StarknetFelt {
        biguint_to_starknet_felt(&scalar_to_biguint(scalar))
    }

    /// Convert a point in the arkworks representation to a point in the starknet representation
    pub fn arkworks_point_to_starknet(point: &Projective<StarknetCurveConfig>) -> ProjectivePoint {
        let affine = point.into_affine();
        let x = scalar_to_starknet_felt(&affine.x);
        let y = scalar_to_starknet_felt(&affine.y);

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
        let s1_biguint = scalar_to_biguint(s1);
        let s2_biguint = starknet_felt_to_biguint(s2);

        s1_biguint == s2_biguint
    }

    /// Compare curve points between the two implementation
    pub fn compare_points(p1: &Projective<StarknetCurveConfig>, p2: &ProjectivePoint) -> bool {
        // Convert the points to affine coordinates
        let p1_affine = p1.into_affine();
        let x_1 = p1_affine.x;
        let y_1 = p1_affine.y;

        let z_inv = p2.z.invert().unwrap();
        let x_2 = p2.x * z_inv;
        let y_2 = p2.y * z_inv;

        compare_scalars(&x_1, &x_2) && compare_scalars(&y_1, &y_2)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use crate::algebra::{deserialize_point, serialize_point};

    use super::{
        deserialize_scalar, serialize_scalar,
        test_helper::{random_point, random_scalar},
    };

    /// Test (de)serialization of a `Scalar`
    #[test]
    fn test_serde_scalar() {
        let scalar = random_scalar();

        // Serialize
        let mut out_buf = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut out_buf);
        serialize_scalar(&scalar, &mut serializer).unwrap();

        // Deserialize
        let mut deserializer = serde_json::Deserializer::from_slice(&out_buf);
        let out = deserialize_scalar(&mut deserializer).unwrap();

        assert_eq!(scalar, out);
    }

    /// Test (de)serialization of a `StarkPoint`
    #[test]
    fn test_serde_point() {
        let point = random_point();

        // Serialize
        let mut out_buf = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut out_buf);
        serialize_point(&point, &mut serializer).unwrap();

        // Deserialize
        let mut deserializer = serde_json::Deserializer::from_slice(&out_buf);
        let out = deserialize_point(&mut deserializer).unwrap();

        assert_eq!(point, out);
    }
}
