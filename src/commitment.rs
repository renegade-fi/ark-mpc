//! Defines Pedersen commitments over the Stark curve used to commit to a value
//! before opening it

use sha3::{Digest, Sha3_256};

use crate::{
    algebra::{
        scalar::{Scalar, ScalarResult},
        stark_curve::{StarkPoint, StarkPointResult},
    },
    fabric::ResultValue,
    random_scalar,
};

/// A handle on the result of a Pedersen commitment, including the committed secret
///
/// Of the form `value * G + blinder * H`
pub(crate) struct PedersenCommitment {
    /// The committed value
    pub(crate) value: Scalar,
    /// The commitment blinder
    pub(crate) blinder: Scalar,
    /// The value of the commitment
    pub(crate) commitment: StarkPoint,
}

impl PedersenCommitment {
    /// Verify that the given commitment is valid
    pub(crate) fn verify(&self) -> bool {
        let generator = StarkPoint::generator();
        let commitment = generator * self.value + generator * self.blinder;

        commitment == self.commitment
    }
}

/// A Pedersen commitment that has been allocated in an MPC computation graph
pub(crate) struct PedersenCommitmentResult {
    /// The committed value
    pub(crate) value: ScalarResult,
    /// The commitment blinder
    pub(crate) blinder: Scalar,
    /// The value of the commitment
    pub(crate) commitment: StarkPointResult,
}

impl PedersenCommitmentResult {
    /// Create a new Pedersen commitment to an underlying value
    pub(crate) fn commit(value: ScalarResult) -> PedersenCommitmentResult {
        // Concretely, we use the curve generator for both `G` and `H` as is done
        // in dalek-cryptography: https://github.com/dalek-cryptography/bulletproofs/blob/main/src/generators.rs#L44-L53
        let blinder = random_scalar();
        let generator = StarkPoint::generator();
        let commitment = generator * &value + generator * blinder;

        PedersenCommitmentResult {
            value,
            blinder,
            commitment,
        }
    }
}

/// A handle on the result of a salted Sha256 hash commitment, including the committed secret
///
/// Of the form `H(salt || value)`
///
/// We use hash commitments to commit to curve points before opening them. There is no straightforward
/// way to adapt Pedersen commitments to curve points, and we do not need the homomorphic properties
/// of a Pedersen commitment
pub(crate) struct HashCommitment {
    /// The committed value
    pub(crate) value: StarkPoint,
    /// The blinder used in the commitment
    pub(crate) blinder: Scalar,
    /// The value of the commitment
    pub(crate) commitment: Scalar,
}

impl HashCommitment {
    /// Verify that the given commitment is valid
    pub(crate) fn verify(&self) -> bool {
        // Create the bytes buffer
        let mut bytes = self.value.to_bytes();
        bytes.append(&mut self.blinder.to_bytes_be());

        // Hash the bytes, squeeze an output, verify that it is equal to the commitment
        let mut hasher = Sha3_256::new();
        hasher.update(bytes);

        let out_bytes = hasher.finalize();
        let out = Scalar::from_be_bytes_mod_order(out_bytes.as_slice());

        out == self.commitment
    }
}

/// A hash commitment that has been allocated in an MPC computation graph
pub(crate) struct HashCommitmentResult {
    /// The committed value
    pub(crate) value: StarkPointResult,
    /// The blinder used in the commitment
    pub(crate) blinder: Scalar,
    /// The value of the commitment
    pub(crate) commitment: ScalarResult,
}

impl HashCommitmentResult {
    /// Create a new hash commitment to an underlying value
    pub(crate) fn commit(value: StarkPointResult) -> HashCommitmentResult {
        let blinder = random_scalar();
        let comm = value.fabric.new_gate_op(vec![value.id], move |mut args| {
            let value: StarkPoint = args.remove(0).into();

            // Create the bytes buffer
            let mut bytes = value.to_bytes();
            bytes.append(&mut blinder.to_bytes_be());

            // Hash the bytes, squeeze an output, verify that it is equal to the commitment
            let mut hasher = Sha3_256::new();
            hasher.update(bytes);

            let out_bytes = hasher.finalize();
            let out = Scalar::from_be_bytes_mod_order(out_bytes.as_slice());

            ResultValue::Scalar(out)
        });

        HashCommitmentResult {
            value,
            blinder,
            commitment: comm,
        }
    }
}
