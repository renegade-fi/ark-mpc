//! Defines Pedersen commitments over the Stark curve used to commit to a value
//! before opening it

use ark_ec::Group;

use crate::{
    algebra::stark_curve::{Scalar, ScalarResult, StarkPoint, StarkPointResult},
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
        let commitment = &generator * &value + generator * blinder;

        PedersenCommitmentResult {
            value,
            blinder,
            commitment,
        }
    }
}
