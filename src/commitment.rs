//! Defines Pedersen commitments over the system curve used to commit to a value
//! before opening it

use ark_ec::CurveGroup;
use rand::thread_rng;
use sha3::{Digest, Sha3_256};

use crate::{
    algebra::{CurvePoint, CurvePointResult, Scalar, ScalarResult},
    fabric::ResultValue,
};

/// A handle on the result of a Pedersen commitment, including the committed
/// secret
///
/// Of the form `value * G + blinder * H`
pub(crate) struct PedersenCommitment<C: CurveGroup> {
    /// The committed value
    pub(crate) value: Scalar<C>,
    /// The commitment blinder
    pub(crate) blinder: Scalar<C>,
    /// The value of the commitment
    pub(crate) commitment: CurvePoint<C>,
}

impl<C: CurveGroup> PedersenCommitment<C> {
    /// Verify that the given commitment is valid
    pub(crate) fn verify(&self) -> bool {
        let generator = CurvePoint::generator();
        let commitment = generator * self.value + generator * self.blinder;

        commitment == self.commitment
    }
}

/// A Pedersen commitment that has been allocated in an MPC computation graph
pub(crate) struct PedersenCommitmentResult<C: CurveGroup> {
    /// The committed value
    pub(crate) value: ScalarResult<C>,
    /// The commitment blinder
    pub(crate) blinder: Scalar<C>,
    /// The value of the commitment
    pub(crate) commitment: CurvePointResult<C>,
}

impl<C: CurveGroup> PedersenCommitmentResult<C> {
    /// Create a new Pedersen commitment to an underlying value
    pub(crate) fn commit(value: ScalarResult<C>) -> PedersenCommitmentResult<C> {
        // Concretely, we use the curve generator for both `G` and `H` as is done
        // in dalek-cryptography: https://github.com/dalek-cryptography/bulletproofs/blob/main/src/generators.rs#L44-L53
        let mut rng = thread_rng();
        let blinder = Scalar::random(&mut rng);
        let generator = CurvePoint::generator();
        let commitment = generator * &value + generator * blinder;

        PedersenCommitmentResult {
            value,
            blinder,
            commitment,
        }
    }
}

/// A handle on the result of a salted Sha256 hash commitment, including the
/// committed secret
///
/// Of the form `H(salt || value)`
///
/// We use hash commitments to commit to curve points before opening them. There
/// is no straightforward way to adapt Pedersen commitments to curve points, and
/// we do not need the homomorphic properties of a Pedersen commitment
pub(crate) struct HashCommitment<C: CurveGroup> {
    /// The committed value
    pub(crate) value: CurvePoint<C>,
    /// The blinder used in the commitment
    pub(crate) blinder: Scalar<C>,
    /// The value of the commitment
    pub(crate) commitment: Scalar<C>,
}

impl<C: CurveGroup> HashCommitment<C> {
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
pub(crate) struct HashCommitmentResult<C: CurveGroup> {
    /// The committed value
    pub(crate) value: CurvePointResult<C>,
    /// The blinder used in the commitment
    pub(crate) blinder: Scalar<C>,
    /// The value of the commitment
    pub(crate) commitment: ScalarResult<C>,
}

impl<C: CurveGroup> HashCommitmentResult<C> {
    /// Create a new hash commitment to an underlying value
    pub(crate) fn commit(value: CurvePointResult<C>) -> HashCommitmentResult<C> {
        let mut rng = thread_rng();
        let blinder = Scalar::random(&mut rng);
        let comm = value.fabric.new_gate_op(vec![value.id], move |mut args| {
            let value: CurvePoint<C> = args.remove(0).into();

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
