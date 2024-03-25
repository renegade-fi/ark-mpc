//! Defines Pedersen commitments over the system curve used to commit to a value
//! before opening it

use ark_ec::CurveGroup;
use itertools::Itertools;
use rand::thread_rng;
use sha3::{Digest, Sha3_256};

use crate::{
    algebra::{Scalar, ScalarResult, ToBytes},
    fabric::ResultValue,
    ResultHandle,
};

/// A handle on the result of a salted Sha256 hash commitment, including the
/// committed secret
///
/// Of the form `H(value[0] || value[1] || ... || value[n] || blinder)`
pub(crate) struct HashCommitment<C: CurveGroup, T: From<ResultValue<C>>> {
    /// The committed values
    pub(crate) values: Vec<T>,
    /// The blinder used in the commitment
    pub(crate) blinder: Scalar<C>,
    /// The value of the commitment
    pub(crate) commitment: Scalar<C>,
}

impl<C: CurveGroup, T: From<ResultValue<C>> + ToBytes> HashCommitment<C, T> {
    /// Verify that the given commitment is valid
    pub(crate) fn verify(&self) -> bool {
        // Create the bytes buffer
        let mut bytes = self.values.iter().flat_map(ToBytes::to_bytes).collect_vec();
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
pub(crate) struct HashCommitmentResult<C: CurveGroup, T: From<ResultValue<C>>> {
    /// The committed values
    pub(crate) values: Vec<ResultHandle<C, T>>,
    /// The blinder used in the commitment
    pub(crate) blinder: Scalar<C>,
    /// The value of the commitment
    pub(crate) commitment: ScalarResult<C>,
}

impl<C: CurveGroup, T: From<ResultValue<C>> + ToBytes> HashCommitmentResult<C, T> {
    /// Create a new hash commitment to an underlying value
    pub(crate) fn commit(value: ResultHandle<C, T>) -> HashCommitmentResult<C, T> {
        Self::batch_commit(vec![value])
    }

    /// Create a new hash commitment to a batch of values
    pub(crate) fn batch_commit(values: Vec<ResultHandle<C, T>>) -> HashCommitmentResult<C, T> {
        assert!(!values.is_empty(), "Cannot commit to an empty set of values");
        let fabric = &values[0].fabric;

        let mut rng = thread_rng();
        let blinder = Scalar::random(&mut rng);
        let ids = values.iter().map(|v| v.id()).collect_vec();

        let comm = fabric.new_gate_op(ids, move |args| {
            let values = args.into_iter().map(Into::<T>::into);
            let mut bytes = values.flat_map(|v| v.to_bytes()).collect_vec();

            // Create the bytes buffer
            bytes.append(&mut blinder.to_bytes_be());

            // Hash the bytes, squeeze an output, verify that it is equal to the commitment
            let mut hasher = Sha3_256::new();
            hasher.update(bytes);

            let out_bytes = hasher.finalize();
            let out = Scalar::from_be_bytes_mod_order(out_bytes.as_slice());

            ResultValue::Scalar(out)
        });

        HashCommitmentResult { values, blinder, commitment: comm }
    }
}

#[cfg(test)]
mod test {
    use futures::future;
    use itertools::Itertools;
    use rand::thread_rng;

    use crate::{
        algebra::{CurvePoint, Scalar, ToBytes},
        commitment::{HashCommitment, HashCommitmentResult},
        test_helpers::{execute_mock_mpc, TestCurve},
        ResultValue,
    };

    /// Verify a commitment to a value
    async fn verify_comm<T: From<ResultValue<TestCurve>> + Unpin + ToBytes>(
        comm: HashCommitmentResult<TestCurve, T>,
    ) -> bool {
        let comm_res = HashCommitment {
            blinder: comm.blinder,
            values: future::join_all(comm.values).await,
            commitment: comm.commitment.await,
        };

        comm_res.verify()
    }

    /// Tests committing and verifying a scalar
    #[tokio::test]
    async fn test_scalar_commit() {
        let mut rng = thread_rng();
        let value = Scalar::<TestCurve>::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let allocated_value = fabric.allocate_scalar(value);

            let comm = HashCommitmentResult::commit(allocated_value);
            verify_comm(comm).await
        })
        .await;

        assert!(res)
    }

    /// Tests committing and verifying a scalar batch commitment
    #[tokio::test]
    async fn test_scalar_batch_commit() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let values = (0..N).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let values = values.clone();
            async move {
                let allocated_values = fabric.allocate_scalars(values.clone());

                let comm = HashCommitmentResult::batch_commit(allocated_values);
                verify_comm(comm).await
            }
        })
        .await;

        assert!(res)
    }

    /// Tests committing and verifying a curve point
    #[tokio::test]
    async fn test_point_commit() {
        let mut rng = thread_rng();
        let value = CurvePoint::<TestCurve>::generator() * Scalar::<TestCurve>::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let allocated_value = fabric.allocate_point(value);

            let comm = HashCommitmentResult::commit(allocated_value);
            verify_comm(comm).await
        })
        .await;

        assert!(res)
    }

    /// Tests committing to a batch of curve points
    #[tokio::test]
    async fn test_point_batch_commit() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let values = (0..N)
            .map(|_| CurvePoint::<TestCurve>::generator() * Scalar::<TestCurve>::random(&mut rng))
            .collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let values = values.clone();
            async move {
                let allocated_values = fabric.allocate_points(values.clone());

                let comm = HashCommitmentResult::batch_commit(allocated_values);
                verify_comm(comm).await
            }
        })
        .await;

        assert!(res)
    }

    /// Tests an invalid commitment
    #[tokio::test]
    async fn test_invalid_commit() {
        let mut rng = thread_rng();
        let value = Scalar::<TestCurve>::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let allocated_value = fabric.allocate_scalar(value);

            let comm = HashCommitmentResult::commit(allocated_value);
            let mut comm_res = HashCommitment {
                blinder: comm.blinder,
                values: future::join_all(comm.values).await,
                commitment: comm.commitment.await,
            };

            // Modify the commitment
            comm_res.commitment += Scalar::one();
            !comm_res.verify()
        })
        .await;

        assert!(res)
    }
}
