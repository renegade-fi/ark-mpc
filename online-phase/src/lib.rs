#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![allow(ambiguous_glob_reexports)]
#![feature(inherent_associated_types)]
#![feature(stmt_expr_attributes)]

//! Defines an MPC implementation over the a generic Arkworks curve that allows
//! for out-of-order execution of the underlying MPC circuit

use algebra::{CurvePoint, Scalar};
use ark_ec::CurveGroup;

use rand::thread_rng;

pub mod algebra;
pub mod commitment;
pub mod error;
pub(crate) mod fabric;
pub mod gadgets;
pub mod offline_prep;
#[cfg(feature = "benchmarks")]
pub use fabric::*;
#[cfg(not(feature = "benchmarks"))]
pub use fabric::{ExecutorSizeHints, FabricInner, MpcFabric, ResultHandle, ResultId, ResultValue};
pub mod network;

// -------------
// | Constants |
// -------------

/// The first party
pub const PARTY0: u64 = 0;
/// The second party
pub const PARTY1: u64 = 1;

/// Generate a random curve point by multiplying a random scalar with the
/// curve group generator
pub fn random_point<C: CurveGroup>() -> CurvePoint<C> {
    let mut rng = thread_rng();
    CurvePoint::generator() * Scalar::random(&mut rng)
}

// --------------------
// | Crate-wide Types |
// --------------------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    //! Defines test helpers for use in unit and integration tests, as well as
    //! benchmarks
    use ark_ec::CurveGroup;
    use futures::{future, Future};

    use crate::{
        algebra::{AuthenticatedPointResult, AuthenticatedScalarResult, CurvePoint, Scalar},
        fabric::ExecutorSizeHints,
        network::{MockNetwork, NoRecvNetwork, UnboundedDuplexStream},
        offline_prep::{PartyIDBeaverSource, PreprocessingPhase},
        MpcFabric, PARTY0, PARTY1,
    };

    use ark_bn254::G1Projective as Bn254Projective;

    /// A curve used for testing algebra implementations, set to bn254
    pub type TestCurve = Bn254Projective;

    /// Open and await a batch of scalars
    pub async fn open_await_all<C: CurveGroup>(
        scalars: &[AuthenticatedScalarResult<C>],
    ) -> Vec<Scalar<C>>
    where
        C::ScalarField: Unpin,
    {
        let results = AuthenticatedScalarResult::open_authenticated_batch(scalars);

        future::join_all(results).await.into_iter().collect::<Result<Vec<_>, _>>().unwrap()
    }

    /// Open and await a batch of curve points
    pub async fn open_await_all_points<C: CurveGroup>(
        points: &[AuthenticatedPointResult<C>],
    ) -> Vec<CurvePoint<C>>
    where
        C::ScalarField: Unpin,
    {
        let results = AuthenticatedPointResult::open_authenticated_batch(points);
        future::join_all(results).await.into_iter().collect::<Result<Vec<_>, _>>().unwrap()
    }

    /// Create a mock fabric
    pub fn mock_fabric() -> MpcFabric<TestCurve> {
        let network = NoRecvNetwork::default();
        let beaver_source = PartyIDBeaverSource::default();

        MpcFabric::new(network, beaver_source)
    }

    /// Run a mock MPC connected by a duplex stream as the mock network
    ///
    /// This will spawn two tasks to execute either side of the MPC
    ///
    /// Returns the outputs of both parties
    pub async fn execute_mock_mpc<T, S, F>(f: F) -> (T, T)
    where
        T: Send + 'static,
        S: Future<Output = T> + Send + 'static,
        F: FnMut(MpcFabric<TestCurve>) -> S,
    {
        execute_mock_mpc_with_beaver_source(
            f,
            PartyIDBeaverSource::new(PARTY0),
            PartyIDBeaverSource::new(PARTY1),
        )
        .await
    }

    /// Execute a mock MPC with a given size hint
    pub async fn execute_mock_mpc_with_size_hint<T, S, F>(
        f: F,
        size_hint: ExecutorSizeHints,
    ) -> (T, T)
    where
        T: Send + 'static,
        S: Future<Output = T> + Send + 'static,
        F: FnMut(MpcFabric<TestCurve>) -> S,
    {
        // Build a duplex stream to broker communication between the two parties
        let (party0_stream, party1_stream) = UnboundedDuplexStream::new_duplex_pair();
        let party0_fabric = MpcFabric::new_with_size_hint(
            size_hint,
            MockNetwork::new(PARTY0, party0_stream),
            PartyIDBeaverSource::new(PARTY0),
        );
        let party1_fabric = MpcFabric::new_with_size_hint(
            size_hint,
            MockNetwork::new(PARTY1, party1_stream),
            PartyIDBeaverSource::new(PARTY1),
        );

        execute_mock_mpc_with_fabrics(f, party0_fabric, party1_fabric).await
    }

    /// Execute a mock MPC by specifying a beaver source for party 0 and 1
    pub async fn execute_mock_mpc_with_beaver_source<B, T, S, F>(
        f: F,
        party0_beaver: B,
        party1_beaver: B,
    ) -> (T, T)
    where
        B: 'static + PreprocessingPhase<TestCurve>,
        T: Send + 'static,
        S: Future<Output = T> + Send + 'static,
        F: FnMut(MpcFabric<TestCurve>) -> S,
    {
        // Build a duplex stream to broker communication between the two parties
        let (party0_stream, party1_stream) = UnboundedDuplexStream::new_duplex_pair();
        let party0_fabric = MpcFabric::new(MockNetwork::new(PARTY0, party0_stream), party0_beaver);
        let party1_fabric = MpcFabric::new(MockNetwork::new(PARTY1, party1_stream), party1_beaver);

        execute_mock_mpc_with_fabrics(f, party0_fabric, party1_fabric).await
    }

    /// Execute a mock in the given fabrics
    async fn execute_mock_mpc_with_fabrics<T, S, F>(
        mut f: F,
        party0_fabric: MpcFabric<TestCurve>,
        party1_fabric: MpcFabric<TestCurve>,
    ) -> (T, T)
    where
        T: Send + 'static,
        S: Future<Output = T> + Send + 'static,
        F: FnMut(MpcFabric<TestCurve>) -> S,
    {
        // Spawn two tasks to execute the MPC
        let fabric0 = party0_fabric.clone();
        let fabric1 = party1_fabric.clone();
        let party0_task = tokio::spawn(f(fabric0));
        let party1_task = tokio::spawn(f(fabric1));

        let party0_output = party0_task.await.unwrap();
        let party1_output = party1_task.await.unwrap();

        // Shutdown the fabrics
        party0_fabric.shutdown();
        party1_fabric.shutdown();

        (party0_output, party1_output)
    }
}
