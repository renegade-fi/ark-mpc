//! Defines an MPC fabric for the protocol
//!
//! The fabric essentially acts as a dependency injection layer. That is, the
//! MpcFabric creates and manages dependencies needed to allocate network
//! values. This provides a cleaner interface for consumers of the library; i.e.
//! clients do not have to hold onto references of the network layer or the
//! offline phase implementation to allocate values.

mod executor;
mod network_sender;
mod result;

use ark_ec::CurveGroup;
pub use executor::ExecutorSizeHints;
#[cfg(not(feature = "benchmarks"))]
use executor::{single_threaded::SerialExecutor, ExecutorMessage};
#[cfg(feature = "benchmarks")]
pub use executor::{single_threaded::SerialExecutor, ExecutorMessage, GrowableBuffer};
pub use result::{ResultHandle, ResultId, ResultValue};

use futures::executor::block_on;
use tracing::log;

use crossbeam::queue::SegQueue;
use kanal::Sender as KanalSender;
use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tokio::sync::broadcast::{self, Sender as BroadcastSender};

use itertools::Itertools;

use crate::{
    algebra::{
        AuthenticatedPointResult, AuthenticatedScalarResult, CurvePoint, CurvePointResult,
        PointShare, Scalar, ScalarResult, ScalarShare,
    },
    network::{MpcNetwork, NetworkOutbound, NetworkPayload, PartyId},
    offline_prep::PreprocessingPhase,
    PARTY0,
};

#[cfg(feature = "multithreaded_executor")]
use self::executor::multi_threaded::ParallelExecutor;
use self::{
    executor::ExecutorJobQueue,
    network_sender::NetworkSender,
    result::{OpResult, ResultWaiter},
};

/// The result id that is hardcoded to zero
const RESULT_ZERO: ResultId = 0;
/// The result id that is hardcoded to one
const RESULT_ONE: ResultId = 1;
/// The result id that is hardcoded to the curve identity point
const RESULT_IDENTITY: ResultId = 2;
/// The result id that is hardcoded to a shared zero
const RESULT_SHARED_ZERO: ResultId = 3;
/// The result id that is hardcoded to a shared one
const RESULT_SHARED_ONE: ResultId = 4;
/// The result id that is hardcoded to a shared curve identity point
const RESULT_SHARED_IDENTITY: ResultId = 5;

/// The number of constant results allocated in the fabric, i.e. those defined
/// above
const N_CONSTANT_RESULTS: usize = 6;

/// A type alias for the identifier used for a gate
pub type OperationId = usize;

/// An operation within the network, describes the arguments and function to
/// evaluate once the arguments are ready
///
/// `N` represents the number of results that this operation outputs
#[derive(Clone)]
pub struct Operation<C: CurveGroup> {
    /// Identifier of the result that this operation emits
    id: OperationId,
    /// The result ID of the first result in the outputs
    result_id: ResultId,
    /// The number of outputs this operation produces
    output_arity: usize,
    /// The number of arguments that are still in-flight for this operation
    inflight_args: usize,
    /// The IDs of the inputs to this operation
    args: Vec<ResultId>,
    /// The type of the operation
    op_type: OperationType<C>,
}

impl<C: CurveGroup> Operation<C> {
    /// Get the result IDs for an operation
    pub fn result_ids(&self) -> Vec<ResultId> {
        (self.result_id..self.result_id + self.output_arity).collect_vec()
    }
}

impl<C: CurveGroup> Debug for Operation<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Operation {}", self.id)
    }
}

/// A type alias for the iter type used in gates
type BoxedResultIter<'a, C> = Box<dyn Iterator<Item = ResultValue<C>> + 'a>;

/// Defines the different types of operations available in the computation graph
pub enum OperationType<C: CurveGroup> {
    /// A gate operation; may be evaluated locally given its ready inputs
    Gate {
        /// The function to apply to the inputs
        #[allow(clippy::type_complexity)]
        function: Box<dyn for<'a> FnOnce(BoxedResultIter<'a, C>) -> ResultValue<C> + Send + Sync>,
    },
    /// A gate operation that has output arity greater than one
    ///
    /// We separate this out to avoid vector allocation for result values of
    /// arity one
    GateBatch {
        /// The function to apply to the inputs
        #[allow(clippy::type_complexity)]
        function: Box<dyn FnOnce(BoxedResultIter<C>) -> Vec<ResultValue<C>> + Send + Sync>,
    },
    /// A network operation, requires that a value be sent over the network
    Network {
        /// The function to apply to the inputs to derive a Network payload
        #[allow(clippy::type_complexity)]
        function: Box<dyn FnOnce(BoxedResultIter<C>) -> NetworkPayload<C> + Send + Sync>,
    },
}

/// A clone implementation, never concretely called but used as a Marker type to
/// allow pre-allocating buffer space for `Operation`s
impl<C: CurveGroup> Clone for OperationType<C> {
    fn clone(&self) -> Self {
        panic!("cannot clone `OperationType`")
    }
}

impl<C: CurveGroup> Debug for OperationType<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            OperationType::Gate { .. } => write!(f, "Gate"),
            OperationType::GateBatch { .. } => write!(f, "GateBatch"),
            OperationType::Network { .. } => write!(f, "Network"),
        }
    }
}

/// A fabric for the MPC protocol, defines a dependency injection layer that
/// dynamically schedules circuit gate evaluations onto the network to be
/// executed
///
/// The fabric does not block on gate evaluations, but instead returns a handle
/// to a future result that may be polled to obtain the materialized result.
/// This allows the application layer to continue using the fabric, scheduling
/// more gates to be evaluated and maximally exploiting gate-level parallelism
/// within the circuit
#[derive(Clone)]
pub struct MpcFabric<C: CurveGroup> {
    /// The inner fabric
    #[cfg(not(feature = "benchmarks"))]
    inner: Arc<FabricInner<C>>,
    /// The inner fabric, accessible publicly for benchmark mocking
    #[cfg(feature = "benchmarks")]
    pub inner: Arc<FabricInner<C>>,
    /// The local party's share of the global MAC key
    ///
    /// The parties collectively hold an additive sharing of the global key
    #[cfg(not(feature = "benchmarks"))]
    mac_key: Scalar<C>,
    /// The MAC key, accessible publicly for benchmark mocking
    #[cfg(feature = "benchmarks")]
    pub mac_key: Scalar<C>,
    /// The channel on which shutdown messages are sent to blocking workers
    #[cfg(not(feature = "benchmarks"))]
    shutdown: BroadcastSender<()>,
    /// The shutdown channel, made publicly available for benchmark mocking
    #[cfg(feature = "benchmarks")]
    pub shutdown: BroadcastSender<()>,
}

impl<C: CurveGroup> Debug for MpcFabric<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "MpcFabric")
    }
}

/// The inner component of the fabric, allows the constructor to allocate
/// executor and network sender objects at the same level as the fabric
#[derive(Clone)]
pub struct FabricInner<C: CurveGroup> {
    /// The ID of the local party in the MPC execution
    party_id: u64,
    /// The next identifier to assign to a result
    next_result_id: Arc<AtomicUsize>,
    /// The next identifier to assign to an operation
    next_op_id: Arc<AtomicUsize>,
    /// A sender to the executor
    execution_queue: ExecutorJobQueue<C>,
    /// The underlying queue to the network
    outbound_queue: KanalSender<NetworkOutbound<C>>,
    /// The underlying shared randomness source
    offline_phase: Arc<Mutex<Box<dyn PreprocessingPhase<C>>>>,
}

impl<C: CurveGroup> Debug for FabricInner<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "FabricInner")
    }
}

impl<C: CurveGroup> FabricInner<C> {
    /// Constructor
    pub fn new<S: 'static + PreprocessingPhase<C>>(
        party_id: u64,
        mac_key: Scalar<C>,
        execution_queue: ExecutorJobQueue<C>,
        outbound_queue: KanalSender<NetworkOutbound<C>>,
        offline_phase: S,
    ) -> Self {
        // Allocate a zero and a one as well as the curve identity in the fabric to
        // begin, for convenience
        let zero = ResultValue::Scalar(Scalar::zero());
        let one = ResultValue::Scalar(Scalar::one());
        let identity = ResultValue::Point(CurvePoint::identity());

        let shared_zero =
            ResultValue::ScalarShare(ScalarShare::new(Scalar::zero(), Scalar::zero()));
        let shared_one =
            ResultValue::ScalarShare(ScalarShare::new(Scalar::from(party_id), mac_key));
        let shared_identity = ResultValue::PointShare(PointShare::new(
            CurvePoint::identity(),
            CurvePoint::identity(),
        ));

        for initial_result in vec![
            OpResult { id: RESULT_ZERO, value: zero },
            OpResult { id: RESULT_ONE, value: one },
            OpResult { id: RESULT_IDENTITY, value: identity },
            OpResult { id: RESULT_SHARED_ZERO, value: shared_zero },
            OpResult { id: RESULT_SHARED_ONE, value: shared_one },
            OpResult { id: RESULT_SHARED_IDENTITY, value: shared_identity },
        ]
        .into_iter()
        {
            execution_queue.push(ExecutorMessage::Result(initial_result));
        }

        let next_result_id = Arc::new(AtomicUsize::new(N_CONSTANT_RESULTS));
        let next_op_id = Arc::new(AtomicUsize::new(0));

        Self {
            party_id,
            next_result_id,
            next_op_id,
            execution_queue,
            outbound_queue,
            offline_phase: Arc::new(Mutex::new(Box::new(offline_phase))),
        }
    }

    /// Register a waiter on a result    
    pub(crate) fn register_waiter(&self, waiter: ResultWaiter<C>) {
        self.execution_queue.push(ExecutorMessage::NewWaiter(waiter));
    }

    /// Shutdown the inner fabric, by sending a shutdown message to the executor
    pub(crate) fn shutdown(&self) {
        self.execution_queue.push(ExecutorMessage::Shutdown)
    }

    /// -----------
    /// | Getters |
    /// -----------

    /// Increment the operation counter and return the existing value
    fn new_result_id(&self) -> ResultId {
        self.next_result_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Increment the operation counter by a given amount
    fn new_result_id_batch(&self, n: usize) -> Vec<ResultId> {
        let start = self.next_result_id.fetch_add(n, Ordering::Relaxed);
        (start..start + n).collect_vec()
    }

    /// Increment the operation counter and return the existing value
    fn new_op_id(&self) -> OperationId {
        self.next_op_id.fetch_add(1, Ordering::Acquire)
    }

    /// Get the hardcoded zero value in the fabric
    pub(crate) fn zero(&self) -> ResultId {
        RESULT_ZERO
    }

    /// Get the hardcoded one value in the fabric
    pub(crate) fn one(&self) -> ResultId {
        RESULT_ONE
    }

    /// Get the hardcoded curve identity value in the fabric
    pub(crate) fn curve_identity(&self) -> ResultId {
        RESULT_IDENTITY
    }

    /// Get the hardcoded shared zero value in the fabric
    pub(crate) fn shared_zero(&self) -> ResultId {
        RESULT_SHARED_ZERO
    }

    /// Get the hardcoded shared one value in the fabric
    pub(crate) fn shared_one(&self) -> ResultId {
        RESULT_SHARED_ONE
    }

    /// Get the hardcoded shared curve identity value in the fabric
    pub(crate) fn shared_curve_identity(&self) -> ResultId {
        RESULT_SHARED_IDENTITY
    }

    // ------------------------
    // | Low Level Allocation |
    // ------------------------

    /// Allocate a new plaintext value in the fabric
    pub(crate) fn allocate_value(&self, value: ResultValue<C>) -> ResultId {
        // Forward the result to the executor
        let id = self.new_result_id();
        self.execution_queue.push(ExecutorMessage::Result(OpResult { id, value }));

        id
    }

    /// Allocate a batch of values in the fabric
    pub(crate) fn allocate_values(&self, values: Vec<ResultValue<C>>) -> Vec<ResultId> {
        // Forward the results to the executor
        let n = values.len();
        let ids = self.new_result_id_batch(n);

        let mut results = Vec::with_capacity(n);
        for (id, value) in ids.iter().zip(values.into_iter()) {
            results.push(OpResult { id: *id, value });
        }

        self.execution_queue.push(ExecutorMessage::ResultBatch(results));

        ids
    }

    /// Receive a value from a network operation initiated by a peer
    ///
    /// The peer will already send the value with the corresponding ID, so all
    /// that is needed is to allocate a slot in the result buffer for the
    /// receipt
    pub(crate) fn receive_value(&self) -> ResultId {
        self.new_result_id()
    }

    // --------------
    // | Operations |
    // --------------

    /// Allocate a new in-flight gate operation in the fabric
    pub(crate) fn new_op(
        &self,
        args: Vec<ResultId>,
        output_arity: usize,
        op_type: OperationType<C>,
    ) -> Vec<ResultId> {
        if matches!(op_type, OperationType::Gate { .. }) {
            assert_eq!(output_arity, 1, "gate operations must have arity 1");
        }

        // Allocate IDs for the results
        assert!(output_arity > 0, "output arity must be greater than 0");
        let ids = self.new_result_id_batch(output_arity);

        // Build the operation
        let op = Operation {
            id: self.new_op_id(),
            result_id: ids[0],
            output_arity,
            args,
            inflight_args: 0,
            op_type,
        };

        // Forward the op to the executor
        self.execution_queue.push(ExecutorMessage::Op(op));
        ids
    }
}

impl<C: CurveGroup> MpcFabric<C> {
    /// Constructor
    pub fn new<N: 'static + MpcNetwork<C>, S: 'static + PreprocessingPhase<C>>(
        network: N,
        offline_phase: S,
    ) -> Self {
        Self::new_with_size_hint(ExecutorSizeHints::default(), network, offline_phase)
    }

    /// Constructor that takes an additional size hint, indicating how much
    /// buffer space the fabric should allocate for results. The size is
    /// given in number of gates
    pub fn new_with_size_hint<N: 'static + MpcNetwork<C>, S: 'static + PreprocessingPhase<C>>(
        size_hints: ExecutorSizeHints,
        network: N,
        offline_phase: S,
    ) -> Self {
        // Build an executor queue and a fabric around it
        let executor_queue = Arc::new(SegQueue::new());
        let self_ = Self::new_with_executor(network, offline_phase, executor_queue.clone());

        // Spawn the executor
        let outbound_queue = self_.inner.outbound_queue.clone();
        #[cfg(not(feature = "multithreaded_executor"))]
        let executor = SerialExecutor::new(size_hints, executor_queue, outbound_queue);
        #[cfg(feature = "multithreaded_executor")]
        let executor = ParallelExecutor::new(size_hints, executor_queue, outbound_queue);
        // tokio::task::spawn_blocking(move || executor.run());
        std::thread::spawn(move || executor.run());

        self_
    }

    /// Constructor that takes an additional size hint as well as a queue for
    /// the executor
    pub fn new_with_executor<N: 'static + MpcNetwork<C>, S: 'static + PreprocessingPhase<C>>(
        network: N,
        offline_phase: S,
        executor_queue: ExecutorJobQueue<C>,
    ) -> Self {
        // Build communication primitives
        let (outbound_sender, outbound_receiver) = kanal::unbounded_async();
        let (shutdown_sender, shutdown_receiver) = broadcast::channel(1 /* capacity */);

        // Build a fabric
        let party_id = network.party_id();
        let mac_key = offline_phase.get_mac_key_share();
        let fabric = FabricInner::new(
            party_id,
            mac_key,
            executor_queue.clone(),
            outbound_sender.to_sync(),
            offline_phase,
        );

        // Start a network sender and operator executor
        let network_sender = NetworkSender::new(
            outbound_receiver,
            executor_queue.clone(),
            network,
            shutdown_receiver,
        );
        tokio::task::spawn_blocking(move || block_on(network_sender.run()));

        // Create the fabric and fill in the MAC key after
        Self { inner: Arc::new(fabric.clone()), shutdown: shutdown_sender, mac_key }
    }

    /// Get the party ID of the local party
    pub fn party_id(&self) -> PartyId {
        self.inner.party_id
    }

    /// Get a copy of the local party's mac key share
    pub fn mac_key(&self) -> Scalar<C> {
        self.mac_key
    }

    /// Get the total number of ops that have been allocated in the fabric
    pub fn num_gates(&self) -> usize {
        self.inner.next_op_id.load(Ordering::Acquire)
    }

    /// Shutdown the fabric and the threads it has spawned
    pub fn shutdown(self) {
        log::debug!("shutting down fabric");
        self.inner.shutdown();
        self.shutdown.send(()).expect("error sending shutdown signal");
    }

    /// Register a waiter on a result
    pub fn register_waiter(&self, waiter: ResultWaiter<C>) {
        self.inner.register_waiter(waiter);
    }

    // ------------------------
    // | Constants Allocation |
    // ------------------------

    /// Get the hardcoded zero wire as a raw `ScalarResult`
    pub fn zero(&self) -> ScalarResult<C> {
        ResultHandle::new(self.inner.zero(), self.clone())
    }

    /// Get the hardcoded zero wire as an `AuthenticatedScalarResult`
    ///
    /// Both parties hold the share 0 directly in this case
    pub fn zero_authenticated(&self) -> AuthenticatedScalarResult<C> {
        ResultHandle::new(self.inner.shared_zero(), self.clone())
    }

    /// Get a batch of references to the zero wire as an
    /// `AuthenticatedScalarResult`
    pub fn zeros_authenticated(&self, n: usize) -> Vec<AuthenticatedScalarResult<C>> {
        vec![self.zero_authenticated(); n]
    }

    /// Get the hardcoded one wire as a raw `ScalarResult`
    pub fn one(&self) -> ScalarResult<C> {
        ResultHandle::new(self.inner.one(), self.clone())
    }

    /// Get the hardcoded one wire as an `AuthenticatedScalarResult`
    ///
    /// Party 0 holds the value zero and party 1 holds the value one
    pub fn one_authenticated(&self) -> AuthenticatedScalarResult<C> {
        ResultHandle::new(self.inner.shared_one(), self.clone())
    }

    /// Get a batch of references to the one wire as an
    /// `AuthenticatedScalarResult`
    pub fn ones_authenticated(&self, n: usize) -> Vec<AuthenticatedScalarResult<C>> {
        let val = self.one_authenticated();
        (0..n).map(|_| val.clone()).collect_vec()
    }

    /// Get the hardcoded curve identity wire as a raw `CurvePointResult`
    pub fn curve_identity(&self) -> CurvePointResult<C> {
        ResultHandle::new(self.inner.curve_identity(), self.clone())
    }

    /// Get the hardcoded curve identity wire as an `AuthenticatedPointResult`
    ///
    /// Both parties hold the identity point directly in this case
    pub fn curve_identity_authenticated(&self) -> AuthenticatedPointResult<C> {
        ResultHandle::new(self.inner.shared_curve_identity(), self.clone())
    }

    // -------------------
    // | Wire Allocation |
    // -------------------

    /// Share a `Scalar` value with the counterparty
    pub fn share_scalar<T: Into<Scalar<C>>>(
        &self,
        val: T,
        sender: PartyId,
    ) -> AuthenticatedScalarResult<C> {
        // Sample an input mask from the offline phase
        let mut offline = self.inner.offline_phase.lock().expect("offline phase poisoned");
        let (masked_val, shared_mask) = if self.party_id() == sender {
            let (mask, mask_share) = offline.next_local_input_mask();
            let masked = Into::<Scalar<C>>::into(val) - mask;
            let masked_val = self.share_plaintext(masked, sender);

            (masked_val, mask_share)
        } else {
            let mask_share = offline.next_counterparty_input_mask();
            let masked_val = self.share_plaintext(Scalar::zero(), sender);

            (masked_val, mask_share)
        };

        // Unmask the value in the MPC circuit
        self.allocate_scalar_share(shared_mask) + masked_val
    }

    /// Share a batch of `Scalar` values with the counterparty
    pub fn batch_share_scalar<T: Into<Scalar<C>>>(
        &self,
        vals: Vec<T>,
        sender: PartyId,
    ) -> Vec<AuthenticatedScalarResult<C>> {
        let n = vals.len();
        let mut offline = self.inner.offline_phase.lock().expect("offline phase poisoned");
        let (masked_vals, mask_shares) = if self.party_id() == sender {
            let (masks, mask_shares) = offline.next_local_input_mask_batch(n);
            let masked = vals.into_iter().zip(masks).map(|(val, mask)| val.into() - mask).collect();
            let masked_vals = self.batch_share_plaintext(masked, sender);

            (masked_vals, mask_shares)
        } else {
            let mask_shares = offline.next_counterparty_input_mask_batch(n);
            let masked_vals = self.batch_share_plaintext(vec![Scalar::zero(); n], sender);

            (masked_vals, mask_shares)
        };

        let shares = self.allocate_scalar_shares(mask_shares);
        AuthenticatedScalarResult::batch_add_public(&shares, &masked_vals)
    }

    /// Share a `CurvePoint` value with the counterparty
    pub fn share_point(&self, val: CurvePoint<C>, sender: PartyId) -> AuthenticatedPointResult<C> {
        let mut offline = self.inner.offline_phase.lock().expect("offline phase poisoned");
        let (masked_point, mask_share) = if self.party_id() == sender {
            let (mask, mask_share) = offline.next_local_input_mask();
            let masked = val - mask * CurvePoint::generator();
            let masked_point = self.share_plaintext(masked, sender);

            (masked_point, mask_share)
        } else {
            let mask_share = offline.next_counterparty_input_mask();
            let masked_point = self.share_plaintext(CurvePoint::generator(), sender);

            (masked_point, mask_share)
        };

        self.allocate_scalar_share(mask_share) * CurvePoint::generator() + masked_point
    }

    /// Share a batch of `CurvePoint`s with the counterparty
    pub fn batch_share_point(
        &self,
        vals: Vec<CurvePoint<C>>,
        sender: PartyId,
    ) -> Vec<AuthenticatedPointResult<C>> {
        let n = vals.len();
        let mut offline = self.inner.offline_phase.lock().expect("offline phase poisoned");
        let (masked_vals, mask_shares) = if self.party_id() == sender {
            let (masks, mask_shares) = offline.next_local_input_mask_batch(n);
            let mask_times_gen =
                masks.into_iter().map(|mask| mask * CurvePoint::generator()).collect_vec();
            let masked =
                vals.into_iter().zip(mask_times_gen).map(|(val, mask)| val - mask).collect();
            let masked_vals = self.batch_share_plaintext(masked, sender);

            (masked_vals, mask_shares)
        } else {
            let mask_shares = offline.next_counterparty_input_mask_batch(n);
            let masked_vals = self.batch_share_plaintext(vec![CurvePoint::generator(); n], sender);

            (masked_vals, mask_shares)
        };

        let shares = self.allocate_scalar_shares(mask_shares);
        let masks = AuthenticatedPointResult::batch_mul_generator(&shares);

        AuthenticatedPointResult::batch_add_public(&masks, &masked_vals)
    }

    /// Allocate a public value in the fabric
    pub fn allocate_scalar<T: Into<Scalar<C>>>(&self, value: T) -> ScalarResult<C> {
        let id = self.inner.allocate_value(ResultValue::Scalar(value.into()));
        ResultHandle::new(id, self.clone())
    }

    /// Allocate a batch of scalars in the fabric
    pub fn allocate_scalars<T: Into<Scalar<C>>>(&self, values: Vec<T>) -> Vec<ScalarResult<C>> {
        let result_values =
            values.into_iter().map(|value| ResultValue::Scalar(value.into())).collect_vec();

        self.inner
            .allocate_values(result_values)
            .into_iter()
            .map(|id| ResultHandle::new(id, self.clone()))
            .collect_vec()
    }

    /// Allocate a share in the fabric
    pub fn allocate_scalar_share(&self, share: ScalarShare<C>) -> AuthenticatedScalarResult<C> {
        let id = self.inner.allocate_value(ResultValue::ScalarShare(share));
        ResultHandle::new(id, self.clone())
    }

    /// Allocate a batch of shares in the fabric
    pub fn allocate_scalar_shares(
        &self,
        shares: Vec<ScalarShare<C>>,
    ) -> Vec<AuthenticatedScalarResult<C>> {
        let result_values = shares.into_iter().map(ResultValue::ScalarShare).collect_vec();
        self.inner
            .allocate_values(result_values)
            .into_iter()
            .map(|id| ResultHandle::new(id, self.clone()))
            .collect_vec()
    }

    /// Allocate a point secret share in the fabric
    pub fn allocate_point_share(&self, share: PointShare<C>) -> AuthenticatedPointResult<C> {
        let id = self.inner.allocate_value(ResultValue::PointShare(share));
        ResultHandle::new(id, self.clone())
    }

    /// Allocate a batch of point secret shares in the fabric
    pub fn allocate_point_shares(
        &self,
        shares: Vec<PointShare<C>>,
    ) -> Vec<AuthenticatedPointResult<C>> {
        let result_values = shares.into_iter().map(ResultValue::PointShare).collect_vec();
        self.inner
            .allocate_values(result_values)
            .into_iter()
            .map(|id| ResultHandle::new(id, self.clone()))
            .collect_vec()
    }

    /// Allocate a public curve point in the fabric
    pub fn allocate_point(&self, value: CurvePoint<C>) -> CurvePointResult<C> {
        let id = self.inner.allocate_value(ResultValue::Point(value));
        ResultHandle::new(id, self.clone())
    }

    /// Allocate a batch of points in the fabric
    pub fn allocate_points(&self, values: Vec<CurvePoint<C>>) -> Vec<CurvePointResult<C>> {
        values.into_iter().map(|value| self.allocate_point(value)).collect_vec()
    }

    /// Send a value to the peer, placing the identity in the local result
    /// buffer at the send ID
    pub fn send_value<T: From<ResultValue<C>> + Into<NetworkPayload<C>>>(
        &self,
        value: ResultHandle<C, T>,
    ) -> ResultHandle<C, T> {
        self.new_network_op(vec![value.id], |mut args| args.next().unwrap().into())
    }

    /// Send a batch of values to the counterparty
    pub fn send_values<T>(&self, values: &[ResultHandle<C, T>]) -> ResultHandle<C, Vec<T>>
    where
        T: From<ResultValue<C>>,
        Vec<T>: Into<NetworkPayload<C>> + From<ResultValue<C>>,
    {
        let ids = values.iter().map(|v| v.id).collect_vec();
        self.new_network_op(ids, |args| {
            let payload: Vec<T> = args.into_iter().map(|val| val.into()).collect();
            payload.into()
        })
    }

    /// Receive a value from the peer
    pub fn receive_value<T: From<ResultValue<C>>>(&self) -> ResultHandle<C, T> {
        let id = self.inner.receive_value();
        ResultHandle::new(id, self.clone())
    }

    /// Exchange a value with the peer, i.e. send then receive or receive then
    /// send based on the party ID
    ///
    /// Returns a handle to the received value, which will be different for
    /// different parties
    pub fn exchange_value<T: From<ResultValue<C>> + Into<NetworkPayload<C>>>(
        &self,
        value: ResultHandle<C, T>,
    ) -> ResultHandle<C, T> {
        if self.party_id() == PARTY0 {
            // Party 0 sends first then receives
            self.send_value(value);
            self.receive_value()
        } else {
            // Party 1 receives first then sends
            let handle = self.receive_value();
            self.send_value(value);
            handle
        }
    }

    /// Exchange a batch of values with the peer, i.e. send then receive or
    /// receive then send based on party ID
    pub fn exchange_values<T>(&self, values: &[ResultHandle<C, T>]) -> ResultHandle<C, Vec<T>>
    where
        T: From<ResultValue<C>>,
        Vec<T>: From<ResultValue<C>> + Into<NetworkPayload<C>>,
    {
        if self.party_id() == PARTY0 {
            self.send_values(values);
            self.receive_value()
        } else {
            let handle = self.receive_value();
            self.send_values(values);
            handle
        }
    }

    /// Share a public value with the counterparty
    pub fn share_plaintext<T>(&self, value: T, sender: PartyId) -> ResultHandle<C, T>
    where
        T: 'static + From<ResultValue<C>> + Into<NetworkPayload<C>> + Send + Sync,
    {
        if self.party_id() == sender {
            self.new_network_op(vec![], move |_args| value.into())
        } else {
            self.receive_value()
        }
    }

    /// Share a batch of public values with the counterparty
    pub fn batch_share_plaintext<T>(
        &self,
        values: Vec<T>,
        sender: PartyId,
    ) -> Vec<ResultHandle<C, T>>
    where
        T: 'static + From<ResultValue<C>> + Into<ResultValue<C>> + Send + Sync,
        Vec<T>: Into<NetworkPayload<C>> + From<ResultValue<C>>,
    {
        let n = values.len();
        let res = self.share_plaintext(values, sender);

        // Split the vec into a result of values
        self.new_batch_gate_op(vec![res.id()], n, |mut args| {
            let values: Vec<T> = args.next().unwrap().into();
            values.into_iter().map(Into::into).collect_vec()
        })
    }

    // -------------------
    // | Gate Definition |
    // -------------------

    /// Construct a new gate operation in the fabric, i.e. one that can be
    /// evaluated immediate given its inputs
    pub fn new_gate_op<F, T>(&self, args: Vec<ResultId>, function: F) -> ResultHandle<C, T>
    where
        F: 'static + FnOnce(BoxedResultIter<C>) -> ResultValue<C> + Send + Sync,
        T: From<ResultValue<C>>,
    {
        let function = Box::new(function);
        let id = self.inner.new_op(
            args,
            1, // output_arity
            OperationType::Gate { function },
        )[0];
        ResultHandle::new(id, self.clone())
    }

    /// Construct a new batch gate operation in the fabric, i.e. one that can be
    /// evaluated to return an array of results
    ///
    /// The array must be sized so that the fabric knows how many results to
    /// allocate buffer space for ahead of execution
    pub fn new_batch_gate_op<F, T>(
        &self,
        args: Vec<ResultId>,
        output_arity: usize,
        function: F,
    ) -> Vec<ResultHandle<C, T>>
    where
        F: 'static + FnOnce(BoxedResultIter<C>) -> Vec<ResultValue<C>> + Send + Sync,
        T: From<ResultValue<C>>,
    {
        let function = Box::new(function);
        let ids = self.inner.new_op(args, output_arity, OperationType::GateBatch { function });
        ids.into_iter().map(|id| ResultHandle::new(id, self.clone())).collect_vec()
    }

    /// Construct a new network operation in the fabric, i.e. one that requires
    /// a value to be sent over the channel
    pub fn new_network_op<F, T>(&self, args: Vec<ResultId>, function: F) -> ResultHandle<C, T>
    where
        F: 'static + FnOnce(BoxedResultIter<C>) -> NetworkPayload<C> + Send + Sync,
        T: From<ResultValue<C>>,
    {
        let function = Box::new(function);
        let id = self.inner.new_op(
            args,
            1, // output_arity
            OperationType::Network { function },
        )[0];
        ResultHandle::new(id, self.clone())
    }

    // -----------------
    // | Offline Phase |
    // -----------------

    /// Sample the next beaver triplet with MACs from the beaver source
    pub fn next_triple(
        &self,
    ) -> (AuthenticatedScalarResult<C>, AuthenticatedScalarResult<C>, AuthenticatedScalarResult<C>)
    {
        let (a, b, c) =
            self.inner.offline_phase.lock().expect("beaver source poisoned").next_triplet();

        let mut abc = self.allocate_scalar_shares(vec![a, b, c]);
        let c_val = abc.pop().unwrap();
        let b_val = abc.pop().unwrap();
        let a_val = abc.pop().unwrap();

        (a_val, b_val, c_val)
    }

    /// Sample the next batch of beaver triples as `AuthenticatedScalar`s
    #[allow(clippy::type_complexity)]
    pub fn next_triple_batch(
        &self,
        n: usize,
    ) -> (
        Vec<AuthenticatedScalarResult<C>>,
        Vec<AuthenticatedScalarResult<C>>,
        Vec<AuthenticatedScalarResult<C>>,
    ) {
        let (a_vals, b_vals, c_vals) =
            self.inner.offline_phase.lock().expect("beaver source poisoned").next_triplet_batch(n);

        // Concatenate and allocate all the values
        let vals = a_vals.into_iter().chain(b_vals).chain(c_vals).collect_vec();
        let mut allocated_vals = self.allocate_scalar_shares(vals);

        // Splice into a, b, c values
        let c_vals = allocated_vals.split_off(2 * n);
        let b_vals = allocated_vals.split_off(n);
        let a_vals = allocated_vals;

        (a_vals, b_vals, c_vals)
    }

    /// Sample a batch of random shared values from the offline phase and
    /// allocate them as `AuthenticatedScalars`
    pub fn random_shared_scalars(&self, n: usize) -> Vec<AuthenticatedScalarResult<C>> {
        let values_raw = self
            .inner
            .offline_phase
            .lock()
            .expect("offline phase poisoned")
            .next_shared_value_batch(n);

        self.allocate_scalar_shares(values_raw)
    }

    /// Sample a pair of values that are multiplicative inverses of one another
    pub fn random_inverse_pair(
        &self,
    ) -> (AuthenticatedScalarResult<C>, AuthenticatedScalarResult<C>) {
        let (l, r) = self.inner.offline_phase.lock().unwrap().next_shared_inverse_pair();
        let mut lr = self.allocate_scalar_shares(vec![l, r]);
        let r = lr.pop().unwrap();
        let l = lr.pop().unwrap();

        (l, r)
    }

    /// Sample a batch of values that are multiplicative inverses of one another
    pub fn random_inverse_pairs(
        &self,
        n: usize,
    ) -> (Vec<AuthenticatedScalarResult<C>>, Vec<AuthenticatedScalarResult<C>>) {
        let (left, right) =
            self.inner.offline_phase.lock().unwrap().next_shared_inverse_pair_batch(n);

        let left_right = left.into_iter().chain(right).collect_vec();
        let mut allocated_left_right = self.allocate_scalar_shares(left_right);

        // Split left and right
        let right = allocated_left_right.split_off(n);
        let left = allocated_left_right;

        (left, right)
    }

    /// Sample a random shared bit from the offline phase
    pub fn random_shared_bit(&self) -> AuthenticatedScalarResult<C> {
        let bit =
            self.inner.offline_phase.lock().expect("offline phase poisoned").next_shared_bit();

        self.allocate_scalar_share(bit)
    }

    /// Sample a batch of random shared bits from the offline phase
    pub fn random_shared_bits(&self, n: usize) -> Vec<AuthenticatedScalarResult<C>> {
        let bits = self
            .inner
            .offline_phase
            .lock()
            .expect("offline phase poisoned")
            .next_shared_bit_batch(n);

        self.allocate_scalar_shares(bits)
    }
}

#[cfg(test)]
mod test {
    use crate::{algebra::Scalar, test_helpers::execute_mock_mpc, PARTY0};

    /// Tests a linear circuit of very large depth
    #[tokio::test]
    async fn test_deep_circuit() {
        const DEPTH: usize = 1_000_000;
        let (res, _) = execute_mock_mpc(|fabric| async move {
            // Perform an operation that takes time, so that further operations will enqueue
            // behind it
            let mut res = fabric.share_plaintext(Scalar::from(1u8), PARTY0);
            for _ in 0..DEPTH {
                res = res + fabric.one();
            }

            res.await
        })
        .await;

        assert_eq!(res, Scalar::from(DEPTH + 1));
    }
}
