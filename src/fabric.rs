//! Defines an MPC fabric for the protocol
//!
//! The fabric essentially acts as a dependency injection layer. That is, the
//! MpcFabric creates and manages dependencies needed to allocate network
//! values. This provides a cleaner interface for consumers of the library; i.e.
//! clients do not have to hold onto references of the network layer or the
//! beaver sources to allocate values.

mod executor;
mod network_sender;
mod result;

use ark_ec::CurveGroup;
#[cfg(feature = "benchmarks")]
pub use executor::{Executor, ExecutorMessage};
#[cfg(not(feature = "benchmarks"))]
use executor::{Executor, ExecutorMessage};
use rand::thread_rng;
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
        AuthenticatedPointResult, AuthenticatedScalarResult, BatchCurvePointResult,
        BatchScalarResult, CurvePoint, CurvePointResult, MpcPointResult, MpcScalarResult, Scalar,
        ScalarResult,
    },
    beaver::SharedValueSource,
    network::{MpcNetwork, NetworkOutbound, NetworkPayload, PartyId},
    PARTY0,
};

use self::{
    network_sender::NetworkSender,
    result::{OpResult, ResultWaiter},
};

/// The result id that is hardcoded to zero
const RESULT_ZERO: ResultId = 0;
/// The result id that is hardcoded to one
const RESULT_ONE: ResultId = 1;
/// The result id that is hardcoded to the curve identity point
const RESULT_IDENTITY: ResultId = 2;

/// The number of constant results allocated in the fabric, i.e. those defined
/// above
const N_CONSTANT_RESULTS: usize = 3;

/// The default size hint to give the fabric for buffer pre-allocation
const DEFAULT_SIZE_HINT: usize = 50_000;

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
    ///
    /// We wrap in a reference counting structure to avoid recursive type issues
    #[cfg(not(feature = "benchmarks"))]
    mac_key: Option<Arc<MpcScalarResult<C>>>,
    /// The MAC key, accessible publicly for benchmark mocking
    #[cfg(feature = "benchmarks")]
    pub mac_key: Option<Arc<MpcScalarResult<C>>>,
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
    execution_queue: Arc<SegQueue<ExecutorMessage<C>>>,
    /// The underlying queue to the network
    outbound_queue: KanalSender<NetworkOutbound<C>>,
    /// The underlying shared randomness source
    beaver_source: Arc<Mutex<Box<dyn SharedValueSource<C>>>>,
}

impl<C: CurveGroup> Debug for FabricInner<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "FabricInner")
    }
}

impl<C: CurveGroup> FabricInner<C> {
    /// Constructor
    pub fn new<S: 'static + SharedValueSource<C>>(
        party_id: u64,
        execution_queue: Arc<SegQueue<ExecutorMessage<C>>>,
        outbound_queue: KanalSender<NetworkOutbound<C>>,
        beaver_source: S,
    ) -> Self {
        // Allocate a zero and a one as well as the curve identity in the fabric to
        // begin, for convenience
        let zero = ResultValue::Scalar(Scalar::zero());
        let one = ResultValue::Scalar(Scalar::one());
        let identity = ResultValue::Point(CurvePoint::identity());

        for initial_result in vec![
            OpResult { id: RESULT_ZERO, value: zero },
            OpResult { id: RESULT_ONE, value: one },
            OpResult { id: RESULT_IDENTITY, value: identity },
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
            beaver_source: Arc::new(Mutex::new(Box::new(beaver_source))),
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

    /// Allocate a secret shared value in the network
    pub(crate) fn allocate_shared_value(
        &self,
        my_share: ResultValue<C>,
        their_share: ResultValue<C>,
    ) -> ResultId {
        // Forward the local party's share to the executor
        let id = self.new_result_id();
        self.execution_queue.push(ExecutorMessage::Result(OpResult { id, value: my_share }));

        // Send the counterparty their share
        if let Err(e) =
            self.outbound_queue.send(NetworkOutbound { result_id: id, payload: their_share.into() })
        {
            log::error!("error sending share to counterparty: {e:?}");
        }

        id
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
    pub fn new<N: 'static + MpcNetwork<C>, S: 'static + SharedValueSource<C>>(
        network: N,
        beaver_source: S,
    ) -> Self {
        Self::new_with_size_hint(DEFAULT_SIZE_HINT, network, beaver_source)
    }

    /// Constructor that takes an additional size hint, indicating how much
    /// buffer space the fabric should allocate for results. The size is
    /// given in number of gates
    pub fn new_with_size_hint<N: 'static + MpcNetwork<C>, S: 'static + SharedValueSource<C>>(
        size_hint: usize,
        network: N,
        beaver_source: S,
    ) -> Self {
        // Build communication primitives
        let execution_queue = Arc::new(SegQueue::new());

        let (outbound_sender, outbound_receiver) = kanal::unbounded_async();
        let (shutdown_sender, shutdown_receiver) = broadcast::channel(1 /* capacity */);

        // Build a fabric
        let fabric = FabricInner::new(
            network.party_id(),
            execution_queue.clone(),
            outbound_sender.to_sync(),
            beaver_source,
        );

        // Start a network sender and operator executor
        let network_sender = NetworkSender::new(
            outbound_receiver,
            execution_queue.clone(),
            network,
            shutdown_receiver,
        );
        tokio::task::spawn_blocking(move || block_on(network_sender.run()));

        let executor = Executor::new(size_hint, execution_queue, fabric.clone());
        tokio::task::spawn_blocking(move || executor.run());

        // Create the fabric and fill in the MAC key after
        let mut self_ =
            Self { inner: Arc::new(fabric.clone()), shutdown: shutdown_sender, mac_key: None };

        // Sample a MAC key from the pre-shared values in the beaver source
        let mac_key_id = fabric.allocate_value(ResultValue::Scalar(
            fabric.beaver_source.lock().expect("beaver source poisoned").next_shared_value(),
        ));
        let mac_key = MpcScalarResult::new_shared(ResultHandle::new(mac_key_id, self_.clone()));

        // Set the MAC key
        self_.mac_key.replace(Arc::new(mac_key));

        self_
    }

    /// Get the party ID of the local party
    pub fn party_id(&self) -> PartyId {
        self.inner.party_id
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

    /// Immutably borrow the MAC key
    pub(crate) fn borrow_mac_key(&self) -> &MpcScalarResult<C> {
        // Unwrap is safe, the constructor sets the MAC key
        self.mac_key.as_ref().unwrap()
    }

    // ------------------------
    // | Constants Allocation |
    // ------------------------

    /// Get the hardcoded zero wire as a raw `ScalarResult`
    pub fn zero(&self) -> ScalarResult<C> {
        ResultHandle::new(self.inner.zero(), self.clone())
    }

    /// Get the shared zero value as an `MpcScalarResult`
    fn zero_shared(&self) -> MpcScalarResult<C> {
        MpcScalarResult::new_shared(self.zero())
    }

    /// Get the hardcoded zero wire as an `AuthenticatedScalarResult`
    ///
    /// Both parties hold the share 0 directly in this case
    pub fn zero_authenticated(&self) -> AuthenticatedScalarResult<C> {
        let zero_value = self.zero();
        let share_value = self.zero_shared();
        let mac_value = self.zero_shared();

        AuthenticatedScalarResult {
            share: share_value,
            mac: mac_value,
            public_modifier: zero_value,
        }
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

    /// Get the hardcoded shared one wire as an `MpcScalarResult`
    fn one_shared(&self) -> MpcScalarResult<C> {
        MpcScalarResult::new_shared(self.one())
    }

    /// Get the hardcoded one wire as an `AuthenticatedScalarResult`
    ///
    /// Party 0 holds the value zero and party 1 holds the value one
    pub fn one_authenticated(&self) -> AuthenticatedScalarResult<C> {
        if self.party_id() == PARTY0 {
            let zero_value = self.zero();
            let share_value = self.zero_shared();
            let mac_value = self.zero_shared();

            AuthenticatedScalarResult {
                share: share_value,
                mac: mac_value,
                public_modifier: zero_value,
            }
        } else {
            let zero_value = self.zero();
            let share_value = self.one_shared();
            let mac_value = self.borrow_mac_key().clone();

            AuthenticatedScalarResult {
                share: share_value,
                mac: mac_value,
                public_modifier: zero_value,
            }
        }
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

    /// Get the hardcoded shared curve identity wire as an `MpcPointResult`
    fn curve_identity_shared(&self) -> MpcPointResult<C> {
        MpcPointResult::new_shared(self.curve_identity())
    }

    /// Get the hardcoded curve identity wire as an `AuthenticatedPointResult`
    ///
    /// Both parties hold the identity point directly in this case
    pub fn curve_identity_authenticated(&self) -> AuthenticatedPointResult<C> {
        let identity_val = self.curve_identity();
        let share_value = self.curve_identity_shared();
        let mac_value = self.curve_identity_shared();

        AuthenticatedPointResult {
            share: share_value,
            mac: mac_value,
            public_modifier: identity_val,
        }
    }

    // -------------------
    // | Wire Allocation |
    // -------------------

    /// Allocate a shared value in the fabric
    fn allocate_shared_value<T: From<ResultValue<C>>>(
        &self,
        my_share: ResultValue<C>,
        their_share: ResultValue<C>,
    ) -> ResultHandle<C, T> {
        let id = self.inner.allocate_shared_value(my_share, their_share);
        ResultHandle::new(id, self.clone())
    }

    /// Share a `Scalar` value with the counterparty
    pub fn share_scalar<T: Into<Scalar<C>>>(
        &self,
        val: T,
        sender: PartyId,
    ) -> AuthenticatedScalarResult<C> {
        let scalar: ScalarResult<C> = if self.party_id() == sender {
            let scalar_val = val.into();
            let mut rng = thread_rng();
            let random = Scalar::random(&mut rng);

            let (my_share, their_share) = (scalar_val - random, random);
            self.allocate_shared_value(
                ResultValue::Scalar(my_share),
                ResultValue::Scalar(their_share),
            )
        } else {
            self.receive_value()
        };

        AuthenticatedScalarResult::new_shared(scalar)
    }

    /// Share a batch of `Scalar` values with the counterparty
    pub fn batch_share_scalar<T: Into<Scalar<C>>>(
        &self,
        vals: Vec<T>,
        sender: PartyId,
    ) -> Vec<AuthenticatedScalarResult<C>> {
        let n = vals.len();
        let shares: BatchScalarResult<C> = if self.party_id() == sender {
            let vals = vals.into_iter().map(|val| val.into()).collect_vec();
            let mut rng = thread_rng();

            let peer_shares = (0..vals.len()).map(|_| Scalar::random(&mut rng)).collect_vec();
            let my_shares =
                vals.iter().zip(peer_shares.iter()).map(|(val, share)| val - share).collect_vec();

            self.allocate_shared_value(
                ResultValue::ScalarBatch(my_shares),
                ResultValue::ScalarBatch(peer_shares),
            )
        } else {
            self.receive_value()
        };

        AuthenticatedScalarResult::new_shared_from_batch_result(shares, n)
    }

    /// Share a `CurvePoint` value with the counterparty
    pub fn share_point(&self, val: CurvePoint<C>, sender: PartyId) -> AuthenticatedPointResult<C> {
        let point: CurvePointResult<C> = if self.party_id() == sender {
            // As mentioned in https://eprint.iacr.org/2009/226.pdf
            // it is okay to sample a random point by sampling a random `Scalar` and
            // multiplying by the generator in the case that the discrete log of
            // the output may be leaked with respect to the generator. Leaking
            // the discrete log (i.e. the random `Scalar`) is okay when it is
            // used to generate secret shares
            let mut rng = thread_rng();
            let random = Scalar::random(&mut rng);
            let random_point = random * CurvePoint::generator();

            let (my_share, their_share) = (val - random_point, random_point);
            self.allocate_shared_value(
                ResultValue::Point(my_share),
                ResultValue::Point(their_share),
            )
        } else {
            self.receive_value()
        };

        AuthenticatedPointResult::new_shared(point)
    }

    /// Share a batch of `CurvePoint`s with the counterparty
    pub fn batch_share_point(
        &self,
        vals: Vec<CurvePoint<C>>,
        sender: PartyId,
    ) -> Vec<AuthenticatedPointResult<C>> {
        let n = vals.len();
        let shares: BatchCurvePointResult<C> = if self.party_id() == sender {
            let mut rng = thread_rng();
            let generator = CurvePoint::generator();
            let peer_shares = (0..vals.len())
                .map(|_| {
                    let discrete_log = Scalar::random(&mut rng);
                    discrete_log * generator
                })
                .collect_vec();
            let my_shares =
                vals.iter().zip(peer_shares.iter()).map(|(val, share)| val - share).collect_vec();

            self.allocate_shared_value(
                ResultValue::PointBatch(my_shares),
                ResultValue::PointBatch(peer_shares),
            )
        } else {
            self.receive_value()
        };

        AuthenticatedPointResult::new_shared_from_batch_result(shares, n)
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

    /// Allocate a scalar as a secret share of an already shared value
    pub fn allocate_preshared_scalar<T: Into<Scalar<C>>>(
        &self,
        value: T,
    ) -> AuthenticatedScalarResult<C> {
        let allocated = self.allocate_scalar(value);
        AuthenticatedScalarResult::new_shared(allocated)
    }

    /// Allocate a batch of scalars as secret shares of already shared values
    pub fn batch_allocate_preshared_scalar<T: Into<Scalar<C>>>(
        &self,
        values: Vec<T>,
    ) -> Vec<AuthenticatedScalarResult<C>> {
        let values = self.allocate_scalars(values);
        AuthenticatedScalarResult::new_shared_batch(&values)
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
    ) -> ResultHandle<C, Vec<T>>
    where
        T: 'static + From<ResultValue<C>> + Send + Sync,
        Vec<T>: Into<NetworkPayload<C>> + From<ResultValue<C>>,
    {
        self.share_plaintext(values, sender)
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
    // | Beaver Source |
    // -----------------

    /// Sample the next beaver triplet from the beaver source
    pub fn next_beaver_triple(
        &self,
    ) -> (MpcScalarResult<C>, MpcScalarResult<C>, MpcScalarResult<C>) {
        // Sample the triple and allocate it in the fabric, the counterparty will do the
        // same
        let (a, b, c) =
            self.inner.beaver_source.lock().expect("beaver source poisoned").next_triplet();

        let a_val = self.allocate_scalar(a);
        let b_val = self.allocate_scalar(b);
        let c_val = self.allocate_scalar(c);

        (
            MpcScalarResult::new_shared(a_val),
            MpcScalarResult::new_shared(b_val),
            MpcScalarResult::new_shared(c_val),
        )
    }

    /// Sample a batch of beaver triples
    #[allow(clippy::type_complexity)]
    pub fn next_beaver_triple_batch(
        &self,
        n: usize,
    ) -> (Vec<MpcScalarResult<C>>, Vec<MpcScalarResult<C>>, Vec<MpcScalarResult<C>>) {
        let (a_vals, b_vals, c_vals) =
            self.inner.beaver_source.lock().expect("beaver source poisoned").next_triplet_batch(n);

        let a_vals = self
            .allocate_scalars(a_vals)
            .into_iter()
            .map(MpcScalarResult::new_shared)
            .collect_vec();
        let b_vals = self
            .allocate_scalars(b_vals)
            .into_iter()
            .map(MpcScalarResult::new_shared)
            .collect_vec();
        let c_vals = self
            .allocate_scalars(c_vals)
            .into_iter()
            .map(MpcScalarResult::new_shared)
            .collect_vec();

        (a_vals, b_vals, c_vals)
    }

    /// Sample the next beaver triplet with MACs from the beaver source
    ///
    /// TODO: Authenticate these values either here or in the pre-processing
    /// phase as per the SPDZ paper
    pub fn next_authenticated_triple(
        &self,
    ) -> (AuthenticatedScalarResult<C>, AuthenticatedScalarResult<C>, AuthenticatedScalarResult<C>)
    {
        let (a, b, c) =
            self.inner.beaver_source.lock().expect("beaver source poisoned").next_triplet();

        let a_val = self.allocate_scalar(a);
        let b_val = self.allocate_scalar(b);
        let c_val = self.allocate_scalar(c);

        (
            AuthenticatedScalarResult::new_shared(a_val),
            AuthenticatedScalarResult::new_shared(b_val),
            AuthenticatedScalarResult::new_shared(c_val),
        )
    }

    /// Sample the next batch of beaver triples as `AuthenticatedScalar`s
    #[allow(clippy::type_complexity)]
    pub fn next_authenticated_triple_batch(
        &self,
        n: usize,
    ) -> (
        Vec<AuthenticatedScalarResult<C>>,
        Vec<AuthenticatedScalarResult<C>>,
        Vec<AuthenticatedScalarResult<C>>,
    ) {
        let (a_vals, b_vals, c_vals) =
            self.inner.beaver_source.lock().expect("beaver source poisoned").next_triplet_batch(n);

        let a_allocated = self.allocate_scalars(a_vals);
        let b_allocated = self.allocate_scalars(b_vals);
        let c_allocated = self.allocate_scalars(c_vals);

        (
            AuthenticatedScalarResult::new_shared_batch(&a_allocated),
            AuthenticatedScalarResult::new_shared_batch(&b_allocated),
            AuthenticatedScalarResult::new_shared_batch(&c_allocated),
        )
    }

    /// Sample a batch of random shared values from the beaver source
    pub fn random_shared_scalars(&self, n: usize) -> Vec<ScalarResult<C>> {
        let values_raw = self
            .inner
            .beaver_source
            .lock()
            .expect("beaver source poisoned")
            .next_shared_value_batch(n);

        // Wrap the values in a result handle
        values_raw.into_iter().map(|value| self.allocate_scalar(value)).collect_vec()
    }

    /// Sample a batch of random shared values from the beaver source and
    /// allocate them as `AuthenticatedScalars`
    pub fn random_shared_scalars_authenticated(
        &self,
        n: usize,
    ) -> Vec<AuthenticatedScalarResult<C>> {
        let values_raw = self
            .inner
            .beaver_source
            .lock()
            .expect("beaver source poisoned")
            .next_shared_value_batch(n);

        // Wrap the values in an authenticated wrapper
        AuthenticatedScalarResult::new_shared_batch(&self.allocate_scalars(values_raw))
    }

    /// Sample a pair of values that are multiplicative inverses of one another
    pub fn random_inverse_pair(
        &self,
    ) -> (AuthenticatedScalarResult<C>, AuthenticatedScalarResult<C>) {
        let (l, r) = self.inner.beaver_source.lock().unwrap().next_shared_inverse_pair();
        (
            AuthenticatedScalarResult::new_shared(self.allocate_scalar(l)),
            AuthenticatedScalarResult::new_shared(self.allocate_scalar(r)),
        )
    }

    /// Sample a batch of values that are multiplicative inverses of one another
    pub fn random_inverse_pairs(
        &self,
        n: usize,
    ) -> (Vec<AuthenticatedScalarResult<C>>, Vec<AuthenticatedScalarResult<C>>) {
        let (left, right) =
            self.inner.beaver_source.lock().unwrap().next_shared_inverse_pair_batch(n);

        let left_right = left.into_iter().chain(right).collect_vec();
        let allocated_left_right = self.allocate_scalars(left_right);
        let authenticated_left_right =
            AuthenticatedScalarResult::new_shared_batch(&allocated_left_right);

        // Split left and right
        let (left, right) = authenticated_left_right.split_at(n);
        (left.to_vec(), right.to_vec())
    }

    /// Sample a random shared bit from the beaver source
    pub fn random_shared_bit(&self) -> AuthenticatedScalarResult<C> {
        let bit =
            self.inner.beaver_source.lock().expect("beaver source poisoned").next_shared_bit();

        let bit = self.allocate_scalar(bit);
        AuthenticatedScalarResult::new_shared(bit)
    }

    /// Sample a batch of random shared bits from the beaver source
    pub fn random_shared_bits(&self, n: usize) -> Vec<AuthenticatedScalarResult<C>> {
        let bits = self
            .inner
            .beaver_source
            .lock()
            .expect("beaver source poisoned")
            .next_shared_bit_batch(n);

        let bits = self.allocate_scalars(bits);
        AuthenticatedScalarResult::new_shared_batch(&bits)
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
