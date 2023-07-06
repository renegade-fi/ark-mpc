//! Defines an MPC fabric for the protocol
//!
//! The fabric essentially acts as a dependency injection layer. That is, the MpcFabric
//! creates and manages dependencies needed to allocate network values. This provides a
//! cleaner interface for consumers of the library; i.e. clients do not have to hold onto
//! references of the network layer or the beaver sources to allocate values.

mod executor;
mod network_sender;
mod result;

pub(crate) use result::cast_args;
pub use result::{ResultHandle, ResultId, ResultValue};

use futures::executor::block_on;
use tracing::log;

use std::{
    collections::HashMap,
    fmt::{Debug, Formatter, Result as FmtResult},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    task::Waker,
};
use tokio::sync::broadcast::{self, Sender as BroadcastSender};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender as TokioSender};

use itertools::Itertools;

use crate::{
    algebra::{authenticated_scalar::AuthenticatedScalarResult, mpc_scalar::MpcScalarResult},
    beaver::SharedValueSource,
    network::{MpcNetwork, NetworkOutbound, NetworkPayload, PartyId, QuicTwoPartyNet},
    Shared, PARTY0,
};

use self::{
    executor::{Executor, ExecutorMessage},
    network_sender::NetworkSender,
    result::OpResult,
};

/// An operation within the network, describes the arguments and function to evaluate
/// once the arguments are ready
pub(crate) struct Operation {
    /// Identifier of the result that this operation emits
    id: ResultId,
    /// The number of arguments that are still in-flight for this operation
    inflight_args: AtomicUsize,
    /// The IDs of the inputs to this operation
    args: Vec<ResultId>,
    /// The type of the operation
    op_type: OperationType,
}

impl Debug for Operation {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Operation {}", self.id)
    }
}

/// Defines the different types of operations available in the computation graph
pub(crate) enum OperationType {
    /// A gate operation; may be evaluated locally given its ready inputs
    Gate {
        /// The function to apply to the inputs
        function: Box<dyn FnOnce(Vec<ResultValue>) -> ResultValue + Send + Sync>,
    },
    /// A network operation, requires that a value be sent over the network
    Network {
        /// The function to apply to the inputs to derive a Network payload
        function: Box<dyn FnOnce(Vec<ResultValue>) -> NetworkPayload + Send + Sync>,
    },
}

/// A fabric for the MPC protocol, defines a dependency injection layer that dynamically schedules
/// circuit gate evaluations onto the network to be executed
///
/// The fabric does not block on gate evaluations, but instead returns a handle to a future result
/// that may be polled to obtain the materialized result. This allows the application layer to
/// continue using the fabric, scheduling more gates to be evaluated and maximally exploiting
/// gate-level parallelism within the circuit
#[derive(Clone)]
pub struct MpcFabric {
    /// The inner fabric
    inner: FabricInner,
    /// The local party's share of the global MAC key
    ///
    /// The parties collectively hold an additive sharing of the global key
    ///
    /// We wrap in a reference counting structure to avoid recursive type issues
    mac_key: Option<Arc<MpcScalarResult>>,
    /// The channel on which shutdown messages are sent to blocking workers
    shutdown: BroadcastSender<()>,
}

impl Debug for MpcFabric {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "MpcFabric")
    }
}

/// The inner component of the fabric, allows the constructor to allocate executor and network
/// sender objects at the same level as the fabric
#[derive(Clone)]
pub(crate) struct FabricInner {
    /// The ID of the local party in the MPC execution
    party_id: u64,
    /// The next identifier to assign to an operation
    next_id: Arc<AtomicUsize>,
    /// The completed results of operations
    results: Shared<HashMap<ResultId, OpResult>>,
    /// The list of in-flight operations
    operations: Shared<HashMap<ResultId, Operation>>,
    /// The dependency map; maps in-flight results to operations that are dependent on them
    dependencies: Shared<HashMap<ResultId, Vec<ResultId>>>,
    /// A map of operations to wakers of tasks that are waiting on the operation to complete
    wakers: Shared<HashMap<ResultId, Vec<Waker>>>,
    /// A sender to the executor
    execution_queue: TokioSender<ExecutorMessage>,
    /// The underlying queue to the network
    outbound_queue: TokioSender<NetworkOutbound>,
    /// The underlying shared randomness source
    beaver_source: Arc<Mutex<Box<dyn SharedValueSource>>>,
}

impl Debug for FabricInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "FabricInner")
    }
}

impl FabricInner {
    /// Constructor
    pub fn new<S: 'static + SharedValueSource>(
        party_id: u64,
        execution_queue: TokioSender<ExecutorMessage>,
        outbound_queue: TokioSender<NetworkOutbound>,
        beaver_source: S,
    ) -> Self {
        Self {
            party_id,
            next_id: Arc::new(AtomicUsize::new(0)),
            results: Arc::new(RwLock::new(HashMap::new())),
            operations: Arc::new(RwLock::new(HashMap::new())),
            dependencies: Arc::new(RwLock::new(HashMap::new())),
            wakers: Arc::new(RwLock::new(HashMap::new())),
            execution_queue,
            outbound_queue,
            beaver_source: Arc::new(Mutex::new(Box::new(beaver_source))),
        }
    }

    /// Increment the operation counter and return the existing value
    fn new_id(&self) -> ResultId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    // ------------------------
    // | Low Level Allocation |
    // ------------------------

    /// Allocate a new plaintext value in the fabric
    pub(crate) fn allocate_value(&self, value: ResultValue) -> ResultId {
        // Acquire locks
        let mut locked_results = self.results.write().expect("results poisoned");

        // Update fabric state
        let id = self.new_id();
        locked_results.insert(id, OpResult { id, value });

        id
    }

    /// Allocate a secret shared value in the network
    pub(crate) fn allocate_shared_value(
        &self,
        my_share: ResultValue,
        their_share: ResultValue,
    ) -> ResultId {
        // Acquire locks
        let mut locked_results = self.results.write().expect("results poisoned");

        // Add my share to the results
        let id = self.new_id();
        locked_results.insert(
            id,
            OpResult {
                id,
                value: my_share,
            },
        );

        // Send the counterparty their share
        if let Err(e) = self.outbound_queue.send(NetworkOutbound {
            op_id: id,
            payload: their_share.into(),
        }) {
            log::error!("error sending share to counterparty: {e:?}");
        }

        id
    }

    /// Receive a value from a network operation initiated by a peer
    ///
    /// The peer will already send the value with the corresponding ID, so all that is needed
    /// is to allocate a slot in the result buffer for the receipt
    pub(crate) fn receive_value(&self) -> ResultId {
        self.new_id()
    }

    // --------------
    // | Operations |
    // --------------

    /// Allocate a new in-flight gate operation in the fabric
    pub(crate) fn new_op(&self, args: Vec<ResultId>, op_type: OperationType) -> ResultId {
        // Acquire all locks
        let locked_results = self.results.read().expect("results poisoned");
        let mut locked_ops = self.operations.write().expect("ops poisoned");
        let mut locked_deps = self.dependencies.write().expect("deps poisoned");

        // Get an ID for the result
        let id = self.new_id();

        // Count the args that are not yet ready
        let inputs = args
            .iter()
            .filter_map(|id| locked_results.get(id))
            .map(|op_res| op_res.value.clone())
            .collect_vec();
        let n_inflight = args.len() - inputs.len();

        // Create an operation and handle it
        let op = Operation {
            id,
            inflight_args: AtomicUsize::new(n_inflight),
            args,
            op_type,
        };

        // If all arguments are already resolved, forward to the executor for immediate execution
        if n_inflight == 0 {
            self.execution_queue
                .send(ExecutorMessage::Op(op))
                .expect("error sending op to executor");
        } else {
            // Update the dependency map
            for arg in op.args.iter() {
                locked_deps.entry(*arg).or_insert_with(Vec::new).push(id);
            }

            locked_ops.insert(id, op);
        }

        id
    }
}

impl MpcFabric {
    /// Constructor
    pub fn new<S: 'static + SharedValueSource>(network: QuicTwoPartyNet, beaver_source: S) -> Self {
        // Build communication primitives
        let (result_sender, result_receiver) = unbounded_channel();
        let (outbound_sender, outbound_receiver) = unbounded_channel();
        let (shutdown_sender, shutdown_receiver) = broadcast::channel(1 /* capacity */);

        // Build a fabric
        let fabric = FabricInner::new(
            network.party_id(),
            result_sender.clone(),
            outbound_sender,
            beaver_source,
        );

        // Start a network sender and operator executor
        let network_sender = NetworkSender::new(
            outbound_receiver,
            result_sender.clone(),
            network,
            shutdown_receiver,
        );
        tokio::task::spawn_blocking(move || block_on(network_sender.run()));

        let executor = Executor::new(
            result_receiver,
            result_sender,
            fabric.clone(),
            shutdown_sender.subscribe(),
        );
        tokio::task::spawn_blocking(move || block_on(executor.run()));

        // Create the fabric and fill in the MAC key after
        let mut self_ = Self {
            inner: fabric.clone(),
            shutdown: shutdown_sender,
            mac_key: None,
        };

        // Sample a MAC key from the pre-shared values in the beaver source
        let mac_key_id = fabric.allocate_value(ResultValue::Scalar(
            fabric
                .beaver_source
                .lock()
                .expect("beaver source poisoned")
                .next_shared_value(),
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

    /// Shutdown the fabric and the threads it has spawned
    pub fn shutdown(self) {
        log::debug!("shutting down fabric");
        self.shutdown
            .send(())
            .expect("error sending shutdown signal");
    }

    /// Immutably borrow the MAC key
    pub(crate) fn borrow_mac_key(&self) -> &MpcScalarResult {
        // Unwrap is safe, the constructor sets the MAC key
        self.mac_key.as_ref().unwrap()
    }

    // ---------------------
    // | Direct Allocation |
    // ---------------------

    /// Allocate a new plaintext value in the fabric
    pub fn allocate_value<T: From<ResultValue>>(&self, value: ResultValue) -> ResultHandle<T> {
        let id = self.inner.allocate_value(value);
        ResultHandle::new(id, self.clone())
    }

    /// Allocate a shared value in the fabric
    pub fn allocate_shared_value<T: From<ResultValue>>(
        &self,
        my_share: ResultValue,
        their_share: ResultValue,
    ) -> ResultHandle<T> {
        let id = self.inner.allocate_shared_value(my_share, their_share);
        ResultHandle::new(id, self.clone())
    }

    /// Send a value to the peer, placing the identity in the local result buffer at the send ID
    pub fn send_value<T: From<ResultValue> + Into<NetworkPayload>>(
        &self,
        value: ResultHandle<T>,
    ) -> ResultHandle<T> {
        self.new_network_op(vec![value.id], |args| {
            let [value]: [T; 1] = cast_args(args);
            value.into()
        })
    }

    /// Receive a value from the peer
    pub fn receive_value<T: From<ResultValue>>(&self) -> ResultHandle<T> {
        let id = self.inner.receive_value();
        ResultHandle::new(id, self.clone())
    }

    /// Exchange a value with the peer, i.e. send then receive or receive then send
    /// based on the party ID
    ///
    /// Returns a handle to the received value, which will be different for different parties
    pub fn exchange_value<T: From<ResultValue> + Into<NetworkPayload>>(
        &self,
        value: ResultHandle<T>,
    ) -> ResultHandle<T> {
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

    // -------------------
    // | Gate Definition |
    // -------------------

    /// Construct a new gate operation in the fabric, i.e. one that can be evaluated immediate given
    /// its inputs
    pub fn new_gate_op<F, T>(&self, args: Vec<ResultId>, function: F) -> ResultHandle<T>
    where
        F: 'static + FnOnce(Vec<ResultValue>) -> ResultValue + Send + Sync,
        T: From<ResultValue>,
    {
        let function = Box::new(function);
        let id = self.inner.new_op(args, OperationType::Gate { function });
        ResultHandle::new(id, self.clone())
    }

    /// Construct a new network operation in the fabric, i.e. one that requires a value to be sent
    /// over the channel
    pub fn new_network_op<F, T>(&self, args: Vec<ResultId>, function: F) -> ResultHandle<T>
    where
        F: 'static + FnOnce(Vec<ResultValue>) -> NetworkPayload + Send + Sync,
        T: From<ResultValue>,
    {
        let function = Box::new(function);
        let id = self.inner.new_op(args, OperationType::Network { function });
        ResultHandle::new(id, self.clone())
    }

    // -----------------
    // | Beaver Source |
    // -----------------

    /// Sample the next beaver triplet from the beaver source
    pub fn next_beaver_triple(&self) -> (MpcScalarResult, MpcScalarResult, MpcScalarResult) {
        // Sample the triple and allocate it in the fabric, the counterparty will do the same
        let (a, b, c) = self
            .inner
            .beaver_source
            .lock()
            .expect("beaver source poisoned")
            .next_triplet();

        let a_val = self.allocate_value(ResultValue::Scalar(a));
        let b_val = self.allocate_value(ResultValue::Scalar(b));
        let c_val = self.allocate_value(ResultValue::Scalar(c));

        (
            MpcScalarResult::new_shared(a_val),
            MpcScalarResult::new_shared(b_val),
            MpcScalarResult::new_shared(c_val),
        )
    }

    /// Sample the next beaver triplet with MACs from the beaver source
    ///
    /// TODO: Authenticate these values either here or in the pre-processing phase as per
    /// the SPDZ paper
    pub fn next_authenticated_beaver_triple(
        &self,
    ) -> (
        AuthenticatedScalarResult,
        AuthenticatedScalarResult,
        AuthenticatedScalarResult,
    ) {
        let (a, b, c) = self
            .inner
            .beaver_source
            .lock()
            .expect("beaver source poisoned")
            .next_triplet();

        let a_val = self.allocate_value(ResultValue::Scalar(a));
        let b_val = self.allocate_value(ResultValue::Scalar(b));
        let c_val = self.allocate_value(ResultValue::Scalar(c));

        (
            AuthenticatedScalarResult::new_shared(a_val),
            AuthenticatedScalarResult::new_shared(b_val),
            AuthenticatedScalarResult::new_shared(c_val),
        )
    }
}
