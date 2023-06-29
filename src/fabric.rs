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
        Arc, RwLock,
    },
    task::Waker,
};
use tokio::sync::broadcast::{self, Sender as BroadcastSender};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender as TokioSender};

use itertools::Itertools;

use crate::{
    beaver::SharedValueSource,
    network::{MpcNetwork, NetworkOutbound, NetworkPayload, PartyId, QuicTwoPartyNet},
    Shared,
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
#[derive(Clone, Debug)]
pub struct MpcFabric {
    /// The inner fabric
    inner: FabricInner,
    /// The channel on which shutdown messages are sent to blocking workers
    shutdown: BroadcastSender<()>,
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
    beaver_source: Arc<Box<dyn SharedValueSource>>,
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
            beaver_source: Arc::new(Box::new(beaver_source)),
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
    pub(crate) fn new_value(&self, value: ResultValue) -> ResultId {
        // Acquire locks
        let mut locked_results = self.results.write().expect("results poisoned");

        // Update fabric state
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        locked_results.insert(id, OpResult { id, value });

        id
    }

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

    // ------------------
    // | Secret Sharing |
    // ------------------

    /// Share a value with the counterparty
    pub(crate) fn share_value(
        &self,
        my_value: ResultValue,
        their_value: NetworkPayload,
    ) -> ResultId {
        // Allocate a new value
        let id = self.new_value(my_value);

        // Send the value to the counterparty
        if let Err(e) = self.outbound_queue.send(NetworkOutbound {
            op_id: id,
            payload: their_value,
        }) {
            log::error!("error sending value to counterparty: {e:?}");
        }

        id
    }

    /// Receive a value from the counterparty
    pub(crate) fn receive_value(&self) -> ResultId {
        // Simply allocate a new result ID, no extra work needs to be done, the
        // other party will push the value over the stream and the `NetworkSender`
        // will mark the value as ready once received
        self.new_id()
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

        Self {
            inner: fabric,
            shutdown: shutdown_sender,
        }
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

    /// Allocate a new plaintext value in the fabric
    pub fn new_value<T: From<ResultValue>>(&self, value: ResultValue) -> ResultHandle<T> {
        let id = self.inner.new_value(value);
        ResultHandle::new(id, self.clone())
    }

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
}
