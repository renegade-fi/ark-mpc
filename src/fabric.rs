//! Defines an MPC fabric for the protocol
//!
//! The fabric essentially acts as a dependency injection layer. That is, the MpcFabric
//! creates and manages dependencies needed to allocate network values. This provides a
//! cleaner interface for consumers of the library; i.e. clients do not have to hold onto
//! references of the network layer or the beaver sources to allocate values.

mod executor;
mod network_sender;
mod result;

use futures::Future;
pub(crate) use result::{ResultId, ResultValue};

use std::{
    collections::HashMap,
    fmt::{Debug, Formatter, Result as FmtResult},
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
    task::{Context, Poll, Waker},
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender as TokioSender};

use itertools::Itertools;

use crate::{
    beaver::SharedValueSource,
    network::{MpcNetwork, NetworkOutbound, QuicTwoPartyNet},
    Shared,
};

use self::{executor::Executor, network_sender::NetworkSender, result::OpResult};

// ----------------------
// | New Implementation |
// ----------------------

/// A handle to the result of the execution of an MPC computation graph
pub struct ResultHandle<S: SharedValueSource> {
    /// The id of the result
    id: ResultId,
    /// The underlying fabric
    fabric: FabricInner<S>,
}

impl<S: SharedValueSource> Future for ResultHandle<S> {
    type Output = ResultValue;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let locked_results = self.fabric.results.read().expect("results poisoned");
        let mut locked_wakers = self.fabric.wakers.write().expect("wakers poisoned");

        match locked_results.get(&self.id) {
            Some(res) => Poll::Ready(res.value.clone()),
            None => {
                locked_wakers
                    .entry(self.id)
                    .or_insert_with(Vec::new)
                    .push(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

/// An operation within the network, describes the arguments and function to evaluate
/// once the arguments are ready
struct Operation {
    /// Identifier of the result that this operation emits
    id: ResultId,
    /// The number of arguments that are still in-flight for this operation
    inflight_args: AtomicUsize,
    /// The IDs of the inputs to this operation
    args: Vec<ResultId>,
    /// The function to apply to the inputs
    function: fn(Vec<ResultValue>) -> ResultValue,
}

/// A fabric for the MPC protocol, defines a dependency injection layer that dynamically schedules
/// circuit gate evaluations onto the network to be executed
///
/// The fabric does not block on gate evaluations, but instead returns a handle to a future result
/// that may be polled to obtain the materialized result. This allows the application layer to
/// continue using the fabric, scheduling more gates to be evaluated and maximally exploiting
/// gate-level parallelism within the circuit
#[derive(Clone, Debug)]
pub struct MpcFabric<S: SharedValueSource>(FabricInner<S>);

/// The inner component of the fabric, allows the constructor to allocate executor and network
/// sender objects at the same level as the fabric
#[derive(Clone)]
struct FabricInner<S: SharedValueSource> {
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
    result_queue: TokioSender<OpResult>,
    /// The underlying queue to the network
    outbound_queue: TokioSender<NetworkOutbound>,
    /// The underlying shared randomness source
    beaver_source: S,
}

impl<S: SharedValueSource> Debug for FabricInner<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "FabricInner")
    }
}

impl<S: SharedValueSource> FabricInner<S> {
    /// Constructor
    pub fn new(
        party_id: u64,
        result_queue: TokioSender<OpResult>,
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
            result_queue,
            outbound_queue,
            beaver_source,
        }
    }

    /// Allocate a new plaintext value in the fabric
    pub fn new_value(&mut self, value: ResultValue) -> ResultId {
        // Acquire locks
        let mut locked_results = self.results.write().expect("results poisoned");

        // Update fabric state
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        locked_results.insert(id, OpResult { id, value });

        id
    }

    /// Allocate a new in-flight operation in the network
    pub fn new_op(
        &mut self,
        args: Vec<ResultId>,
        function: fn(Vec<ResultValue>) -> ResultValue,
    ) -> ResultId {
        // Acquire all locks
        let locked_results = self.results.read().expect("results poisoned");
        let mut locked_ops = self.operations.write().expect("ops poisoned");
        let mut locked_deps = self.dependencies.write().expect("deps poisoned");

        // Get an ID for the result
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        // Count the args that are not yet ready
        let inputs = args
            .iter()
            .filter_map(|id| locked_results.get(id))
            .map(|op_res| op_res.value.clone())
            .collect_vec();
        let n_inflight = args.len() - inputs.len();

        // If all arguments are already resolved, simply execute the result directly
        if n_inflight == 0 {
            let res = function(inputs);
            self.result_queue
                .send(OpResult { id, value: res })
                .expect("error sending result to executor");
        } else {
            // Update the dependency map
            for arg in args.iter() {
                locked_deps.entry(*arg).or_insert_with(Vec::new).push(id);
            }

            // Add the operation to the in-flight list
            let op = Operation {
                id,
                inflight_args: AtomicUsize::new(n_inflight),
                args,
                function,
            };
            locked_ops.insert(id, op);
        }

        id
    }
}

impl<S: 'static + SharedValueSource> MpcFabric<S> {
    /// Constructor
    pub fn new(network: QuicTwoPartyNet, beaver_source: S) -> Self {
        // Build communication primitives
        let (result_sender, result_receiver) = unbounded_channel();
        let (outbound_sender, outbound_receiver) = unbounded_channel();

        // Build a fabric
        let fabric = FabricInner::new(
            network.party_id(),
            result_sender.clone(),
            outbound_sender,
            beaver_source,
        );

        // Start a network sender and operator executor
        let network_sender = NetworkSender::new(outbound_receiver, result_sender.clone(), network);
        tokio::task::spawn_blocking(move || network_sender.run());

        let executor = Executor::new(result_receiver, result_sender, fabric.clone());
        tokio::task::spawn_blocking(move || executor.run());

        Self(fabric)
    }

    /// Allocate a new plaintext value in the fabric
    pub fn new_value(&mut self, value: ResultValue) -> ResultHandle<S> {
        let id = self.0.new_value(value);
        ResultHandle {
            id,
            fabric: self.0.clone(),
        }
    }

    /// Construct a new operation in the fabric
    pub fn new_op(
        &mut self,
        args: Vec<ResultHandle<S>>,
        function: fn(Vec<ResultValue>) -> ResultValue,
    ) -> ResultHandle<S> {
        let arg_ids = args.iter().map(|arg| arg.id).collect_vec();
        let id = self.0.new_op(arg_ids, function);
        ResultHandle {
            id,
            fabric: self.0.clone(),
        }
    }
}
