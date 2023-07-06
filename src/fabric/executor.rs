//! The executor receives IDs of operations that are ready for execution, executes
//! them, and places the result back into the fabric for further executions

use std::sync::atomic::Ordering;

use itertools::Itertools;
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::sync::mpsc::{UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender};
use tracing::log;

use crate::network::NetworkOutbound;

use super::{result::OpResult, FabricInner};
use super::{Operation, OperationType, ResultId, ResultValue};

/// Error dequeuing a result from the queue
const ERR_DEQUEUE: &str = "error dequeuing result";

/// The executor is responsible for executing operation that are ready for execution, etiher
/// passed explicitly by the fabric or as a result of a dependency being satisfied
pub(super) struct Executor {
    /// The receiver on the result queue, where operation results are first materialized
    /// so that their dependents may be evaluated
    result_queue: TokioReceiver<ExecutorMessage>,
    /// A sender to the result queue so that hte executor may re-enqueue results for
    /// recursive evaluation
    result_sender: TokioSender<ExecutorMessage>,
    /// The underlying fabric that the executor is a part of
    fabric: FabricInner,
    /// The channel on which the fabric may send a shutdown signal
    shutdown: BroadcastReceiver<()>,
}

/// The type that the `Executor` receives on its channel, this may either be:
/// - A result of an operation, for which th executor will check the dependency map and
///  execute any operations that are now ready
/// - An operation directly, which the executor will execute immediately if all of its
///  arguments are ready
#[derive(Debug)]
pub(crate) enum ExecutorMessage {
    /// A result of an operation
    Result(OpResult),
    /// An operation that is ready for execution
    Op(Operation),
}

impl Executor {
    /// Constructor
    pub fn new(
        result_queue: TokioReceiver<ExecutorMessage>,
        result_sender: TokioSender<ExecutorMessage>,
        fabric: FabricInner,
        shutdown: BroadcastReceiver<()>,
    ) -> Self {
        Self {
            result_queue,
            result_sender,
            fabric,
            shutdown,
        }
    }

    /// Run the executor until a shutdown message is received
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                // Next result
                x = self.result_queue.recv() => {
                    match x.expect(ERR_DEQUEUE) {
                        ExecutorMessage::Result(res) => self.handle_new_result(res),
                        ExecutorMessage::Op(op) => self.handle_new_operation(op),
                    }
                }

                // Shutdown signal
                _ = self.shutdown.recv() => {
                    log::debug!("executor shutting down");
                    break;
                }
            }
        }
    }

    /// Handle a new result
    fn handle_new_result(&mut self, result: OpResult) {
        let id = result.id;

        // Lock the fabric elements needed
        let mut locked_results = self.fabric.results.write().expect("results lock poisoned");
        locked_results.insert(result.id, result);

        let mut locked_operations = self.fabric.operations.write().expect("ops lock poisoned");
        let mut locked_deps = self
            .fabric
            .dependencies
            .write()
            .expect("deps lock poisoned");
        let mut locked_wakers = self.fabric.wakers.write().expect("wakers lock poisoned");

        // Get the operation's dependencies
        for operation_id in locked_deps.remove(&id).unwrap_or_default() {
            // Decrement the operation's in-flight args count, take ownership of the operation
            // so that we may consume the `FnOnce` callback if the args are ready
            let operation = locked_operations.remove(&operation_id).unwrap();
            let prev_num_args = operation.inflight_args.fetch_sub(1, Ordering::Relaxed);

            if prev_num_args == 1 {
                // Get the inputs and execute the method to produce the output
                let inputs = operation
                    .args
                    .iter()
                    .map(|id| locked_results.get(id).unwrap().value.clone())
                    .collect::<Vec<_>>();
                self.execute_operation(operation_id, operation.op_type, inputs);
            } else {
                locked_operations.insert(operation_id, operation);
            }
        }

        // Wake all tasks awaiting this result
        for waker in locked_wakers.remove(&id).unwrap_or_default().into_iter() {
            waker.wake();
        }
    }

    /// Handle a new operation
    fn handle_new_operation(&self, operation: Operation) {
        // Acquire all necessary locks
        let locked_results = self.fabric.results.write().expect("results lock poisoned");

        // Check that all arguments are ready
        let inputs = operation
            .args
            .iter()
            .filter_map(|id| locked_results.get(id).cloned())
            .map(|res| res.value)
            .collect_vec();
        if inputs.len() != operation.args.len() {
            log::error!("operation {:?} has missing arguments", operation.id);
            return;
        }

        // Execute the operation
        self.execute_operation(operation.id, operation.op_type, inputs);
    }

    /// Executes an operation whose arguments are ready
    fn execute_operation(&self, id: ResultId, operation: OperationType, inputs: Vec<ResultValue>) {
        match operation {
            OperationType::Gate { function } => {
                let output = (function)(inputs);
                self.result_sender
                    .send(ExecutorMessage::Result(OpResult { id, value: output }))
                    .expect("error re-enqueuing result");
            }

            OperationType::Network { function } => {
                // Derive a network payload from the gate inputs and forward it to the outbound buffer
                let payload = (function)(inputs);
                let outbound = NetworkOutbound {
                    op_id: id,
                    payload: payload.clone(),
                };

                self.fabric
                    .outbound_queue
                    .send(outbound)
                    .expect("error sending network payload");

                // On a `send`, the local party receives a copy of the value placed as the result of
                // the network operation, so we must re-enqueue the result
                self.result_sender
                    .send(ExecutorMessage::Result(OpResult {
                        id,
                        value: payload.into(),
                    }))
                    .expect("error re-enqueuing result");
            }
        }
    }
}
