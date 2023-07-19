//! The executor receives IDs of operations that are ready for execution, executes
//! them, and places the result back into the fabric for further executions

use std::collections::HashMap;

use crossbeam::channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender};
use itertools::Itertools;
use tracing::log;

use crate::network::NetworkOutbound;

use super::{result::OpResult, FabricInner};
use super::{Operation, OperationType, ResultId, ResultValue};

/// The executor is responsible for executing operation that are ready for execution, either
/// passed explicitly by the fabric or as a result of a dependency being satisfied
pub struct Executor {
    /// The receiver on the result queue, where operation results are first materialized
    /// so that their dependents may be evaluated
    result_receiver: CrossbeamReceiver<ExecutorMessage>,
    /// A sender to the result queue so that hte executor may re-enqueue results for
    /// recursive evaluation
    result_sender: CrossbeamSender<ExecutorMessage>,
    /// The operation buffer, stores in-flight operations
    operations: HashMap<ResultId, Operation>,
    /// The dependency map; maps in-flight results to operations that are waiting for them
    dependencies: HashMap<ResultId, Vec<ResultId>>,
    /// The underlying fabric that the executor is a part of
    fabric: FabricInner,
}

/// The type that the `Executor` receives on its channel, this may either be:
/// - A result of an operation, for which th executor will check the dependency map and
///  execute any operations that are now ready
/// - An operation directly, which the executor will execute immediately if all of its
///  arguments are ready
#[derive(Debug)]
pub enum ExecutorMessage {
    /// A result of an operation
    Result(OpResult),
    /// An operation that is ready for execution
    Op {
        /// The id allocated to this operation's result
        id: ResultId,
        /// The args of the operations
        args: Vec<ResultId>,
        /// The operation type
        op_type: OperationType,
    },
    /// Indicates that the executor should shut down
    Shutdown,
}

impl Executor {
    /// Constructor
    pub fn new(
        result_receiver: CrossbeamReceiver<ExecutorMessage>,
        result_sender: CrossbeamSender<ExecutorMessage>,
        fabric: FabricInner,
    ) -> Self {
        Self {
            result_receiver,
            result_sender,
            operations: HashMap::new(),
            dependencies: HashMap::new(),
            fabric,
        }
    }

    /// Run the executor until a shutdown message is received
    pub fn run(mut self) {
        loop {
            match self.result_receiver.recv() {
                Ok(ExecutorMessage::Result(res)) => self.handle_new_result(res),
                Ok(ExecutorMessage::Op { id, args, op_type }) => {
                    self.handle_new_operation(id, args, op_type)
                }
                Ok(ExecutorMessage::Shutdown) | Err(_) => {
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

        let prev = locked_results.insert(result.id, result);
        assert!(prev.is_none(), "duplicate result id: {id:?}");

        // Execute any ready dependencies
        if let Some(deps) = self.dependencies.get(&id) {
            for op_id in deps {
                {
                    let operation = self.operations.get_mut(op_id).unwrap();
                    operation.inflight_args -= 1;

                    if operation.inflight_args > 0 {
                        continue;
                    }
                } // Explicitly drop the mutable reference to `self`

                // Remove the operation from the in-flight list
                let operation = self.operations.remove(op_id).unwrap();

                // Get the inputs and execute the method to produce the output
                let inputs = operation
                    .args
                    .iter()
                    .map(|id| locked_results.get(id).unwrap().value.clone())
                    .collect::<Vec<_>>();
                self.execute_operation(*op_id, operation.op_type, inputs);
            }
        }
        // Wake all tasks awaiting this result
        let mut locked_wakers = self.fabric.wakers.write().expect("wakers lock poisoned");
        for waker in locked_wakers.remove(&id).unwrap_or_default().into_iter() {
            waker.wake();
        }
    }

    /// Handle a new operation
    fn handle_new_operation(
        &mut self,
        id: ResultId,
        args: Vec<ResultId>,
        operation: OperationType,
    ) {
        // Acquire all necessary locks
        let locked_results = self.fabric.results.read().expect("results lock poisoned");

        // Check if all arguments are ready
        let ready = args
            .iter()
            .filter_map(|id| locked_results.get(id))
            .map(|res| res.value.clone())
            .collect_vec();
        let inflight_args = args.len() - ready.len();

        // If the operation is ready for execution, do so
        if inflight_args == 0 {
            self.execute_operation(id, operation, ready);
            return;
        }

        // Otherwise, add the operation to the in-flight operations list and the dependency map
        for args in args.iter() {
            self.dependencies.entry(*args).or_default().push(id);
        }

        self.operations.insert(
            id,
            Operation {
                id,
                inflight_args,
                args,
                op_type: operation,
            },
        );
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
