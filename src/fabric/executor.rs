//! The executor receives IDs of operations that are ready for execution, executes
//! them, and places the result back into the fabric for further executions

use std::sync::atomic::Ordering;

use tokio::sync::mpsc::{UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender};

use super::{result::OpResult, FabricInner};

/// Error dequeuing a result from the queue
const ERR_DEQUEUE: &str = "error dequeuing result";

pub(super) struct Executor {
    /// The receiver on the result queue, where operation results are first materialized
    /// so that their dependents may be evaluated
    result_queue: TokioReceiver<OpResult>,
    /// A sender to the result queue so that hte executor may re-enqueue results for
    /// recursive evaluation
    result_sender: TokioSender<OpResult>,
    /// The underlying fabric that the executor is a part of
    fabric: FabricInner,
}

impl Executor {
    pub fn new(
        result_queue: TokioReceiver<OpResult>,
        result_sender: TokioSender<OpResult>,
        fabric: FabricInner,
    ) -> Self {
        Self {
            result_queue,
            result_sender,
            fabric,
        }
    }

    pub fn run(mut self) {
        loop {
            // Pull the next result off the queue
            let result = self.result_queue.blocking_recv().expect(ERR_DEQUEUE);

            // Lock the fabric elements needed
            let mut locked_results = self.fabric.results.write().expect("results lock poisoned");
            locked_results.insert(result.id, result);

            let mut locked_operations = self.fabric.operations.write().expect("ops lock poisoned");
            let mut locked_deps = self.fabric.dependencies.read().expect("deps lock poisoned");
            let mut locked_wakers = self.fabric.wakers.read().expect("wakers lock poisoned");

            // Get the operation's dependencies
            for operation_id in locked_deps.remove(&result.id).unwrap_or_default() {
                // Decrement the operation's in-flight args count
                let operation = locked_operations.get_mut(&operation_id).unwrap();
                let prev_num_args = operation.inflight_args.fetch_sub(1, Ordering::Relaxed);

                if prev_num_args == 1 {
                    // Get the inputs and execute the method to produce the output
                    let inputs = operation
                        .inputs
                        .iter()
                        .map(|id| locked_results.get(id).unwrap().value)
                        .collect::<Vec<_>>();

                    let output = (operation.function)(inputs);

                    // Remove the operation from the set of in-flights
                    locked_operations.remove(&operation_id);

                    // Re-enqueue the result for processing
                    self.result_sender
                        .send(OpResult {
                            id: operation_id,
                            value: output,
                            fabric: self.fabric.clone(),
                        })
                        .expect("error re-enqueuing result");
                }
            }

            // Wake all tasks awaiting this result
            for waker in locked_wakers.remove(&result.id).iter() {
                waker.wake();
            }
        }
    }
}
