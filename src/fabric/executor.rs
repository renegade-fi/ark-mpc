//! The executor receives IDs of operations that are ready for execution, executes
//! them, and places the result back into the fabric for further executions

use std::sync::atomic::Ordering;

use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::sync::mpsc::{UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender};
use tracing::log;

use crate::beaver::SharedValueSource;

use super::{result::OpResult, FabricInner};

/// Error dequeuing a result from the queue
const ERR_DEQUEUE: &str = "error dequeuing result";

pub(super) struct Executor<S: SharedValueSource> {
    /// The receiver on the result queue, where operation results are first materialized
    /// so that their dependents may be evaluated
    result_queue: TokioReceiver<OpResult>,
    /// A sender to the result queue so that hte executor may re-enqueue results for
    /// recursive evaluation
    result_sender: TokioSender<OpResult>,
    /// The underlying fabric that the executor is a part of
    fabric: FabricInner<S>,
    /// The channel on which the fabric may send a shutdown signal
    shutdown: BroadcastReceiver<()>,
}

impl<S: SharedValueSource> Executor<S> {
    pub fn new(
        result_queue: TokioReceiver<OpResult>,
        result_sender: TokioSender<OpResult>,
        fabric: FabricInner<S>,
        shutdown: BroadcastReceiver<()>,
    ) -> Self {
        Self {
            result_queue,
            result_sender,
            fabric,
            shutdown,
        }
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                // Next result
                x = self.result_queue.recv() => {
                    self.handle_new_result(x.expect(ERR_DEQUEUE));
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
            // Decrement the operation's in-flight args count
            let operation = locked_operations.get_mut(&operation_id).unwrap();
            let prev_num_args = operation.inflight_args.fetch_sub(1, Ordering::Relaxed);

            if prev_num_args == 1 {
                // Get the inputs and execute the method to produce the output
                let inputs = operation
                    .args
                    .iter()
                    .map(|id| locked_results.get(id).unwrap().value.clone())
                    .collect::<Vec<_>>();

                let output = (operation.function)(inputs);

                // Remove the operation from the set of in-flights
                locked_operations.remove(&operation_id);

                // Re-enqueue the result for processing
                self.result_sender
                    .send(OpResult {
                        id: operation_id,
                        value: output,
                    })
                    .expect("error re-enqueuing result");
            }
        }

        // Wake all tasks awaiting this result
        for waker in locked_wakers.remove(&id).unwrap_or_default().into_iter() {
            waker.wake();
        }
    }
}
