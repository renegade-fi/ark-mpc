//! A multithreaded executor underlying the fabric
//!
//! The executor receives IDs of operations that are ready for execution,
//! executes them, and places the result back into the fabric for further
//! executions
//!
//! The concurrency model is as follows:
//! - A coordinator thread manages the inbound executor queue, handling new
//!   results, operations, waiters, etc
//! - The coordinator is backed by a thread pool of worker threads, onto which
//!   it spawns operations that are ready to execute

use std::{collections::HashMap, sync::Arc};

use ark_ec::CurveGroup;
use crossbeam::queue::SegQueue;
use kanal::Sender as KanalSender;
use rayon::{ThreadPool, ThreadPoolBuilder};
use tracing::log;

use crate::{
    fabric::{
        executor::{buffer::GrowableBuffer, ExecutorJobQueue, ExecutorMessage, ExecutorSizeHints},
        result::{ResultWaiter, ERR_RESULT_BUFFER_POISONED},
        OpResult, Operation, OperationId, OperationType,
    },
    network::NetworkOutbound,
    ResultId,
};

use super::result_buffer::ParallelResultBuffer;
use super::result_mask::ResultMask;

/// The executor is responsible for executing operation that are ready for
/// execution, either passed explicitly by the fabric or as a result of a
/// dependency being satisfied
pub struct ParallelExecutor<C: CurveGroup> {
    /// The job queue for the executor
    job_queue: ExecutorJobQueue<C>,
    /// The operation buffer, stores in-flight operations
    operations: GrowableBuffer<Operation<C>>,
    /// The dependency map; maps in-flight results to operations that are
    /// waiting for them
    dependencies: GrowableBuffer<Vec<ResultId>>,
    /// The completed results of operations
    results: ParallelResultBuffer<C>,
    /// A bit vector representing which results are available
    ///
    /// We use this to avoid contention and races on the `results` buffer while
    /// the coordinator is computing in-flight args
    ready_mask: ResultMask,
    /// An index of waiters for incomplete results
    waiters: HashMap<ResultId, Vec<ResultWaiter<C>>>,
    /// The thread pool that results are computed on
    pool: ThreadPool,
    /// The network outbound queue
    network_outbound: KanalSender<NetworkOutbound<C>>,
}

impl<C: CurveGroup> ParallelExecutor<C> {
    /// Constructor
    pub fn new(
        size_hints: ExecutorSizeHints,
        job_queue: Arc<SegQueue<ExecutorMessage<C>>>,
        network_outbound: KanalSender<NetworkOutbound<C>>,
    ) -> Self {
        let pool = ThreadPoolBuilder::new().build().expect("error building thread pool");
        Self {
            job_queue,
            operations: GrowableBuffer::new(size_hints.n_ops),
            dependencies: GrowableBuffer::new(size_hints.n_ops),
            results: ParallelResultBuffer::new(size_hints.n_results),
            ready_mask: ResultMask::new(size_hints.n_results),
            waiters: HashMap::new(),
            pool,
            network_outbound,
        }
    }

    /// Run the executor until a shutdown message is received
    pub fn run(mut self) {
        loop {
            if let Some(job) = self.job_queue.pop() {
                match job {
                    ExecutorMessage::Result(res) => self.handle_new_result(res),
                    ExecutorMessage::ResultBatch(res) => {
                        for result in res.into_iter() {
                            self.handle_new_result(result);
                        }
                    },
                    ExecutorMessage::ResultsReady(ids) => {
                        for result_id in ids.into_iter() {
                            self.handle_new_result_by_id(result_id);
                        }
                    },
                    ExecutorMessage::Op(operation) => self.handle_new_operation(operation),
                    ExecutorMessage::NewWaiter(waiter) => self.handle_new_waiter(waiter),
                    ExecutorMessage::Shutdown => {
                        log::debug!("executor shutting down");
                        break;
                    },
                }
            }
        }
    }

    // ----------------
    // | Job Handlers |
    // ----------------

    /// Handle a new result
    fn handle_new_result(&mut self, result: OpResult<C>) {
        let id = result.id;
        self.ready_mask.mark_ready(id);

        // Add the result to the buffer and execute any operations that are now ready
        self.insert_result(result);
        self.execute_dependents(id);
    }

    /// Handle a new result given by ID
    fn handle_new_result_by_id(&mut self, id: ResultId) {
        // Notify any threads waiting on this value
        self.wake_waiters_on_result(id);

        self.ready_mask.mark_ready(id);
        self.execute_dependents(id);
    }

    /// Handle a new operation
    fn handle_new_operation(&mut self, mut op: Operation<C>) {
        // Check if all arguments are ready
        let n_ready = op.args.iter().filter(|&&id| self.ready_mask.is_ready(id)).count();
        let inflight_args = op.args.len() - n_ready;
        op.inflight_args = inflight_args;

        // If the operation is ready for execution, do so
        if inflight_args == 0 {
            let id = op.id;
            if self.operations.insert(id, op).is_some() {
                panic!("duplicate operation id: {id}");
            }

            self.execute_operations(vec![id]);
            return;
        }

        // Otherwise, add the operation to the in-flight operations list and the
        // dependency map
        for arg in op.args.iter() {
            let entry = self.dependencies.entry_mut(*arg);
            if entry.is_none() {
                *entry = Some(Vec::new());
            }

            entry.as_mut().unwrap().push(op.id);
        }

        let id = op.id;
        if self.operations.insert(id, op).is_some() {
            panic!("duplicate operation id: {id}");
        }
    }

    /// Handle a new waiter for a result
    pub fn handle_new_waiter(&mut self, waiter: ResultWaiter<C>) {
        let id = waiter.result_id;

        // Insert the new waiter to the queue
        self.waiters.entry(waiter.result_id).or_default().push(waiter);

        // If the result being awaited is already available, wake the waiter
        if self.results.get(id).is_some() {
            self.wake_waiters_on_result(id);
        }
    }

    // -----------
    // | Helpers |
    // -----------

    /// Insert a result into the buffer
    fn insert_result(&mut self, result: OpResult<C>) {
        let id = result.id;
        self.results.set(id, result.value);

        self.wake_waiters_on_result(id);
    }

    /// Execute all operations that are ready after committing a result
    fn execute_dependents(&mut self, id: ResultId) {
        let mut ready_ops = Vec::new();
        if let Some(deps) = self.dependencies.get(id) {
            for op_id in deps.iter() {
                let operation = self.operations.get_mut(*op_id).unwrap();

                operation.inflight_args -= 1;
                if operation.inflight_args > 0 {
                    continue;
                }

                // Mark the operation as ready for execution
                ready_ops.push(*op_id);
            }
        }

        self.execute_operations(ready_ops);
    }

    /// Executes the operations in the buffer, recursively executing any
    /// dependencies that become ready
    fn execute_operations(&mut self, ops: Vec<OperationId>) {
        for op_id in ops.into_iter() {
            let op = self.operations.take(op_id).unwrap();

            let results = self.results.clone();
            let job_queue = self.job_queue.clone();
            let network_outbound = self.network_outbound.clone();
            self.pool.spawn(move || Self::compute_result(op, results, job_queue, network_outbound));
        }
    }

    /// Compute the result of an operation, assumed to be done in a separate
    /// thread that will re-enqueue the result with the coordinator
    fn compute_result(
        op: Operation<C>,
        result_buffer: ParallelResultBuffer<C>,
        job_queue: ExecutorJobQueue<C>,
        network_sender: KanalSender<NetworkOutbound<C>>,
    ) {
        let result_ids = op.result_ids();

        // Collect the inputs to the operation
        let args = op.args.into_iter().map(|arg| result_buffer.get(arg).unwrap().clone());
        let input = Box::new(args);

        let results = match op.op_type {
            OperationType::Gate { function } => {
                let value = (function)(input);
                vec![OpResult { id: op.result_id, value }]
            },

            OperationType::GateBatch { function } => {
                let output = (function)(input);
                result_ids
                    .into_iter()
                    .zip(output)
                    .map(|(id, value)| OpResult { id, value })
                    .collect()
            },

            OperationType::Network { function } => {
                // Derive a network payload from the gate inputs and forward it to the outbound
                // buffer
                let result_id = result_ids[0];
                let payload = (function)(input);
                let outbound = NetworkOutbound { result_id, payload: payload.clone() };

                network_sender.send(outbound).expect("error sending network payload");

                // On a `send`, the local party receives a copy of the value placed as the
                // result of the network operation, so we must re-enqueue the
                // result
                vec![OpResult { id: result_id, value: payload.into() }]
            },
        };

        // Place the results in the result buffer
        let mut ids = Vec::with_capacity(results.len());
        for result in results.into_iter() {
            let id = result.id;

            ids.push(id);
            result_buffer.set(id, result.value);
        }

        // Notify the coordinator that the results are ready
        job_queue.push(ExecutorMessage::ResultsReady(ids));
    }

    /// Wake all the waiters for a given result
    pub fn wake_waiters_on_result(&mut self, result_id: ResultId) {
        // Wake all tasks awaiting this result
        if let Some(waiters) = self.waiters.get(&result_id) {
            let result = self.results.get(result_id).unwrap();
            for waiter in waiters {
                // Place the result in the waiter's buffer and wake up the waiting thread
                let mut buffer = waiter.result_buffer.write().expect(ERR_RESULT_BUFFER_POISONED);

                *buffer = result.clone();
                waiter.waker.wake_by_ref();
            }
        }
    }
}
