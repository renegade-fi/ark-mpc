//! Executor implementations

use std::sync::Arc;

use ark_ec::CurveGroup;
use crossbeam::queue::SegQueue;

use super::result::{OpResult, ResultWaiter};
use crate::fabric::Operation;
#[cfg(feature = "multithreaded_executor")]
use crate::fabric::ResultId;

pub(crate) mod buffer;
#[cfg(feature = "multithreaded_executor")]
pub mod multi_threaded;
pub mod single_threaded;

#[cfg(feature = "benchmarks")]
pub use buffer::*;

/// The default number of operations to pre-allocate
const DEFAULT_N_OPS: usize = 1000;
/// The default number of results to pre-allocate
const DEFAULT_N_RESULTS: usize = 10_000;

/// The job queue that the executor may receive messages on
#[allow(type_alias_bounds)]
pub type ExecutorJobQueue<C: CurveGroup> = Arc<SegQueue<ExecutorMessage<C>>>;

/// The type that the `Executor` receives on its channel, this may either be:
/// - A result of an operation, for which th executor will check the dependency
///   map and
///  execute any operations that are now ready
/// - An operation directly, which the executor will execute immediately if all
///   of its
///  arguments are ready
/// - A new waiter for a result, which the executor will add to its waiter map
#[derive(Debug)]
pub enum ExecutorMessage<C: CurveGroup> {
    /// A result of an operation
    Result(OpResult<C>),
    /// A batch of results
    ResultBatch(Vec<OpResult<C>>),
    /// A batch of results are ready in the result buffer, this message does not
    /// contain the results themselves
    #[cfg(feature = "multithreaded_executor")]
    ResultsReady(Vec<ResultId>),
    /// An operation that is ready for
    /// execution
    Op(Operation<C>),
    /// A new waiter has registered itself for a result
    NewWaiter(ResultWaiter<C>),
    /// Indicates that the executor should shut down
    Shutdown,
}

/// Size hints given to an executor to pre-allocate buffer space
#[derive(Debug, Clone, Copy)]
pub struct ExecutorSizeHints {
    /// The number of operations that will be executed
    pub n_ops: usize,
    /// The number of results that will be produced
    pub n_results: usize,
}

impl Default for ExecutorSizeHints {
    fn default() -> Self {
        Self { n_ops: DEFAULT_N_OPS, n_results: DEFAULT_N_RESULTS }
    }
}
