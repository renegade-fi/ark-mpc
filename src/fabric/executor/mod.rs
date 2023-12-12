//! Executor implementations

use ark_ec::CurveGroup;

use crate::fabric::Operation;

use super::result::{OpResult, ResultWaiter};

pub mod single_threaded;

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
    /// An operation that is ready for execution
    Op(Operation<C>),
    /// A new waiter has registered itself for a result
    NewWaiter(ResultWaiter<C>),
    /// Indicates that the executor should shut down
    Shutdown,
}
