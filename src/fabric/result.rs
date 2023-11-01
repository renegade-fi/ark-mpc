//! Defines the abstractions over the result of an MPC operation, this can be a
//! network operation, a simple local computation, or a more complex operation
//! like a Beaver multiplication

use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll, Waker},
};

use ark_ec::CurveGroup;
use futures::Future;

use crate::{
    algebra::{CurvePoint, Scalar},
    network::NetworkPayload,
    Shared,
};

use super::MpcFabric;

/// Error message when a result buffer lock is poisoned
pub(crate) const ERR_RESULT_BUFFER_POISONED: &str = "result buffer lock poisoned";

// ---------------------
// | Result Value Type |
// ---------------------

/// An identifier for a result
pub type ResultId = usize;

/// The result of an MPC operation
#[derive(Clone, Debug)]
pub struct OpResult<C: CurveGroup> {
    /// The ID of the result's output
    pub id: ResultId,
    /// The result's value
    pub value: ResultValue<C>,
}

/// The value of a result
#[derive(Clone)]
pub enum ResultValue<C: CurveGroup> {
    /// A byte value
    Bytes(Vec<u8>),
    /// A scalar value
    Scalar(Scalar<C>),
    /// A batch of scalars
    ScalarBatch(Vec<Scalar<C>>),
    /// A point on the curve
    Point(CurvePoint<C>),
    /// A batch of points on the curve
    PointBatch(Vec<CurvePoint<C>>),
}

impl<C: CurveGroup> Debug for ResultValue<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ResultValue::Bytes(bytes) => f.debug_tuple("Bytes").field(bytes).finish(),
            ResultValue::Scalar(scalar) => f.debug_tuple("Scalar").field(scalar).finish(),
            ResultValue::ScalarBatch(scalars) => {
                f.debug_tuple("ScalarBatch").field(scalars).finish()
            },
            ResultValue::Point(point) => f.debug_tuple("Point").field(point).finish(),
            ResultValue::PointBatch(points) => f.debug_tuple("PointBatch").field(points).finish(),
        }
    }
}

impl<C: CurveGroup> From<NetworkPayload<C>> for ResultValue<C> {
    fn from(value: NetworkPayload<C>) -> Self {
        match value {
            NetworkPayload::Bytes(bytes) => ResultValue::Bytes(bytes),
            NetworkPayload::Scalar(scalar) => ResultValue::Scalar(scalar),
            NetworkPayload::ScalarBatch(scalars) => ResultValue::ScalarBatch(scalars),
            NetworkPayload::Point(point) => ResultValue::Point(point),
            NetworkPayload::PointBatch(points) => ResultValue::PointBatch(points),
        }
    }
}

impl<C: CurveGroup> From<ResultValue<C>> for NetworkPayload<C> {
    fn from(value: ResultValue<C>) -> Self {
        match value {
            ResultValue::Bytes(bytes) => NetworkPayload::Bytes(bytes),
            ResultValue::Scalar(scalar) => NetworkPayload::Scalar(scalar),
            ResultValue::ScalarBatch(scalars) => NetworkPayload::ScalarBatch(scalars),
            ResultValue::Point(point) => NetworkPayload::Point(point),
            ResultValue::PointBatch(points) => NetworkPayload::PointBatch(points),
        }
    }
}

// -- Coercive Casts to Concrete Types -- //
impl<C: CurveGroup> From<ResultValue<C>> for Vec<u8> {
    fn from(value: ResultValue<C>) -> Self {
        match value {
            ResultValue::Bytes(bytes) => bytes,
            _ => panic!("Cannot cast {:?} to bytes", value),
        }
    }
}

impl<C: CurveGroup> From<ResultValue<C>> for Scalar<C> {
    fn from(value: ResultValue<C>) -> Self {
        match value {
            ResultValue::Scalar(scalar) => scalar,
            _ => panic!("Cannot cast {:?} to scalar", value),
        }
    }
}

impl<C: CurveGroup> From<&ResultValue<C>> for Scalar<C> {
    fn from(value: &ResultValue<C>) -> Self {
        match value {
            ResultValue::Scalar(scalar) => *scalar,
            _ => panic!("Cannot cast {:?} to scalar", value),
        }
    }
}

impl<C: CurveGroup> From<ResultValue<C>> for Vec<Scalar<C>> {
    fn from(value: ResultValue<C>) -> Self {
        match value {
            ResultValue::ScalarBatch(scalars) => scalars,
            _ => panic!("Cannot cast {:?} to scalar batch", value),
        }
    }
}

impl<C: CurveGroup> From<ResultValue<C>> for CurvePoint<C> {
    fn from(value: ResultValue<C>) -> Self {
        match value {
            ResultValue::Point(point) => point,
            _ => panic!("Cannot cast {:?} to point", value),
        }
    }
}

impl<C: CurveGroup> From<&ResultValue<C>> for CurvePoint<C> {
    fn from(value: &ResultValue<C>) -> Self {
        match value {
            ResultValue::Point(point) => *point,
            _ => panic!("Cannot cast {:?} to point", value),
        }
    }
}

impl<C: CurveGroup> From<ResultValue<C>> for Vec<CurvePoint<C>> {
    fn from(value: ResultValue<C>) -> Self {
        match value {
            ResultValue::PointBatch(points) => points,
            _ => panic!("Cannot cast {:?} to point batch", value),
        }
    }
}

// ---------------
// | Handle Type |
// ---------------

/// A handle to the result of the execution of an MPC computation graph
///
/// This handle acts as a pointer to a possible incomplete partial result, and
/// `await`-ing it will block the task until the graph has evaluated up to that
/// point
///
/// This allows for construction of the graph concurrently with execution,
/// giving the fabric the opportunity to schedule all results onto the network
/// optimistically
#[derive(Clone, Debug)]
pub struct ResultHandle<C: CurveGroup, T: From<ResultValue<C>>> {
    /// The id of the result
    pub(crate) id: ResultId,
    /// The buffer that the result will be written to when it becomes available
    pub(crate) result_buffer: Shared<Option<ResultValue<C>>>,
    /// The underlying fabric
    pub(crate) fabric: MpcFabric<C>,
    /// A phantom for the type of the result
    phantom: PhantomData<T>,
}

impl<C: CurveGroup, T: From<ResultValue<C>>> ResultHandle<C, T> {
    /// Get the id of the result
    pub fn id(&self) -> ResultId {
        self.id
    }

    /// Borrow the fabric that this result is allocated within
    pub fn fabric(&self) -> &MpcFabric<C> {
        &self.fabric
    }
}

impl<C: CurveGroup, T: From<ResultValue<C>>> ResultHandle<C, T> {
    /// Constructor
    pub(crate) fn new(id: ResultId, fabric: MpcFabric<C>) -> Self {
        Self {
            id,
            result_buffer: Arc::new(RwLock::new(None)),
            fabric,
            phantom: PhantomData,
        }
    }

    /// Get the ids that this result represents, awaiting these IDs is awaiting
    /// this result
    pub fn op_ids(&self) -> Vec<ResultId> {
        vec![self.id]
    }
}

/// A struct describing an async task that is waiting on a result
pub struct ResultWaiter<C: CurveGroup> {
    /// The id of the result that the task is waiting on
    pub result_id: ResultId,
    /// The buffer that the result will be written to when it becomes available
    pub result_buffer: Shared<Option<ResultValue<C>>>,
    /// The waker of the task
    pub waker: Waker,
}

impl<C: CurveGroup> Debug for ResultWaiter<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("ResultWaiter")
            .field("id", &self.result_id)
            .finish()
    }
}

impl<C: CurveGroup, T: From<ResultValue<C>> + Debug> Future for ResultHandle<C, T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Lock the result buffer
        let locked_result = self.result_buffer.read().expect(ERR_RESULT_BUFFER_POISONED);

        // If the result is ready, return it, otherwise register the current context's
        // waker with the `Executor`
        match locked_result.clone() {
            Some(res) => Poll::Ready(res.into()),
            None => {
                let waiter = ResultWaiter {
                    result_id: self.id,
                    result_buffer: self.result_buffer.clone(),
                    waker: cx.waker().clone(),
                };

                self.fabric.register_waiter(waiter);
                Poll::Pending
            },
        }
    }
}
