//! Defines the abstractions over the result of an MPC operation, this can be a network
//! operation, a simple local computation, or a more complex operation like a
//! Beaver multiplication

use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use futures::Future;
use serde::{Deserialize, Serialize};

use crate::beaver::SharedValueSource;

use super::FabricInner;

/// An identifier for a result
pub type ResultId = usize;

/// The result of an MPC operation
#[derive(Clone, Debug)]
pub struct OpResult {
    /// The ID of the result's output
    pub id: ResultId,
    /// The result's value
    pub value: ResultValue,
}

/// The value of a result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ResultValue {
    /// A byte value
    Bytes(Vec<u8>),
    /// A scalar value
    Scalar(Scalar),
    /// A point on the curve
    Point(RistrettoPoint),
}

// -- Coercive Casts to Concrete Types -- //
impl From<ResultValue> for Vec<u8> {
    fn from(value: ResultValue) -> Self {
        match value {
            ResultValue::Bytes(bytes) => bytes,
            _ => panic!("Cannot cast {:?} to bytes", value),
        }
    }
}

impl From<ResultValue> for Scalar {
    fn from(value: ResultValue) -> Self {
        match value {
            ResultValue::Scalar(scalar) => scalar,
            _ => panic!("Cannot cast {:?} to scalar", value),
        }
    }
}

impl From<ResultValue> for RistrettoPoint {
    fn from(value: ResultValue) -> Self {
        match value {
            ResultValue::Point(point) => point,
            _ => panic!("Cannot cast {:?} to point", value),
        }
    }
}

// ---------------
// | Handle Type |
// ---------------

/// A handle to the result of the execution of an MPC computation graph
///
/// This handle acts as a pointer to a possible incomplete partial result, and
/// `await`-ing it will block the task until the graph has evaluated up to that point
///
/// This allows for construction of the graph concurrently with execution, giving the
/// fabric the opportunity to schedule all results onto the network optimistically
pub struct ResultHandle<T: From<ResultValue>, S: SharedValueSource> {
    /// The id of the result
    pub(crate) id: ResultId,
    /// The underlying fabric
    pub(crate) fabric: FabricInner<S>,
    /// A phantom for the type of the result
    phantom: PhantomData<T>,
}

impl<T: From<ResultValue>, S: SharedValueSource> ResultHandle<T, S> {
    /// Constructor
    pub(crate) fn new(id: ResultId, fabric: FabricInner<S>) -> Self {
        Self {
            id,
            fabric,
            phantom: PhantomData,
        }
    }
}

impl<T: From<ResultValue>, S: SharedValueSource> Future for ResultHandle<T, S> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let locked_results = self.fabric.results.read().expect("results poisoned");
        let mut locked_wakers = self.fabric.wakers.write().expect("wakers poisoned");

        match locked_results.get(&self.id) {
            Some(res) => Poll::Ready(res.value.clone().into()),
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
