//! Defines the abstractions over the result of an MPC operation, this can be a network
//! operation, a simple local computation, or a more complex operation like a
//! Beaver multiplication

use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use futures::Future;
use itertools::Itertools;

use crate::{
    algebra::{
        mpc_scalar::MpcScalar,
        stark_curve::{Scalar, StarkPoint},
    },
    network::NetworkPayload,
};

use super::MpcFabric;

// -----------
// | Helpers |
// -----------

/// A helper to cast the args in a vector to an array for destructuring
pub(crate) fn cast_args<const N: usize, T: From<ResultValue>>(args: Vec<ResultValue>) -> [T; N] {
    assert_eq!(args.len(), N, "wrong number of args");
    args.into_iter()
        .map(|arg| arg.into())
        .collect_vec()
        .try_into()
        .map_err(|_| "wrong number of args")
        .unwrap()
}

// ---------------------
// | Result Value Type |
// ---------------------

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
#[derive(Clone, Debug)]
pub enum ResultValue {
    /// A byte value
    Bytes(Vec<u8>),
    /// A scalar value
    Scalar(Scalar),
    /// A point on the curve
    Point(StarkPoint),
    /// An MPC scalar value
    MpcScalar(MpcScalar),
}

impl From<NetworkPayload> for ResultValue {
    fn from(value: NetworkPayload) -> Self {
        match value {
            NetworkPayload::Bytes(bytes) => ResultValue::Bytes(bytes),
            NetworkPayload::Scalar(scalar) => ResultValue::Scalar(scalar),
            NetworkPayload::Point(point) => ResultValue::Point(point),
        }
    }
}

impl From<ResultValue> for NetworkPayload {
    fn from(value: ResultValue) -> Self {
        match value {
            ResultValue::Bytes(bytes) => NetworkPayload::Bytes(bytes),
            ResultValue::Scalar(scalar) => NetworkPayload::Scalar(scalar),
            ResultValue::Point(point) => NetworkPayload::Point(point),
            _ => panic!("not a valid network payload type"),
        }
    }
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

impl From<ResultValue> for StarkPoint {
    fn from(value: ResultValue) -> Self {
        match value {
            ResultValue::Point(point) => point,
            _ => panic!("Cannot cast {:?} to point", value),
        }
    }
}

impl From<ResultValue> for MpcScalar {
    fn from(value: ResultValue) -> Self {
        match value {
            ResultValue::MpcScalar(scalar) => scalar,
            _ => panic!("Cannot cast {:?} to mpc scalar", value),
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
#[derive(Clone)]
pub struct ResultHandle<T: From<ResultValue>> {
    /// The id of the result
    pub(crate) id: ResultId,
    /// The underlying fabric
    pub(crate) fabric: MpcFabric,
    /// A phantom for the type of the result
    phantom: PhantomData<T>,
}

impl<T: From<ResultValue>> ResultHandle<T> {
    /// Constructor
    pub(crate) fn new(id: ResultId, fabric: MpcFabric) -> Self {
        Self {
            id,
            fabric,
            phantom: PhantomData,
        }
    }
}

impl<T: From<ResultValue>> Future for ResultHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let locked_results = self.fabric.inner.results.read().expect("results poisoned");
        let mut locked_wakers = self.fabric.inner.wakers.write().expect("wakers poisoned");

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
