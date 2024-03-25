//! The `network` module defines abstractions of the transport used to
//! communicate during the course of an MPC
mod cert_verifier;
mod config;
mod mock;
mod quic;
mod stream_buffer;

use ark_ec::CurveGroup;
pub use quic::*;

use futures::{Sink, Stream};
#[cfg(any(feature = "test_helpers", feature = "benchmarks", test))]
pub use mock::{MockNetwork, NoRecvNetwork, UnboundedDuplexStream};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    algebra::{CurvePoint, Scalar},
    error::MpcNetworkError,
    fabric::ResultId,
};

/// A type alias of the id of a party in an MPC for readability
pub type PartyId = u64;

// ---------
// | Trait |
// ---------

/// The type that the network sender receives
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C: CurveGroup")]
pub struct NetworkOutbound<C: CurveGroup> {
    /// The operation ID that generated this message
    pub result_id: ResultId,
    /// The body of the message
    pub payload: NetworkPayload<C>,
}

/// The payload of an outbound message
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "C: CurveGroup", deserialize = "C: CurveGroup"))]
pub enum NetworkPayload<C: CurveGroup> {
    /// A byte value
    Bytes(Vec<u8>),
    /// A scalar value
    Scalar(Scalar<C>),
    /// A batch of scalar values
    ScalarBatch(Vec<Scalar<C>>),
    /// A point on the curve
    Point(CurvePoint<C>),
    /// A batch of points on the curve
    PointBatch(Vec<CurvePoint<C>>),
}

// ---------------
// | Conversions |
// ---------------

impl<C: CurveGroup> From<Vec<u8>> for NetworkPayload<C> {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Bytes(bytes)
    }
}

impl<C: CurveGroup> From<Scalar<C>> for NetworkPayload<C> {
    fn from(scalar: Scalar<C>) -> Self {
        Self::Scalar(scalar)
    }
}

impl<C: CurveGroup> From<Vec<Scalar<C>>> for NetworkPayload<C> {
    fn from(scalars: Vec<Scalar<C>>) -> Self {
        Self::ScalarBatch(scalars)
    }
}

impl<C: CurveGroup> From<CurvePoint<C>> for NetworkPayload<C> {
    fn from(point: CurvePoint<C>) -> Self {
        Self::Point(point)
    }
}

impl<C: CurveGroup> From<Vec<CurvePoint<C>>> for NetworkPayload<C> {
    fn from(value: Vec<CurvePoint<C>>) -> Self {
        Self::PointBatch(value)
    }
}

/// The `MpcNetwork` trait defines shared functionality for a network
/// implementing a connection between two parties in a 2PC
///
/// Values are sent as bytes, scalars, or curve points and always in batch form
/// with the message length (measured in the number of elements sent) prepended
/// to the message
#[async_trait]
pub trait MpcNetwork<C: CurveGroup>:
    Send
    + Stream<Item = Result<NetworkOutbound<C>, MpcNetworkError>>
    + Sink<NetworkOutbound<C>, Error = MpcNetworkError>
{
    /// Get the party ID of the local party in the MPC
    fn party_id(&self) -> PartyId;
    /// Closes the connections opened in the handshake phase
    async fn close(&mut self) -> Result<(), MpcNetworkError>;
}
