//! The `network` module defines abstractions of the transport used to
//! communicate during the course of an MPC
mod cert_verifier;
mod config;
mod mock;
mod quic;
mod stream_buffer;

pub use quic::*;

use futures::{Sink, Stream};
#[cfg(any(feature = "test_helpers", feature = "benchmarks", test))]
pub use mock::{MockNetwork, NoRecvNetwork, UnboundedDuplexStream};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    algebra::{scalar::Scalar, stark_curve::StarkPoint},
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
pub struct NetworkOutbound {
    /// The operation ID that generated this message
    pub result_id: ResultId,
    /// The body of the message
    pub payload: NetworkPayload,
}

/// The payload of an outbound message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetworkPayload {
    /// A byte value
    Bytes(Vec<u8>),
    /// A scalar value
    Scalar(Scalar),
    /// A batch of scalar values
    ScalarBatch(Vec<Scalar>),
    /// A point on the curve
    Point(StarkPoint),
    /// A batch of points on the curve
    PointBatch(Vec<StarkPoint>),
}

impl From<Vec<u8>> for NetworkPayload {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Bytes(bytes)
    }
}

impl From<Scalar> for NetworkPayload {
    fn from(scalar: Scalar) -> Self {
        Self::Scalar(scalar)
    }
}

impl From<Vec<Scalar>> for NetworkPayload {
    fn from(scalars: Vec<Scalar>) -> Self {
        Self::ScalarBatch(scalars)
    }
}

impl From<StarkPoint> for NetworkPayload {
    fn from(point: StarkPoint) -> Self {
        Self::Point(point)
    }
}

impl From<Vec<StarkPoint>> for NetworkPayload {
    fn from(value: Vec<StarkPoint>) -> Self {
        Self::PointBatch(value)
    }
}

/// The `MpcNetwork` trait defines shared functionality for a network implementing a
/// connection between two parties in a 2PC
///
/// Values are sent as bytes, scalars, or curve points and always in batch form with the
/// message length (measured in the number of elements sent) prepended to the message
#[async_trait]
pub trait MpcNetwork:
    Send
    + Stream<Item = Result<NetworkOutbound, MpcNetworkError>>
    + Sink<NetworkOutbound, Error = MpcNetworkError>
{
    /// Get the party ID of the local party in the MPC
    fn party_id(&self) -> PartyId;
    /// Closes the connections opened in the handshake phase
    async fn close(&mut self) -> Result<(), MpcNetworkError>;
}

// -----------
// | Helpers |
// -----------
