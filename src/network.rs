//! The `network` module defines abstractions of the transport used to
//! communicate during the course of an MPC
mod cert_verifier;
mod config;
mod mock;

#[cfg(any(feature = "test_helpers", test))]
pub use mock::{NoRecvNetwork, UnboundedDuplexStream, MockNetwork};

use async_trait::async_trait;
use quinn::{Endpoint, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::{convert::TryInto, net::SocketAddr};
use tracing::log;

use crate::{
    algebra::{scalar::Scalar, stark_curve::StarkPoint},
    error::{MpcNetworkError, SetupError},
    fabric::ResultId,
    PARTY0,
};

/// A type alias of the id of a party in an MPC for readability
pub type PartyId = u64;
/// The number of bytes in a u64
const BYTES_PER_U64: usize = 8;

/// Error message emitted when reading a message length from the stream fails
const ERR_READ_MESSAGE_LENGTH: &str = "error reading message length from stream";

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
pub trait MpcNetwork: Send {
    /// Get the party ID of the local party in the MPC
    fn party_id(&self) -> PartyId;
    /// Send an outbound MPC message
    async fn send_message(&mut self, message: NetworkOutbound) -> Result<(), MpcNetworkError>;
    /// Receive an inbound message
    async fn receive_message(&mut self) -> Result<NetworkOutbound, MpcNetworkError>;
    /// Each peer sends a message to the other
    async fn exchange_messages(
        &mut self,
        message: NetworkOutbound,
    ) -> Result<NetworkOutbound, MpcNetworkError>;
    /// Closes the connections opened in the handshake phase
    async fn close(&mut self) -> Result<(), MpcNetworkError>;
}

// ------------------
// | Implementation |
// ------------------

/// The order in which the local party should read when exchanging values
#[derive(Clone, Debug)]
pub enum ReadWriteOrder {
    /// The local party reads before writing in a swap operation
    ReadFirst,
    /// The local party writes before reading in a swap operation
    WriteFirst,
}

/// Implements an MpcNetwork on top of QUIC
#[derive(Debug)]
pub struct QuicTwoPartyNet {
    /// The index of the local party in the participants
    party_id: PartyId,
    /// Whether the network has been bootstrapped yet
    connected: bool,
    /// The address of the local peer
    local_addr: SocketAddr,
    /// Addresses of the counterparties in the MPC
    peer_addr: SocketAddr,
    /// The send side of the bidirectional stream
    send_stream: Option<SendStream>,
    /// The receive side of the bidirectional stream
    recv_stream: Option<RecvStream>,
}

#[allow(clippy::redundant_closure)] // For readability of error handling
impl<'a> QuicTwoPartyNet {
    /// Create a new network, do not connect the network yet
    pub fn new(party_id: PartyId, local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
        // Construct the QUIC net
        Self {
            party_id,
            local_addr,
            peer_addr,
            connected: false,
            send_stream: None,
            recv_stream: None,
        }
    }

    /// Returns true if the local party is party 0
    fn local_party0(&self) -> bool {
        self.party_id() == PARTY0
    }

    /// Returns the read order for the local peer; king is write first
    fn read_order(&self) -> ReadWriteOrder {
        if self.local_party0() {
            ReadWriteOrder::WriteFirst
        } else {
            ReadWriteOrder::ReadFirst
        }
    }

    /// Returns an error if the network is not connected
    fn assert_connected(&self) -> Result<(), MpcNetworkError> {
        if self.connected {
            Ok(())
        } else {
            Err(MpcNetworkError::NetworkUninitialized)
        }
    }

    /// Establishes connections to the peer
    pub async fn connect(&mut self) -> Result<(), MpcNetworkError> {
        // Build the client and server configs
        let (client_config, server_config) =
            config::build_configs().map_err(|err| MpcNetworkError::ConnectionSetupError(err))?;

        // Create a quinn server
        let mut local_endpoint = Endpoint::server(server_config, self.local_addr).map_err(|e| {
            log::error!("error setting up quinn server: {e:?}");
            MpcNetworkError::ConnectionSetupError(SetupError::ServerSetupError)
        })?;
        local_endpoint.set_default_client_config(client_config);

        // The king dials the peer who awaits connection
        let connection = {
            if self.local_party0() {
                local_endpoint
                    .connect(self.peer_addr, config::SERVER_NAME)
                    .map_err(|err| {
                        log::error!("error setting up quic endpoint connection: {err}");
                        MpcNetworkError::ConnectionSetupError(SetupError::ConnectError(err))
                    })?
                    .await
                    .map_err(|err| {
                        log::error!("error connecting to the remote quic endpoint: {err}");
                        MpcNetworkError::ConnectionSetupError(SetupError::ConnectionError(err))
                    })?
            } else {
                local_endpoint
                    .accept()
                    .await
                    .ok_or_else(|| {
                        log::error!("no incoming connection while awaiting quic endpoint");
                        MpcNetworkError::ConnectionSetupError(SetupError::NoIncomingConnection)
                    })?
                    .await
                    .map_err(|err| {
                        log::error!("error while establishing remote connection as listener");
                        MpcNetworkError::ConnectionSetupError(SetupError::ConnectionError(err))
                    })?
            }
        };

        // King opens a bidirectional stream on top of the connection
        let (send, recv) = {
            if self.local_party0() {
                connection.open_bi().await.map_err(|err| {
                    log::error!("error opening bidirectional stream: {err}");
                    MpcNetworkError::ConnectionSetupError(SetupError::ConnectionError(err))
                })?
            } else {
                connection.accept_bi().await.map_err(|err| {
                    log::error!("error accepting bidirectional stream: {err}");
                    MpcNetworkError::ConnectionSetupError(SetupError::ConnectionError(err))
                })?
            }
        };

        // Update MpcNet state
        self.connected = true;
        self.send_stream = Some(send);
        self.recv_stream = Some(recv);

        Ok(())
    }

    /// Read a message length from the stream
    async fn read_message_length(&mut self) -> Result<u64, MpcNetworkError> {
        let mut read_buffer = vec![0u8; BYTES_PER_U64];
        self.recv_stream
            .as_mut()
            .unwrap()
            .read_exact(&mut read_buffer)
            .await
            .map_err(|e| MpcNetworkError::RecvError(e.to_string()))?;

        Ok(u64::from_le_bytes(read_buffer.try_into().map_err(
            |_| MpcNetworkError::SerializationError(ERR_READ_MESSAGE_LENGTH.to_string()),
        )?))
    }

    /// Write a stream of bytes to the stream
    async fn write_bytes(&mut self, payload: &[u8]) -> Result<(), MpcNetworkError> {
        self.send_stream
            .as_mut()
            .unwrap()
            .write_all(payload)
            .await
            .map_err(|e| MpcNetworkError::SendError(e.to_string()))
    }

    /// Read exactly `n` bytes from the stream
    async fn read_bytes(&mut self, num_bytes: usize) -> Result<Vec<u8>, MpcNetworkError> {
        let mut read_buffer = vec![0u8; num_bytes];
        self.recv_stream
            .as_mut()
            .unwrap()
            .read_exact(&mut read_buffer)
            .await
            .map_err(|e| MpcNetworkError::RecvError(e.to_string()))?;

        Ok(read_buffer.to_vec())
    }
}

#[async_trait]
impl MpcNetwork for QuicTwoPartyNet {
    fn party_id(&self) -> PartyId {
        self.party_id
    }

    async fn send_message(&mut self, message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        // Serialize the message and forward it onto the network
        let bytes = serde_json::to_vec(&message)
            .map_err(|err| MpcNetworkError::SerializationError(err.to_string()))?;
        let mut payload = (bytes.len() as u64).to_le_bytes().to_vec();
        payload.extend_from_slice(&bytes);

        self.write_bytes(&payload).await
    }

    async fn receive_message(&mut self) -> Result<NetworkOutbound, MpcNetworkError> {
        // Read the message length from the buffer
        let len = self.read_message_length().await?;
        let bytes = self.read_bytes(len as usize).await?;

        // Deserialize the message
        serde_json::from_slice(&bytes)
            .map_err(|err| MpcNetworkError::SerializationError(err.to_string()))
    }

    async fn exchange_messages(
        &mut self,
        message: NetworkOutbound,
    ) -> Result<NetworkOutbound, MpcNetworkError> {
        match self.read_order() {
            ReadWriteOrder::ReadFirst => {
                let msg = self.receive_message().await?;
                self.send_message(message).await?;
                Ok(msg)
            }
            ReadWriteOrder::WriteFirst => {
                self.send_message(message).await?;
                self.receive_message().await
            }
        }
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        self.assert_connected()?;

        self.send_stream
            .as_mut()
            .unwrap()
            .finish()
            .await
            .map_err(|_| MpcNetworkError::ConnectionTeardownError)
    }
}
