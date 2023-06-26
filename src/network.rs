//! The `network` module defines abstractions of the transport used to
//! communicate during the course of an MPC
mod cert_verifier;
mod config;
pub mod dummy_network;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use quinn::{Endpoint, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::{convert::TryInto, net::SocketAddr};
use tracing::log;

use crate::{
    error::{MpcNetworkError, SetupError},
    PARTY0,
};

pub type PartyId = u64;

const BYTES_PER_POINT: usize = 32;
const BYTES_PER_SCALAR: usize = 32;
const BYTES_PER_U64: usize = 8;

/// Error message emitted when reading a message length from the stream fails
const ERR_READ_MESSAGE_LENGTH: &str = "error reading message length from stream";
/// Error deserializing a `Scalar` from a message
const ERR_READING_SCALAR: &str = "error deserializing scalars from message";
/// Error deserializing a curve point from a message
const ERR_READING_POINT: &str = "error reading points from message";

// -----------
// | Helpers |
// -----------

/// Convert a vector of scalars to a byte buffer
fn scalars_to_bytes(scalars: &[Scalar]) -> Bytes {
    let mut payload = BytesMut::new();
    scalars.iter().for_each(|scalar| {
        let bytes = scalar.to_bytes();
        payload.extend_from_slice(&bytes);
    });

    payload.freeze()
}

/// Convert a byte buffer back to a vector of scalars
fn bytes_to_scalars(bytes: &[u8]) -> Result<Vec<Scalar>, MpcNetworkError> {
    bytes
        .chunks(BYTES_PER_SCALAR)
        .map(|bytes_chunk| {
            Scalar::from_canonical_bytes(
                bytes_chunk
                    .try_into()
                    .expect("unexpected number of bytes per chunk"),
            )
            .ok_or(MpcNetworkError::SerializationError(
                ERR_READING_SCALAR.to_string(),
            ))
        })
        .collect::<Result<Vec<Scalar>, MpcNetworkError>>()
}

/// Convert a vector of Ristretto points to bytes
fn points_to_bytes(points: &[RistrettoPoint]) -> Bytes {
    // Map to bytes
    let mut payload = BytesMut::new();
    points.iter().for_each(|point| {
        let bytes = point.compress().to_bytes();
        payload.extend_from_slice(&bytes);
    });

    payload.freeze()
}

/// Convert a byte buffer back to a vector of points
fn bytes_to_points(bytes: &[u8]) -> Result<Vec<RistrettoPoint>, MpcNetworkError> {
    bytes
        .chunks(BYTES_PER_POINT)
        .map(|bytes_chunk| {
            CompressedRistretto(
                bytes_chunk
                    .try_into()
                    .expect("unexpected number of bytes per chunk"),
            )
            .decompress()
            .ok_or(MpcNetworkError::SerializationError(
                ERR_READING_POINT.to_string(),
            ))
        })
        .collect::<Result<Vec<RistrettoPoint>, MpcNetworkError>>()
}

// ---------
// | Trait |
// ---------

/// The type that the network sender receives
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum NetworkOutbound {
    /// Raw bytes sent over the network
    Bytes(Vec<u8>),
    /// Scalars to be sent over the network
    Scalars(Vec<Scalar>),
    /// Curve points to be sent over the network
    Points(Vec<RistrettoPoint>),
}

/// The `MpcNetwork` trait defines shared functionality for a network implementing a
/// connection between two parties in a 2PC
///
/// Values are sent as bytes, scalars, or curve points and always in batch form with the
/// message length (measured in the number of elements sent) prepended to the message
#[async_trait]
pub trait MpcNetwork {
    /// Send an outbound MPC message
    async fn send_message(&mut self, message: NetworkOutbound) -> Result<(), MpcNetworkError>;
    /// Receive an inbound message
    async fn receive_message(&mut self) -> Result<NetworkOutbound, MpcNetworkError>;
    /// Closes the connections opened in the handshake phase
    async fn close(&mut self) -> Result<(), MpcNetworkError>;
}

// ------------------
// | Implementation |
// ------------------

/// The order in which the local party should read when exchanging values
#[derive(Clone, Debug)]
pub enum ReadWriteOrder {
    ReadFirst,
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
        self.party_id == PARTY0
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
            .map_err(|_| MpcNetworkError::RecvError)?;

        Ok(u64::from_le_bytes(read_buffer.try_into().map_err(
            |err| MpcNetworkError::SerializationError(ERR_READ_MESSAGE_LENGTH.to_string()),
        )?))
    }

    /// Write a stream of bytes to the stream
    async fn write_bytes(&mut self, payload: &[u8]) -> Result<(), MpcNetworkError> {
        self.send_stream
            .as_mut()
            .unwrap()
            .write_all(payload)
            .await
            .map_err(|_| MpcNetworkError::SendError)
    }

    /// Read exactly `n` bytes from the stream
    async fn read_bytes(&mut self, num_bytes: usize) -> Result<Vec<u8>, MpcNetworkError> {
        let mut read_buffer = vec![0u8; num_bytes as usize];
        self.recv_stream
            .as_mut()
            .unwrap()
            .read_exact(&mut read_buffer)
            .await
            .map_err(|_| MpcNetworkError::RecvError)?;

        Ok(read_buffer.to_vec())
    }
}

#[async_trait]
impl MpcNetwork for QuicTwoPartyNet {
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
