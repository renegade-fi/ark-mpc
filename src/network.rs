//! The `network` module defines abstractions of the transport used to
//! communicate during the course of an MPC
mod cert_verifier;
mod config;
pub(crate) mod dummy_network;

use async_trait::async_trait;
use bytes::{BytesMut, Bytes};
use curve25519_dalek::{ristretto::{RistrettoPoint, CompressedRistretto}, scalar::Scalar};
use futures::StreamExt;
use std::{net::SocketAddr, convert::TryInto};
use quinn::{Endpoint, RecvStream, SendStream, NewConnection};

use crate::error::{MpcNetworkError, BroadcastError, SetupError};

pub type PartyId = u64;

const BYTES_PER_POINT: usize = 32;
const BYTES_PER_SCALAR: usize = 32;

/**
 * Helpers
 */

/// Convert a vector of scalars to a byte buffer
fn scalars_to_bytes(scalars: Vec<Scalar>) -> Bytes {
    let mut payload = BytesMut::new();
    scalars.iter()
        .for_each(|scalar| {
            let bytes = scalar.to_bytes();
            payload.extend_from_slice(&bytes);
        });

    payload.freeze()
}

/// Convert a byte buffer back to a vector of scalars
fn bytes_to_scalars(bytes: &[u8]) -> Result<Vec<Scalar>, MpcNetworkError> {
    bytes.chunks(BYTES_PER_SCALAR)
        .into_iter()
        .map(|bytes_chunk| {
            Scalar::from_canonical_bytes(
                bytes_chunk
                    .try_into()
                    .expect("unexpected number of bytes per chunk")
            )
                .ok_or(MpcNetworkError::SerializationError)
        })
        .collect::<Result<Vec<Scalar>, MpcNetworkError>>()
}

/// Convert a vector of Ristretto points to bytes
fn points_to_bytes(points: Vec<RistrettoPoint>) -> Bytes {
    // Map to bytes 
    let mut payload = BytesMut::new();
    points.iter()
        .for_each(|point| {
            let bytes = point.compress().to_bytes();
            payload.extend_from_slice(&bytes);
        });

    payload.freeze()
}

/// Convert a byte buffer back to a vector of points
fn bytes_to_points(bytes: &[u8]) -> Result<Vec<RistrettoPoint>, MpcNetworkError> {
    bytes.chunks(BYTES_PER_POINT)
        .into_iter()
        .map(|bytes_chunk| {
            CompressedRistretto(
                bytes_chunk
                .try_into()
                .expect("unexpected number of bytes per chunk")
            ).decompress()
            .ok_or(MpcNetworkError::SerializationError)
        })
        .collect::<Result<Vec<RistrettoPoint>, MpcNetworkError>>()
}

/// MpcNetwork represents the network functionality needed for 2PC execution
/// Note that only two party computation is implemented here
#[async_trait]
pub trait MpcNetwork {
    /// Returns the ID of the given party in the MPC computation
    fn party_id(&self) -> u64;
    /// Returns whether the local party is the king of the MPC (party 0)
    fn am_king(&self) -> bool { self.party_id() == 0 }
    /// The local party sends a vector of scalars to the peer
    async fn send_scalars(&mut self, scalars: Vec<Scalar>) -> Result<(), MpcNetworkError>;
    /// The local party sends a single scalar to the peer
    async fn send_single_scalar(&mut self, scalar: Scalar) -> Result<(), MpcNetworkError> {
        self.send_scalars(vec![scalar]).await
    }
    /// The local party receives exactly `n` scalars from the peer
    async fn receive_scalars(&mut self, num_expected: usize) -> Result<Vec<Scalar>, MpcNetworkError>;
    /// The local party receives a single scalar from the peer
    async fn receive_single_scalar(&mut self) -> Result<Scalar, MpcNetworkError> {
        Ok(
            self.receive_scalars(1).await?[0]
        )
    }
    /// Both parties broadcast a vector of scalars to one another
    async fn broadcast_scalars(&mut self, scalars: Vec<Scalar>) -> Result<Vec<Scalar>, MpcNetworkError>;
    /// Both parties broadcast a single scalar to one another
    async fn broadcast_single_scalar(&mut self, scalar: Scalar) -> Result<Scalar, MpcNetworkError> {
        Ok(
            self.broadcast_scalars(vec![scalar]).await?[0]
        )
    }
    /// Both parties broadcast a vector of points to one another
    async fn broadcast_points(&mut self, points: Vec<RistrettoPoint>) -> Result<Vec<RistrettoPoint>, MpcNetworkError>;
    /// Both parties broadcast a single point to one another
    async fn broadcast_single_point(&mut self, point: RistrettoPoint) -> Result<RistrettoPoint, MpcNetworkError> {
        Ok(
           self.broadcast_points(vec![point]).await?[0]
        )
    }
    /// Closes the connections opened in the handshake phase
    async fn close(&mut self) -> Result<(), MpcNetworkError>;
}  

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
    /// The receive side of the bidirecitonal stream
    recv_stream: Option<RecvStream>,
}

#[allow(clippy::redundant_closure)]  // For readability of error handling
impl QuicTwoPartyNet {
    pub fn new(
        party_id: PartyId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> Self {
        // Construct the QUIC net
        Self { party_id, local_addr, peer_addr, connected: false, send_stream: None, recv_stream: None }
    }

    /// Returns the read order for the local peer; king is write first
    fn read_order(&self) -> ReadWriteOrder {
        if self.am_king() { ReadWriteOrder::WriteFirst } else { ReadWriteOrder::ReadFirst }
    }

    /// Returns an error if the network is not connected
    fn assert_connected(&self) -> Result<(), MpcNetworkError> {
        if self.connected { Ok(()) } else { Err(MpcNetworkError::NetworkUninitialized) }
    }

    /// Establishes connections to the peer
    pub async fn connect(&mut self) -> Result<(), MpcNetworkError> {
        // Build the client and server configs
        let (client_config, server_config) = config::build_configs()
            .map_err( |err| MpcNetworkError::ConnectionSetupError(err) )?;

        // Create a quinn server
        let (mut local_node, mut incoming) = Endpoint::server(server_config, self.local_addr)
            .map_err( |_| MpcNetworkError::ConnectionSetupError(SetupError::ServerSetupError) )?;
        local_node.set_default_client_config(client_config);

        // The king dials the peer who awaits connection
        let NewConnection {
            connection,
            mut bi_streams,
            ..
        } = {
            if self.am_king() {
                local_node.connect(self.peer_addr, config::SERVER_NAME)
                    .map_err(|err| {
                        MpcNetworkError::ConnectionSetupError(SetupError::ConnectError(err))
                    })?
                    .await
                    .map_err(|err| {
                        MpcNetworkError::ConnectionSetupError(SetupError::ConnectionError(err)) 
                    })?
            } else {
                incoming.next()
                    .await
                    .ok_or(MpcNetworkError::ConnectionSetupError(SetupError::NoIncomingConnection))?
                    .await
                    .map_err(|err| {
                        MpcNetworkError::ConnectionSetupError(SetupError::ConnectionError(err))
                    })?
            }
        };

        // King opens a bidirectional stream on top of the connection
        let (send, recv) = {
            if self.am_king() {
                connection.open_bi()
                    .await
                    .map_err( |err| MpcNetworkError::ConnectionSetupError(SetupError::ConnectionError(err)) )?
            } else {
                bi_streams.next()
                    .await
                    .ok_or(MpcNetworkError::ConnectionSetupError(SetupError::NoIncomingConnection))?
                    .map_err( |err| MpcNetworkError::ConnectionSetupError(SetupError::ConnectionError(err)) )?
            }
        };
        
        // Update MpcNet state
        self.connected = true;
        self.send_stream = Some(send);
        self.recv_stream = Some(recv);

        Ok(())
    }

    /// Write a stream of bytes to the stream
    async fn write_bytes(&mut self, payload: &[u8]) -> Result<(), MpcNetworkError> {
        self.send_stream.as_mut()
            .unwrap()
            .write_all(payload)
            .await
            .map_err(|_| MpcNetworkError::SendError)
    }

    /// Read exactly `n` bytes from the stream
    async fn read_bytes(&mut self, num_bytes: usize) -> Result<Vec<u8>, MpcNetworkError> {
        let mut read_buffer = vec![0u8; num_bytes];
        let bytes_read = self.recv_stream.as_mut()
            .unwrap()
            .read(&mut read_buffer)
            .await
            .map_err(|_| MpcNetworkError::RecvError)?
            .ok_or(MpcNetworkError::RecvError)?;

        if bytes_read != num_bytes {
            return Err(
                MpcNetworkError::BroadcastError(BroadcastError::TooFewBytes)
            )
        }

        Ok(read_buffer.to_vec())
    }

    /// Write a stream of bytes to the network, then expect the same back from the connected peer
    async fn write_then_read_bytes(&mut self, order: ReadWriteOrder, payload: &[u8]) -> Result<Vec<u8>, MpcNetworkError> {
        let payload_length = payload.len();

        Ok(
            match order {
                ReadWriteOrder::ReadFirst => {
                    let bytes_read = self.read_bytes(payload_length).await?;
                    self.write_bytes(payload).await?;
                    bytes_read
                },
                ReadWriteOrder::WriteFirst => {
                    self.write_bytes(payload).await?;
                    self.read_bytes(payload_length).await?
                }
            }
        )
    }
}

#[async_trait]
impl MpcNetwork for QuicTwoPartyNet {
    fn party_id(&self) -> u64 {
        self.party_id     
    }

    async fn send_scalars(&mut self, scalars: Vec<Scalar>) -> Result<(), MpcNetworkError> {
        self.assert_connected()?;

        // To byte buffer
        let payload = scalars_to_bytes(scalars);
        self.write_bytes(&payload).await?;

        Ok(())
    }

    async fn receive_scalars(&mut self, num_scalars: usize) -> Result<Vec<Scalar>, MpcNetworkError> {
        self.assert_connected()?;
        let bytes_read = self.read_bytes(num_scalars * BYTES_PER_SCALAR).await?;

        bytes_to_scalars(&bytes_read)
    }

    async fn broadcast_scalars(&mut self, scalars: Vec<Scalar>) -> Result<
        Vec<Scalar>,
        MpcNetworkError
    > {
        self.assert_connected()?;

        // To byte buffer
        let payload = scalars_to_bytes(scalars);
        
        
        let read_buffer = self.write_then_read_bytes(self.read_order(), &payload).await?;
        
        bytes_to_scalars(&read_buffer)
    }

    async fn broadcast_points(&mut self, points: Vec<RistrettoPoint>) -> Result<
        Vec<RistrettoPoint>,
        MpcNetworkError  
    > {
        self.assert_connected()?;

        // To byte buffer
        let payload = points_to_bytes(points);
        let read_buffer = self.write_then_read_bytes(self.read_order(), &payload).await?;

        // Deserialize back to Ristretto points
        bytes_to_points(&read_buffer)
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

#[cfg(test)]
mod test {
    use std::{net::SocketAddr};

    use curve25519_dalek::{ristretto::RistrettoPoint};
    use rand_core::OsRng;
    use tokio;

    use super::{QuicTwoPartyNet, MpcNetwork};

    #[tokio::test]
    async fn test_errors() {
        let socket_addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let mut net = QuicTwoPartyNet::new(0, socket_addr, socket_addr);

        assert!(
            net.broadcast_points(vec![])
                .await
                .is_err()
        );

        let mut rng = OsRng{};
        assert!(
            net.broadcast_single_point(RistrettoPoint::random(&mut rng))
                .await
                .is_err()
        )
    }
}