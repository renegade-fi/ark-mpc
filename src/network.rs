//! The `network` module defines abstractions of the transport used to
//! communicate during the course of an MPC
mod cert_verifier;
mod config;
pub(crate) mod dummy_network;

use async_trait::async_trait;
use bytes::{BytesMut};
use curve25519_dalek::{ristretto::{RistrettoPoint, CompressedRistretto}, scalar::Scalar};
use futures::StreamExt;
use std::{net::SocketAddr, convert::TryInto, borrow::Borrow};
use quinn::{Endpoint, RecvStream, SendStream, NewConnection};

use crate::error::{MpcNetworkError, BroadcastError, SetupError};

pub type PartyId = u64;

const BYTES_PER_POINT: usize = 32;
const BYTES_PER_SCALAR: usize = 32;
const MAX_PAYLOAD_SIZE: usize = 1024;

/// MpcNetwork represents the network functionality needed for 2PC execution
/// Note that only two party computation is implemented here
#[async_trait]
pub trait MpcNetwork {
    /// Returns the ID of the given party in the MPC computation
    fn party_id(&self) -> u64;
    /// Returns whether the local party is the king of the MPC (party 0)
    fn am_king(&self) -> bool { self.party_id() == 0 }
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

/// Implements an MpcNetwork on top of QUIC
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
        
        // Update MPCNet state
        self.connected = true;
        self.send_stream = Some(send);
        self.recv_stream = Some(recv);

        Ok(())
    }

    /// Write a stream of bytes to the network, then expect the same back from the connected peer
    async fn write_then_read_bytes(&mut self, payload: &[u8]) -> Result<Vec<u8>, MpcNetworkError> {
        let payload_length = payload.len();

        self.send_stream.as_mut()
            .unwrap()
            .write_all(payload)
            .await
            .map_err(|_| MpcNetworkError::SendError)?;
        
        let mut read_buffer = [0u8; MAX_PAYLOAD_SIZE];
        let bytes_read = self.recv_stream.as_mut()
            .unwrap()
            .read(&mut read_buffer)
            .await
            .map_err(|_| MpcNetworkError::RecvError)?
            .ok_or(MpcNetworkError::RecvError)?;

        if bytes_read != payload_length {
            return Err(
                MpcNetworkError::BroadcastError(BroadcastError::TooFewBytes)
            )
        }

        Ok(read_buffer[..bytes_read].to_vec())
    }

}

#[async_trait]
impl MpcNetwork for QuicTwoPartyNet {
    fn party_id(&self) -> u64 {
        self.party_id     
    }

    async fn broadcast_scalars(&mut self, scalars: Vec<Scalar>) -> Result<
        Vec<Scalar>,
        MpcNetworkError
    > {
        if !self.connected {
            return Err(MpcNetworkError::NetworkUninitialized)
        }

        // To byte buffer
        let mut payload = BytesMut::new();
        scalars.iter()
            .for_each(|scalar| {
                let bytes = scalar.to_bytes();
                payload.extend_from_slice(&bytes);
            });

        let payload_final = payload.freeze();
        let read_buffer = self.write_then_read_bytes(payload_final.borrow()).await?;

        // Deserialize back into Scalars
        let res = read_buffer.chunks(BYTES_PER_SCALAR)
            .into_iter()
            .map(|bytes_chunk| {
                Scalar::from_canonical_bytes(
                    bytes_chunk
                        .try_into()
                        .expect("unexpected number of bytes per chunk")
                )
                    .ok_or(MpcNetworkError::SerializationError)
            })
            .collect::<Result<Vec<Scalar>, MpcNetworkError>>()?;
        
        Ok(res)
    }

    async fn broadcast_points(&mut self, points: Vec<RistrettoPoint>) -> Result<
        Vec<RistrettoPoint>,
        MpcNetworkError  
    > {
        if !self.connected {
            return Err(MpcNetworkError::NetworkUninitialized)
        }

        // Map to bytes 
        let mut payload = BytesMut::new();
        points.iter()
            .for_each(|point| {
                let bytes = point.compress().to_bytes();
                payload.extend_from_slice(&bytes);
            });

        let payload_final = payload.freeze();
        let read_buffer = self.write_then_read_bytes(payload_final.borrow()).await?;

        // Deserialize back to Ristretto points
        let res = read_buffer.chunks(BYTES_PER_POINT)
            .into_iter()
            .map(|bytes_chunk| {
                CompressedRistretto(
                    bytes_chunk
                    .try_into()
                    .expect("unexpected number of bytes per chunk")
                ).decompress()
                .ok_or(MpcNetworkError::SerializationError)
            })
            .collect::<Result<Vec<RistrettoPoint>, MpcNetworkError>>()?;

        Ok(res)
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        if !self.connected {
            return Err(MpcNetworkError::NetworkUninitialized);
        }

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