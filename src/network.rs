//! The `network` module defines abstractions of the transport used to
//! communicate during the course of an MPC
mod cert_verifier;
mod config;
pub(crate) mod dummy_network;

use async_trait::async_trait;
use bytes::{BytesMut};
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use futures::StreamExt;
use std::{net::SocketAddr, convert::TryInto, borrow::Borrow};
use quinn::{Endpoint, RecvStream, SendStream, NewConnection};

use crate::error::{MPCNetworkError, BroadcastError, SetupError};

pub type PartyId = u64;

const BYTES_PER_POINT: usize = 32;
const MAX_PAYLOAD_SIZE: usize = 1024;

/// MPCNetwork represents the network functionality needed for 2PC execution
/// Note that only two party computation is implemented here
#[async_trait]
pub trait MPCNetwork {
    /// Returns the ID of the given party in the MPC computation
    fn party_id(&self) -> u64;
    /// Returns whether the local party is the king of the MPC (party 0)
    fn am_king(&self) -> bool { self.party_id() == 0 }
    /// Both parties broadcast a vector of points to one another
    async fn broadcast_points(&mut self, points: Vec<RistrettoPoint>) -> Result<Vec<RistrettoPoint>, MPCNetworkError>;
    /// Both parties broadcast a single point to one another
    async fn broadcast_single_point(&mut self, point: RistrettoPoint) -> Result<RistrettoPoint, MPCNetworkError> {
        Ok(
           self.broadcast_points(vec![point]).await?[0]
        )
    }
    /// Closes the connections opened in the handshake phase
    async fn close(&mut self) -> Result<(), MPCNetworkError>;
}  

/// Implements an MPCNetwork on top of QUIC
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
    pub async fn connect(&mut self) -> Result<(), MPCNetworkError> {
        // Build the client and server configs
        let (client_config, server_config) = config::build_configs()
            .map_err( |err| MPCNetworkError::ConnectionSetupError(err) )?;

        // Create a quinn server
        let (mut local_node, mut incoming) = Endpoint::server(server_config, self.local_addr)
            .map_err( |_| MPCNetworkError::ConnectionSetupError(SetupError::ServerSetupError) )?;
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
                        MPCNetworkError::ConnectionSetupError(SetupError::ConnectError(err))
                    })?
                    .await
                    .map_err(|err| {
                        MPCNetworkError::ConnectionSetupError(SetupError::ConnectionError(err)) 
                    })?
            } else {
                incoming.next()
                    .await
                    .ok_or(MPCNetworkError::ConnectionSetupError(SetupError::NoIncomingConnection))?
                    .await
                    .map_err(|err| {
                        MPCNetworkError::ConnectionSetupError(SetupError::ConnectionError(err))
                    })?
            
            }
        };

        // King opens a bidirectional stream on top of the connection
        let (send, recv) = {
            if self.am_king() {
                connection.open_bi()
                    .await
                    .map_err( |err| MPCNetworkError::ConnectionSetupError(SetupError::ConnectionError(err)) )?
            } else {
                bi_streams.next()
                    .await
                    .ok_or(MPCNetworkError::ConnectionSetupError(SetupError::NoIncomingConnection))?
                    .map_err( |err| MPCNetworkError::ConnectionSetupError(SetupError::ConnectionError(err)) )?
            }
        };
        
        // Update MPCNet state
        self.connected = true;
        self.send_stream = Some(send);
        self.recv_stream = Some(recv);

        Ok(())
    }

}

#[async_trait]
impl MPCNetwork for QuicTwoPartyNet {
    fn party_id(&self) -> u64 {
        self.party_id     
    }

    async fn broadcast_points(&mut self, points: Vec<RistrettoPoint>) -> Result<
        Vec<RistrettoPoint>,
        MPCNetworkError  
    > {
        if !self.connected {
            return Err(MPCNetworkError::NetworkUninitialized)
        }

        // Map to bytes 
        // let mut payload = BytesMut::with_capacity(points.len() * size_of::<RistrettoPoint>());
        let mut payload = BytesMut::new();
        points.iter()
            .for_each(|point| {
                let bytes = point.compress().to_bytes();
                payload.extend_from_slice(&bytes);
            });
        let payload_final = payload.freeze();
        let payload_length = payload_final.len();

        // Send on the stream and expect the same number of bytes back
        self.send_stream.as_mut()
            .unwrap()
            .write_all(payload_final.borrow())
            .await
            .map_err(|_| MPCNetworkError::SendError)?;
        
        let mut read_buffer = [0u8; MAX_PAYLOAD_SIZE];
        let bytes_read = self.recv_stream.as_mut()
            .unwrap()
            .read(&mut read_buffer)
            .await
            .map_err(|_| MPCNetworkError::RecvError)?
            .ok_or(MPCNetworkError::RecvError)?;

        if bytes_read != payload_length {
            return Err(
                MPCNetworkError::BroadcastError(BroadcastError::TooFewBytes)
            )
        }

        // Deserialize back to Ristretto points
        let res = read_buffer[..bytes_read].chunks(BYTES_PER_POINT)
            .into_iter()
            .map(|bytes_chunk| {
                CompressedRistretto(
                    bytes_chunk
                    .try_into()
                    .expect("unexpected number of bytes per chunk")
                ).decompress()
                .ok_or(MPCNetworkError::SerializationError)
            })
            .collect::<Result<Vec<RistrettoPoint>, MPCNetworkError>>()?;

        Ok(res)
    }

    async fn close(&mut self) -> Result<(), MPCNetworkError> {
        if !self.connected {
            return Err(MPCNetworkError::NetworkUninitialized);
        }

        self.send_stream
            .as_mut()
            .unwrap()
            .finish()
            .await
            .map_err(|_| MPCNetworkError::ConnectionTeardownError)
    }
}

#[cfg(test)]
mod test {
    use std::{net::SocketAddr};

    use curve25519_dalek::{ristretto::RistrettoPoint};
    use rand_core::OsRng;
    use tokio;

    use super::{QuicTwoPartyNet, MPCNetwork};

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