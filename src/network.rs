//! The `network` module defines abstractions of the transport used to
//! communicate during the course of an MPC
//!
use async_trait::async_trait;
use bytes::{BytesMut, BufMut, Bytes};
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use std::{net::SocketAddr, convert::TryInto, mem::size_of};
use qp2p::{Config, Endpoint, SendStream, RecvStream};

use crate::error::{MPCNetworkError, BroadcastError};

pub type PartyId = u64;
const BYTES_PER_POINT: usize = 32;

/// MPCNetwork represents the network functionality needed for 2PC execution
/// Note that only two party computation is implemented here
#[async_trait]
pub trait MPCNetwork {
    /// Returns the ID of the given party in the MPC computation
    fn party_id(&self) -> u64;
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
        // Open a QUIC connection to the peer
        let (_, _, connections) = Endpoint::new_peer(
            self.local_addr, 
            &[self.peer_addr], 
            Config::default(),
        ).await
        .map_err(|_| MPCNetworkError::ConnectionSetupError)?;

        // Open a bi-directional stream 
        let outbound = connections.ok_or(MPCNetworkError::ConnectionSetupError)?.0;

        let (send, recv) = outbound.open_bi()
            .await
            .map_err( |_| MPCNetworkError::ConnectionSetupError)?;
        
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
        let mut payload = BytesMut::with_capacity(points.len() * size_of::<RistrettoPoint>());
        points.iter()
            .for_each(|point| {
                let bytes = point.compress().to_bytes();
                payload.put_slice(&bytes);
            });
        let payload_final = payload.freeze();
        let payload_length = payload_final.len();

        // Send on the stream and expect the same number of bytes back
        self.send_stream.as_mut()
            .unwrap()
            .send_user_msg(
                (Bytes::new(), Bytes::new(), payload_final)
            ).await
            .map_err(|_| MPCNetworkError::SendError)?;
        
        let (_, _, recv_payload) = self.recv_stream.as_mut()
            .unwrap()
            .next()
            .await
            .map_err(|_| MPCNetworkError::RecvError)?;

        if recv_payload.len() != payload_length {
            return Err(
                MPCNetworkError::BroadcastError(BroadcastError::TooFewBytes)
            )
        }

        // Deserialize back to Ristretto points
        let res = recv_payload.chunks(BYTES_PER_POINT)
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