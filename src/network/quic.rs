//! Defines the central implementation of an `MpcNetwork` over the QUIC transport

use async_trait::async_trait;
use futures::{Future, Sink, Stream};
use quinn::{Endpoint, RecvStream, SendStream};
use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tracing::log;

use crate::{
    error::{MpcNetworkError, SetupError},
    PARTY0,
};

use super::{config, stream_buffer::BufferWithCursor, MpcNetwork, NetworkOutbound, PartyId};

// -------------
// | Constants |
// -------------

/// The number of bytes in a u64
const BYTES_PER_U64: usize = 8;

/// Error thrown when a stream finishes early
const ERR_STREAM_FINISHED_EARLY: &str = "stream finished early";
/// Error message emitted when reading a message length from the stream fails
const ERR_READ_MESSAGE_LENGTH: &str = "error reading message length from stream";
/// Error message emitted when the the send `Sink` is not ready
const ERR_SEND_BUFFER_FULL: &str = "send buffer full";

// -----------------------
// | Quic Implementation |
// -----------------------

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
    /// A buffered message length read from the stream
    ///
    /// In the case that the whole message is not available yet, reads may block
    /// and the `read_message` future may be cancelled by the executor.
    /// We buffer the message length to avoid re-reading the message length incorrectly from
    /// the stream
    buffered_message_length: Option<u64>,
    /// A buffered partial message read from the stream
    ///
    /// This buffer exists to provide cancellation safety to a `read` future as the underlying `quinn`
    /// stream is not cancellation safe, i.e. if a `ReadBuf` future is dropped, the buffer is dropped with
    /// it and the partially read data is skipped
    buffered_inbound: Option<BufferWithCursor>,
    /// A buffered partial message written to the stream
    buffered_outbound: Option<BufferWithCursor>,
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
            buffered_message_length: None,
            buffered_inbound: None,
            buffered_outbound: None,
            send_stream: None,
            recv_stream: None,
        }
    }

    /// Returns true if the local party is party 0
    fn local_party0(&self) -> bool {
        self.party_id() == PARTY0
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

    /// Write the current buffer to the stream
    async fn write_bytes(&mut self) -> Result<(), MpcNetworkError> {
        // If no pending writes are available, return
        if self.buffered_outbound.is_none() {
            return Ok(());
        }

        // While the outbound buffer has elements remaining, write them
        let buf = self.buffered_outbound.as_mut().unwrap();
        while !buf.is_depleted() {
            let bytes_written = self
                .send_stream
                .as_mut()
                .unwrap()
                .write(buf.get_remaining())
                .await
                .map_err(|e| MpcNetworkError::SendError(e.to_string()))?;

            buf.advance_cursor(bytes_written);
        }

        self.buffered_outbound = None;
        Ok(())
    }

    /// Read exactly `n` bytes from the stream
    async fn read_bytes(&mut self, num_bytes: usize) -> Result<Vec<u8>, MpcNetworkError> {
        // Allocate a buffer for the next message if one does not already exist
        if self.buffered_inbound.is_none() {
            self.buffered_inbound = Some(BufferWithCursor::new(vec![0u8; num_bytes]));
        }

        // Read until the buffer is full
        let read_buffer = self.buffered_inbound.as_mut().unwrap();
        while !read_buffer.is_depleted() {
            let bytes_read = self
                .recv_stream
                .as_mut()
                .unwrap()
                .read(read_buffer.get_remaining())
                .await
                .map_err(|e| MpcNetworkError::RecvError(e.to_string()))?
                .ok_or(MpcNetworkError::RecvError(
                    ERR_STREAM_FINISHED_EARLY.to_string(),
                ))?;

            read_buffer.advance_cursor(bytes_read);
        }

        // Take ownership of the buffer, and reset the buffered message to `None`
        Ok(self.buffered_inbound.take().unwrap().into_vec())
    }

    /// Read a message length from the stream
    async fn read_message_length(&mut self) -> Result<u64, MpcNetworkError> {
        let read_buffer = self.read_bytes(BYTES_PER_U64).await?;
        Ok(u64::from_le_bytes(read_buffer.try_into().map_err(
            |_| MpcNetworkError::SerializationError(ERR_READ_MESSAGE_LENGTH.to_string()),
        )?))
    }

    /// Receive a message from the peer
    async fn receive_message(&mut self) -> Result<NetworkOutbound, MpcNetworkError> {
        // Read the message length from the buffer if available
        if self.buffered_message_length.is_none() {
            self.buffered_message_length = Some(self.read_message_length().await?);
        }

        // Read the data from the stream
        let len = self.buffered_message_length.unwrap();
        let bytes = self.read_bytes(len as usize).await?;

        // Reset the message length buffer after the data has been pulled from the stream
        self.buffered_message_length = None;

        // Deserialize the message
        serde_json::from_slice(&bytes)
            .map_err(|err| MpcNetworkError::SerializationError(err.to_string()))
    }
}

#[async_trait]
impl MpcNetwork for QuicTwoPartyNet {
    fn party_id(&self) -> PartyId {
        self.party_id
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

impl Stream for QuicTwoPartyNet {
    type Item = Result<NetworkOutbound, MpcNetworkError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Box::pin(self.receive_message()).as_mut().poll(cx).map(Some)
    }
}

impl Sink<NetworkOutbound> for QuicTwoPartyNet {
    type Error = MpcNetworkError;

    fn start_send(mut self: Pin<&mut Self>, msg: NetworkOutbound) -> Result<(), Self::Error> {
        if !self.connected {
            return Err(MpcNetworkError::NetworkUninitialized);
        }

        // Must call `poll_flush` before calling `start_send` again
        if self.buffered_outbound.is_some() {
            return Err(MpcNetworkError::SendError(ERR_SEND_BUFFER_FULL.to_string()));
        }

        // Serialize the message and buffer it for writing
        let bytes = serde_json::to_vec(&msg)
            .map_err(|err| MpcNetworkError::SerializationError(err.to_string()))?;
        let mut payload = (bytes.len() as u64).to_le_bytes().to_vec();
        payload.extend_from_slice(&bytes);

        self.buffered_outbound = Some(BufferWithCursor::new(payload));
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Poll the write future
        Box::pin(self.write_bytes()).as_mut().poll(cx)
    }

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // The network is always ready to send
        self.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // The network is always ready to close
        self.poll_flush(cx)
    }
}
