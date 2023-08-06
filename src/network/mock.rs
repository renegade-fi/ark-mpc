//! Defines a mock network for unit tests

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures::{future::pending, Future, Sink, Stream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::{error::MpcNetworkError, PARTY0};

use super::{MpcNetwork, NetworkOutbound, PartyId};

/// A dummy MPC network that never receives messages
#[derive(Default)]
pub struct NoRecvNetwork;

#[async_trait]
impl MpcNetwork for NoRecvNetwork {
    fn party_id(&self) -> PartyId {
        PARTY0
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}

impl Stream for NoRecvNetwork {
    type Item = Result<NetworkOutbound, MpcNetworkError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Box::pin(pending()).as_mut().poll(cx)
    }
}

impl Sink<NetworkOutbound> for NoRecvNetwork {
    type Error = MpcNetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, _item: NetworkOutbound) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// A dummy MPC network that operates over a duplex channel instead of a network connection/// An unbounded duplex channel used to mock a network connection
pub struct UnboundedDuplexStream {
    /// The send side of the stream
    send: UnboundedSender<NetworkOutbound>,
    /// The receive side of the stream
    recv: UnboundedReceiver<NetworkOutbound>,
}

impl UnboundedDuplexStream {
    /// Create a new pair of duplex streams
    pub fn new_duplex_pair() -> (Self, Self) {
        let (send1, recv1) = unbounded_channel();
        let (send2, recv2) = unbounded_channel();

        (
            Self {
                send: send1,
                recv: recv2,
            },
            Self {
                send: send2,
                recv: recv1,
            },
        )
    }

    /// Send a message on the stream
    pub fn send(&mut self, msg: NetworkOutbound) {
        self.send.send(msg).unwrap();
    }

    /// Recv a message from the stream
    pub async fn recv(&mut self) -> NetworkOutbound {
        self.recv.recv().await.unwrap()
    }
}

/// A dummy network implementation used for unit testing
pub struct MockNetwork {
    /// The ID of the local party
    party_id: PartyId,
    /// The underlying mock network connection
    mock_conn: UnboundedDuplexStream,
}

impl MockNetwork {
    /// Create a new mock network from one half of a duplex stream
    pub fn new(party_id: PartyId, stream: UnboundedDuplexStream) -> Self {
        Self {
            party_id,
            mock_conn: stream,
        }
    }
}

#[async_trait]
impl MpcNetwork for MockNetwork {
    fn party_id(&self) -> PartyId {
        self.party_id
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}

impl Stream for MockNetwork {
    type Item = Result<NetworkOutbound, MpcNetworkError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Box::pin(self.mock_conn.recv())
            .as_mut()
            .poll(cx)
            .map(|value| Some(Ok(value)))
    }
}

impl Sink<NetworkOutbound> for MockNetwork {
    type Error = MpcNetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: NetworkOutbound) -> Result<(), Self::Error> {
        self.mock_conn.send(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
