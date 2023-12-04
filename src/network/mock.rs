//! Defines a mock network for unit tests

use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use ark_ec::CurveGroup;
use async_trait::async_trait;
use futures::{future::pending, Future, Sink, Stream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::{error::MpcNetworkError, PARTY0};

use super::{MpcNetwork, NetworkOutbound, PartyId};

/// A dummy MPC network that never receives messages
#[derive(Default)]
pub struct NoRecvNetwork<C: CurveGroup>(PhantomData<C>);

#[async_trait]
impl<C: CurveGroup> MpcNetwork<C> for NoRecvNetwork<C> {
    fn party_id(&self) -> PartyId {
        PARTY0
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}

impl<C: CurveGroup> Stream for NoRecvNetwork<C> {
    type Item = Result<NetworkOutbound<C>, MpcNetworkError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Box::pin(pending()).as_mut().poll(cx)
    }
}

impl<C: CurveGroup> Sink<NetworkOutbound<C>> for NoRecvNetwork<C> {
    type Error = MpcNetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, _item: NetworkOutbound<C>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// A dummy MPC network that operates over a duplex channel instead of a network
/// connection/// An unbounded duplex channel used to mock a network connection
pub struct UnboundedDuplexStream<C: CurveGroup> {
    /// The send side of the stream
    send: UnboundedSender<NetworkOutbound<C>>,
    /// The receive side of the stream
    recv: UnboundedReceiver<NetworkOutbound<C>>,
}

impl<C: CurveGroup> UnboundedDuplexStream<C> {
    /// Create a new pair of duplex streams
    pub fn new_duplex_pair() -> (Self, Self) {
        let (send1, recv1) = unbounded_channel();
        let (send2, recv2) = unbounded_channel();

        (Self { send: send1, recv: recv2 }, Self { send: send2, recv: recv1 })
    }

    /// Send a message on the stream
    pub fn send(&mut self, msg: NetworkOutbound<C>) {
        self.send.send(msg).unwrap();
    }

    /// Recv a message from the stream
    pub async fn recv(&mut self) -> NetworkOutbound<C> {
        self.recv.recv().await.unwrap()
    }
}

/// A dummy network implementation used for unit testing
pub struct MockNetwork<C: CurveGroup> {
    /// The ID of the local party
    party_id: PartyId,
    /// The underlying mock network connection
    mock_conn: UnboundedDuplexStream<C>,
}

impl<C: CurveGroup> MockNetwork<C> {
    /// Create a new mock network from one half of a duplex stream
    pub fn new(party_id: PartyId, stream: UnboundedDuplexStream<C>) -> Self {
        Self { party_id, mock_conn: stream }
    }
}

#[async_trait]
impl<C: CurveGroup> MpcNetwork<C> for MockNetwork<C> {
    fn party_id(&self) -> PartyId {
        self.party_id
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}

impl<C: CurveGroup> Stream for MockNetwork<C> {
    type Item = Result<NetworkOutbound<C>, MpcNetworkError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Box::pin(self.mock_conn.recv()).as_mut().poll(cx).map(|value| Some(Ok(value)))
    }
}

impl<C: CurveGroup> Sink<NetworkOutbound<C>> for MockNetwork<C> {
    type Error = MpcNetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: NetworkOutbound<C>) -> Result<(), Self::Error> {
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
