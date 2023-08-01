//! Defines a mock network for unit tests

use async_trait::async_trait;
use futures::future::pending;
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

    async fn send_message(&mut self, _message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<NetworkOutbound, MpcNetworkError> {
        pending().await
    }

    async fn exchange_messages(
        &mut self,
        _message: NetworkOutbound,
    ) -> Result<NetworkOutbound, MpcNetworkError> {
        pending().await
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
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

    async fn send_message(&mut self, message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        self.mock_conn.send(message);
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<NetworkOutbound, MpcNetworkError> {
        let msg = self.mock_conn.recv().await;
        Ok(msg)
    }

    async fn exchange_messages(
        &mut self,
        message: NetworkOutbound,
    ) -> Result<NetworkOutbound, MpcNetworkError> {
        if self.party_id() == PARTY0 {
            self.send_message(message).await?;
            self.receive_message().await
        } else {
            let res = self.receive_message().await?;
            self.send_message(message).await?;
            Ok(res)
        }
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}
