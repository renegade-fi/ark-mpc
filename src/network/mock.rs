//! Defines a mock network for unit tests

use async_trait::async_trait;
use futures::future::pending;

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
