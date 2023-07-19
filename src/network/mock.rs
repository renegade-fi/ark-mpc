//! Defines a mock network for unit tests

use async_trait::async_trait;
use futures::future::pending;

use crate::{algebra::scalar::Scalar, error::MpcNetworkError, PARTY0};

use super::{MpcNetwork, NetworkOutbound, NetworkPayload, PartyId};

/// A dummy network implementation used for unit testing
#[derive(Default)]
pub struct MockNetwork;

#[async_trait]
impl MpcNetwork for MockNetwork {
    fn party_id(&self) -> PartyId {
        PARTY0
    }

    async fn send_message(&mut self, _message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<NetworkOutbound, MpcNetworkError> {
        Ok(NetworkOutbound {
            op_id: 0,
            payload: NetworkPayload::Scalar(Scalar::one()),
        })
    }

    async fn exchange_messages(
        &mut self,
        _message: NetworkOutbound,
    ) -> Result<NetworkOutbound, MpcNetworkError> {
        Ok(NetworkOutbound {
            op_id: 0,
            payload: NetworkPayload::Scalar(Scalar::one()),
        })
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}

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
