//! Defines a mock network for unit tests

use async_trait::async_trait;

use crate::{algebra::scalar::Scalar, error::MpcNetworkError, PARTY0};

use super::{MpcNetwork, NetworkOutbound, NetworkPayload, PartyId};

/// A dummy network implementation used for unit testing
pub struct MockNetwork;
impl MockNetwork {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

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
