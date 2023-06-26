#![cfg(test)]
//! Implements a dummy network used for testing

use async_trait::async_trait;

use crate::{error::MpcNetworkError, PARTY0};

use super::{MpcNetwork, NetworkOutbound};

#[derive(Clone, Debug, Default)]
pub(crate) struct DummyMpcNetwork {
    /// A list of mock messages sent from the peer
    mock_messages: Vec<NetworkOutbound>,
}

impl DummyMpcNetwork {
    pub fn new() -> Self {
        Self {
            mock_messages: Vec::new(),
        }
    }

    pub fn add_mock_messages(&mut self, messages: Vec<NetworkOutbound>) {
        self.mock_messages.extend(messages);
    }
}

#[async_trait]
impl MpcNetwork for DummyMpcNetwork {
    fn party_id(&self) -> u64 {
        PARTY0
    }

    async fn send_message(&mut self, message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<NetworkOutbound, MpcNetworkError> {
        Ok(self.mock_messages.pop().expect("mock messages exhausted"))
    }

    async fn exchange_messages(
        &mut self,
        message: NetworkOutbound,
    ) -> Result<NetworkOutbound, MpcNetworkError> {
        self.receive_message().await
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}
