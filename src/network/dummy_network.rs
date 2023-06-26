#![cfg(test)]
//! Implements a dummy network used for testing

use std::vec;

use async_trait::async_trait;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use crate::error::MpcNetworkError;

use super::{MpcNetwork, NetworkOutbound};

#[derive(Clone, Debug, Default)]
pub struct DummyMpcNetwork {
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
    async fn send_message(&mut self, message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<NetworkOutbound, MpcNetworkError> {
        Ok(self.mock_messages.pop().expect("mock messages exhausted"))
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}
