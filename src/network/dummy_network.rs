//! Implements a dummy network used for testing


use std::vec;

use async_trait::async_trait;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use crate::error::MpcNetworkError;

use super::MpcNetwork;

#[derive(Clone, Debug)]
pub(crate) struct DummyMpcNetwork {
    /// Append to mock a scalar sent from a peer
    mock_scalars: Vec<Scalar>,
    /// Append to mock a Ristretto point sent from a peer
    mock_points: Vec<RistrettoPoint>,
}

#[allow(unused)]
impl DummyMpcNetwork {
    pub fn new() -> Self { 
        Self {
            mock_scalars: vec![],
            mock_points: vec![],
        } 
    }

    pub fn add_mock_scalars(&mut self, scalars: Vec<Scalar>) {
        self.mock_scalars.extend_from_slice(&scalars);
    }

    pub fn add_mock_points(&mut self, points: Vec<RistrettoPoint>) {
        self.mock_points.extend_from_slice(&points);
    }
}

#[async_trait]
impl MpcNetwork for DummyMpcNetwork {
    /// Always return king
    fn party_id(&self) -> u64 { 0 }

    async fn send_scalars(&mut self, _: Vec<Scalar>) -> Result<(), MpcNetworkError> {
        Ok(())
    }

    async fn receive_scalars(&mut self, num_scalars: usize) -> Result<Vec<Scalar>, MpcNetworkError> {
        Ok(
            self.mock_scalars
                .drain(0..num_scalars)
                .as_slice()
                .to_vec()
        )
    }

    async fn broadcast_points(&mut self, points: Vec<RistrettoPoint>) -> Result<
        Vec<RistrettoPoint>,
        MpcNetworkError    
    > {
        Ok(
            self.mock_points
                .drain(0..points.len())
                .as_slice()
                .to_vec()
        )
    }

    async fn send_points(&mut self, _: Vec<RistrettoPoint>) -> Result<(), MpcNetworkError> {
        Ok(())
    }

    async fn receive_points(&mut self, num_points: usize) -> Result<Vec<RistrettoPoint>, MpcNetworkError> {
        Ok(
            self.mock_points
                .drain(0..num_points)
                .as_slice()
                .to_vec()
        )
    }

    async fn broadcast_scalars(&mut self, scalars: Vec<Scalar>) -> Result<
        Vec<Scalar>,
        MpcNetworkError 
    > {
        Ok(
            self.mock_scalars
                .drain(0..scalars.len())
                .as_slice()
                .to_vec()
        )
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> { Ok(()) }
}