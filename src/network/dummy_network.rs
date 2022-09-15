//! Implements a dummy network used for testing

use async_trait::async_trait;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use crate::error::MpcNetworkError;

use super::MpcNetwork;

#[derive(Clone, Debug)]
pub(crate) struct DummyMpcNetwork {
}

#[allow(unused)]
impl DummyMpcNetwork {
    pub fn new() -> Self { Self {} }
}

#[async_trait]
impl MpcNetwork for DummyMpcNetwork {
    /// Always return king
    fn party_id(&self) -> u64 { 0 }

    async fn broadcast_points(&mut self, points: Vec<RistrettoPoint>) -> Result<
        Vec<RistrettoPoint>,
        MpcNetworkError    
    > {
        Ok(points)
    }

    async fn broadcast_scalars(&mut self, scalars: Vec<Scalar>) -> Result<
        Vec<Scalar>,
        MpcNetworkError 
    > {
        Ok(scalars)
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> { Ok(()) }
}