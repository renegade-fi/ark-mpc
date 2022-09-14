//! Implements a dummy network used for testing

use async_trait::async_trait;
use curve25519_dalek::ristretto::RistrettoPoint;

use crate::error::MPCNetworkError;

use super::MPCNetwork;

#[derive(Clone, Debug)]
pub(crate) struct DummyMpcNetwork {
}

#[allow(unused)]
impl DummyMpcNetwork {
    pub fn new() -> Self { Self {} }
}

#[async_trait]
impl MPCNetwork for DummyMpcNetwork {
    /// Always return king
    fn party_id(&self) -> u64 { 0 }

    async fn broadcast_points(&mut self, points:Vec<RistrettoPoint>) -> Result<
        Vec<RistrettoPoint>,
        MPCNetworkError    
    > {
        Ok(points)
    }

    async fn close(&mut self) -> Result<(), MPCNetworkError> { Ok(()) }
}