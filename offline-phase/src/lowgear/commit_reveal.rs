//! Defines a commit/reveal subprotocol for the LowGear offline phase

use ark_ec::CurveGroup;
use ark_mpc::{algebra::Scalar, network::MpcNetwork};
use sha3::{Digest, Sha3_256};

use crate::error::LowGearError;

use super::LowGear;

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin + Send> LowGear<C, N> {
    /// Open a single value without committing first
    ///
    /// Adds the counterparty's value to the input to recover the underlying
    /// value
    pub async fn open_single(&mut self, my_value: Scalar<C>) -> Result<Scalar<C>, LowGearError> {
        Ok(self.open_batch(&[my_value]).await?.pop().expect("Expected a single value"))
    }

    /// Open a batch of values without committing first
    ///
    /// Adds the counterparty's values to the input to recover the underlying
    /// values
    pub async fn open_batch(
        &mut self,
        values: &[Scalar<C>],
    ) -> Result<Vec<Scalar<C>>, LowGearError> {
        // Send the values
        self.send_network_payload(values.to_vec()).await?;
        let their_values: Vec<Scalar<C>> = self.receive_network_payload().await?;
        let res = their_values.iter().zip(values.iter()).map(|(a, b)| a + b).collect();

        Ok(res)
    }

    /// Commit and reveal a single value
    pub async fn commit_reveal_single(
        &mut self,
        value: Scalar<C>,
    ) -> Result<Scalar<C>, LowGearError> {
        Ok(self.commit_reveal(&[value]).await?.pop().expect("Expected a single value"))
    }

    /// Commit and reveal a set of values
    ///
    /// Returns the counterparty's revealed values
    pub async fn commit_reveal(
        &mut self,
        values: &[Scalar<C>],
    ) -> Result<Vec<Scalar<C>>, LowGearError> {
        // Hash the values
        let my_comm = Self::commit_scalars(values);
        self.send_network_payload(my_comm).await?;
        let their_comm: Scalar<C> = self.receive_network_payload().await?;

        // Reveal the values
        self.send_network_payload(values.to_vec()).await?;
        let their_values: Vec<Scalar<C>> = self.receive_network_payload().await?;

        // Check the counterparty's commitment
        let expected_comm = Self::commit_scalars(&their_values);
        if expected_comm != their_comm {
            return Err(LowGearError::InvalidCommitment);
        }

        Ok(their_values)
    }

    /// Hash commit to a set of random values
    pub(crate) fn commit_scalars(values: &[Scalar<C>]) -> Scalar<C> {
        let mut hasher = Sha3_256::new();
        for value in values.iter() {
            hasher.update(value.to_bytes_be());
        }
        let hash_output = hasher.finalize();

        Scalar::<C>::from_be_bytes_mod_order(&hash_output)
    }
}
