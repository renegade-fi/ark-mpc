//! Setup routines for the Lowgear implementation:
//!     - Exchange BGV keys
//!     - Generate MAC keys

use ark_ec::CurveGroup;
use ark_mpc::network::MpcNetwork;
use mp_spdz_rs::fhe::plaintext::Plaintext;

use crate::{error::LowGearError, lowgear::LowGear};

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin> LowGear<C, N> {
    /// Exchange BGV public keys and mac shares with the counterparty
    pub async fn run_key_exchange(&mut self) -> Result<(), LowGearError> {
        // First, share the public key
        self.send_message(self.local_keypair.public_key()).await?;
        let counterparty_pk = self.receive_message().await?;

        // Encrypt my mac share under my public key
        let mut pt = Plaintext::new(&self.params);
        pt.set_all(self.mac_share);
        let ct = self.local_keypair.encrypt(&pt);

        // Send and receive
        self.send_message(ct).await?;
        let counterparty_mac_enc = self.receive_message().await?;

        self.other_pk = Some(counterparty_pk);
        self.other_mac_enc = Some(counterparty_mac_enc);
        Ok(())
    }
}
