//! Defines the result of the Lowgear offline phase

use ark_ec::CurveGroup;
use ark_mpc::algebra::Scalar;
use mp_spdz_rs::fhe::ciphertext::Ciphertext;
use mp_spdz_rs::fhe::keys::{BGVKeypair, BGVPublicKey};
use mp_spdz_rs::fhe::params::BGVParams;

/// The parameters setup by the offline phase
#[derive(Clone)]
pub struct LowGearParams<C: CurveGroup> {
    /// The local party's BGV keypair
    pub local_keypair: BGVKeypair<C>,
    /// The local party's MAC key share
    pub mac_key_share: Scalar<C>,
    /// The BGV public key of the counterparty
    pub other_pk: BGVPublicKey<C>,
    /// An encryption of the counterparty's MAC key share
    pub other_mac_enc: Ciphertext<C>,
    /// The BGV cryptosystem parameters
    pub bgv_params: BGVParams<C>,
}
