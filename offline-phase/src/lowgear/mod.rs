//! Defines the lowgear protocol for generating triples, inverse pairs, mac
//! keys, authenticating inputs, etc

pub mod setup;
pub mod shared_random;
pub mod triplets;

use ark_ec::CurveGroup;
use ark_mpc::{
    algebra::Scalar,
    network::{MpcNetwork, NetworkOutbound, NetworkPayload},
};
use futures::{SinkExt, StreamExt};
use mp_spdz_rs::{
    fhe::{
        ciphertext::{Ciphertext, CiphertextVector},
        keys::{BGVKeypair, BGVPublicKey},
        params::BGVParams,
        plaintext::{Plaintext, PlaintextVector},
    },
    FromBytesWithParams, ToBytes,
};
use rand::thread_rng;

use crate::{beaver_source::LowGearParams, error::LowGearError};

/// A type implementing Lowgear protocol logic
pub struct LowGear<C: CurveGroup, N: MpcNetwork<C>> {
    /// The parameters for the BGV scheme
    pub params: BGVParams<C>,
    /// The BGV keypair used by the local party
    pub local_keypair: BGVKeypair<C>,
    /// The local party's MAC key share
    pub mac_share: Scalar<C>,
    /// The BGV public key of the counterparty
    pub other_pk: Option<BGVPublicKey<C>>,
    /// An encryption of the counterparty's MAC key share under their public key
    pub other_mac_enc: Option<Ciphertext<C>>,
    /// The Beaver triples generated during the offline phase
    pub triples: Vec<(Scalar<C>, Scalar<C>, Scalar<C>)>,
    /// The mac values for the triples generated during the offline phase
    pub triple_macs: Vec<(Scalar<C>, Scalar<C>, Scalar<C>)>,
    /// A reference to the underlying network connection
    pub network: N,
}

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin> LowGear<C, N> {
    /// Create a new LowGear instance
    #[allow(clippy::new_without_default)]
    pub fn new(network: N) -> Self {
        let mut rng = thread_rng();
        let params = BGVParams::new_no_mults();
        let local_keypair = BGVKeypair::gen(&params);
        let mac_share = Scalar::random(&mut rng);

        Self {
            params,
            local_keypair,
            mac_share,
            other_pk: None,
            other_mac_enc: None,
            triples: vec![],
            triple_macs: vec![],
            network,
        }
    }

    /// Get the setup parameters from the offline phase
    pub fn get_setup_params(&self) -> Result<LowGearParams<C>, LowGearError> {
        Ok(LowGearParams {
            local_keypair: self.local_keypair.clone(),
            mac_key_share: self.mac_share,
            other_pk: self.other_pk.clone().ok_or(LowGearError::NotSetup)?,
            other_mac_enc: self.other_mac_enc.clone().ok_or(LowGearError::NotSetup)?,
            bgv_params: self.params.clone(),
        })
    }

    /// Get a plaintext with the local mac share in all slots
    pub fn get_mac_plaintext(&self) -> Plaintext<C> {
        let mut pt = Plaintext::new(&self.params);
        pt.set_all(self.mac_share);

        pt
    }

    /// Get a plaintext vector wherein each plaintext created with the local mac
    /// share in all slots
    pub fn get_mac_plaintext_vector(&self, n: usize) -> PlaintextVector<C> {
        let mut vec = PlaintextVector::new(n, &self.params);
        let pt = self.get_mac_plaintext();
        for i in 0..n {
            vec.set(i, &pt);
        }

        vec
    }

    /// Get a ciphertext vector wherein each ciphertext is an encryption of the
    /// counterparty's mac share
    pub fn get_other_mac_enc(&self, n: usize) -> CiphertextVector<C> {
        let mut vec = CiphertextVector::new(n, &self.params);
        let ct = self.other_mac_enc.as_ref().unwrap();
        for i in 0..n {
            vec.set(i, ct);
        }

        vec
    }

    /// Send a message to the counterparty
    pub async fn send_message<T: ToBytes>(&mut self, message: &T) -> Result<(), LowGearError> {
        let payload = NetworkPayload::<C>::Bytes(message.to_bytes());
        let msg = NetworkOutbound { result_id: 0, payload };

        self.network.send(msg).await.map_err(|e| LowGearError::SendMessage(e.to_string()))?;
        Ok(())
    }

    /// Send a message to the counterparty that can directly be converted to a
    /// network payload
    pub async fn send_network_payload<T: Into<NetworkPayload<C>>>(
        &mut self,
        payload: T,
    ) -> Result<(), LowGearError> {
        let msg = NetworkOutbound { result_id: 0, payload: payload.into() };

        self.network.send(msg).await.map_err(|e| LowGearError::SendMessage(e.to_string()))?;
        Ok(())
    }

    /// Receive a message from the counterparty
    pub async fn receive_message<T: FromBytesWithParams<C>>(&mut self) -> Result<T, LowGearError> {
        let msg = self.network.next().await.unwrap().unwrap();
        let payload = match msg.payload {
            NetworkPayload::Bytes(bytes) => bytes,
            _ => return Err(LowGearError::UnexpectedMessage(format!("{:?}", msg.payload))),
        };

        Ok(T::from_bytes(&payload, &self.params))
    }

    /// Receive a network payload from the counterparty
    pub async fn receive_network_payload<T: From<NetworkPayload<C>>>(
        &mut self,
    ) -> Result<T, LowGearError> {
        let msg = self.network.next().await.unwrap().unwrap();
        Ok(msg.payload.into())
    }
}

#[cfg(test)]
mod test {
    use ark_mpc::{network::MpcNetwork, test_helpers::TestCurve, PARTY0};
    use mp_spdz_rs::{fhe::params::BGVParams, FromBytesWithParams, ToBytes};

    use crate::test_helpers::mock_lowgear;

    /// A test message type
    #[derive(Clone, Debug)]
    struct TestMessage(String);
    impl ToBytes for TestMessage {
        fn to_bytes(&self) -> Vec<u8> {
            self.0.as_bytes().to_vec()
        }
    }

    impl FromBytesWithParams<TestCurve> for TestMessage {
        fn from_bytes(data: &[u8], _params: &BGVParams<TestCurve>) -> Self {
            Self(String::from_utf8(data.to_vec()).unwrap())
        }
    }

    /// Tests sending and receiving a message
    #[tokio::test]
    async fn test_send_receive() {
        const MSG1: &str = "Party 0 to Party 1";
        const MSG2: &str = "Party 1 to Party 0";

        let (res1, res2) = mock_lowgear(|mut lowgear| async move {
            let party = lowgear.network.party_id();
            if party == PARTY0 {
                let msg = TestMessage(MSG1.to_string());
                lowgear.send_message(&msg).await.unwrap();
                lowgear.receive_message::<TestMessage>().await.unwrap()
            } else {
                let msg = TestMessage(MSG2.to_string());
                let recv = lowgear.receive_message::<TestMessage>().await.unwrap();
                lowgear.send_message(&msg).await.unwrap();

                recv
            }
        })
        .await;

        // Check the results
        assert_eq!(res1.0, MSG2);
        assert_eq!(res2.0, MSG1);
    }
}
