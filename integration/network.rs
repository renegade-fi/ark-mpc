use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{network::{QuicTwoPartyNet, MpcNetwork}};

use crate::base_point_mul;

pub(crate) async fn test_send_ristretto(
    party_id: u64,
    net: &mut QuicTwoPartyNet,
) -> Result<(), String> {
    // Send the party ID over the network; expect the counterparty's ID back
    let res = net.broadcast_single_point(base_point_mul(party_id))
        .await
        .map_err(|err| format!("{:?}", err))?;

    let expected = base_point_mul(
        if party_id == 0 { 1u64 } else { 0u64 }
    );

    if res.eq(&expected) { Ok(()) } else { Err("res != expected".to_string()) }
}

pub(crate) async fn test_send_scalar(
    party_id: u64,
    net: &mut QuicTwoPartyNet,
) -> Result<(), String> {
    // Send the party ID over the network as a Scalar; expect the counterparty's ID back
    let res = net.broadcast_single_scalar(Scalar::from(party_id))
        .await
        .map_err(|err| format!("{:?}", err))?;

    let expected = Scalar::from(
        if party_id == 0 { 1u8 } else { 0u8 }
    );

    if res.eq(&expected) { Ok(()) } else { Err("res != expected".to_string()) }
}