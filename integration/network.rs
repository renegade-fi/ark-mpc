use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::network::MpcNetwork;
use tokio::runtime::Handle;

use crate::{base_point_mul, IntegrationTest, IntegrationTestArgs};

fn test_send_ristretto(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Send the party ID over the network; expect the counterparty's ID back
    let res = Handle::current()
        .block_on(
            test_args
                .net_ref
                .borrow_mut()
                .broadcast_single_point(base_point_mul(test_args.party_id)),
        )
        .map_err(|err| format!("{:?}", err))?;

    let expected = base_point_mul(if test_args.party_id == 0 { 1u64 } else { 0u64 });

    if res.eq(&expected) {
        Ok(())
    } else {
        Err("res != expected".to_string())
    }
}

fn test_send_scalar(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Send the party ID over the network as a Scalar; expect the counterparty's ID back
    let res = Handle::current()
        .block_on(
            test_args
                .net_ref
                .borrow_mut()
                .broadcast_single_scalar(Scalar::from(test_args.party_id)),
        )
        .map_err(|err| format!("{:?}", err))?;

    let expected = Scalar::from(if test_args.party_id == 0 { 1u8 } else { 0u8 });

    if res.eq(&expected) {
        Ok(())
    } else {
        Err("res != expected".to_string())
    }
}

// Take inventory
inventory::submit!(IntegrationTest {
    name: "network::test_send_ristretto",
    test_fn: test_send_ristretto,
});

inventory::submit!(IntegrationTest {
    name: "network::test_send_scalar",
    test_fn: test_send_scalar,
});
