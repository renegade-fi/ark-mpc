//! Defines tests for the fabric directly

use mpc_ristretto::{
    algebra::{
        mpc_scalar::{MpcScalar, MpcScalarResult},
        stark_curve::Scalar,
    },
    fabric::{ResultHandle, ResultValue},
    network::{NetworkPayload, PartyId},
    PARTY0, PARTY1,
};
use tokio::runtime::Handle;

use crate::{
    helpers::{assert_scalars_eq, await_result, create_secret_shares},
    IntegrationTest, IntegrationTestArgs,
};

// -----------
// | Helpers |
// -----------

/// Send or receive a value from the given party
fn share_value(
    value: Scalar,
    sender: PartyId,
    test_args: &IntegrationTestArgs,
) -> ResultHandle<Scalar> {
    if test_args.party_id == sender {
        let (my_share, their_share) = create_secret_shares(value);
        test_args.fabric.allocate_shared_value(
            ResultValue::Scalar(my_share),
            ResultValue::Scalar(their_share),
        )
    } else {
        test_args.fabric.receive_value()
    }
}

// ---------
// | Tests |
// ---------

/// Tests that sharing a value over the fabric works correctly
fn test_fabric_share_and_open(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party shares their party ID with the counterparty
    let my_party_id = Scalar::from(test_args.party_id);

    // Party 0
    let party0_value = share_value(my_party_id, PARTY0, test_args);
    let party0_mpc_value = MpcScalarResult::new_shared(party0_value, test_args.fabric.clone());
    let party0_value_opened = party0_mpc_value.open();
    let party0_res = await_result(party0_value_opened);

    assert_scalars_eq(party0_res, Scalar::from(0))?;

    // Party 1
    let party1_value = share_value(my_party_id, PARTY1, test_args);
    let party1_mpc_value = MpcScalarResult::new_shared(party1_value, test_args.fabric.clone());
    let party1_value_opened = party1_mpc_value.open();
    let party1_res = await_result(party1_value_opened);

    assert_scalars_eq(party1_res, Scalar::from(1))
}

inventory::submit!(IntegrationTest {
    name: "fabric::test_fabric_share_and_open",
    test_fn: test_fabric_share_and_open,
});
