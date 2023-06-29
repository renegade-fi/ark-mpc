//! Defines tests for the fabric directly

use mpc_ristretto::{algebra::stark_curve::Scalar, PARTY0, PARTY1};

use crate::{
    helpers::{assert_scalars_eq, await_result, share_scalar},
    IntegrationTest, IntegrationTestArgs,
};

// ---------
// | Tests |
// ---------

/// Tests that sharing a value over the fabric works correctly
fn test_fabric_share_and_open(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party shares their party ID with the counterparty
    let my_party_id = Scalar::from(test_args.party_id);

    // Party 0
    let party0_value = share_scalar(my_party_id, PARTY0, test_args);
    let party0_value_opened = party0_value.open();
    let party0_res = await_result(party0_value_opened);

    assert_scalars_eq(party0_res, Scalar::from(0))?;

    // Party 1
    let party1_value = share_scalar(my_party_id, PARTY1, test_args);
    let party1_value_opened = party1_value.open();
    let party1_res = await_result(party1_value_opened);

    assert_scalars_eq(party1_res, Scalar::from(1))
}

inventory::submit!(IntegrationTest {
    name: "fabric::test_fabric_share_and_open",
    test_fn: test_fabric_share_and_open,
});
