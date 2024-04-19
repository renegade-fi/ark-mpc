//! Integration tests for the lowgear offline phase

use ark_mpc::{algebra::Scalar, MpcFabric, PARTY0, PARTY1};
use ark_mpc_offline::{
    lowgear::{self, LowGear},
    structs::OfflineSizingParams,
};

use crate::{
    helpers::{await_result, await_result_with_error},
    IntegrationTest, IntegrationTestArgs,
};

/// Test a mock circuit using lowgear for setup
fn test_setup_and_run_circuit(test_args: &mut IntegrationTestArgs) -> Result<(), String> {
    let net = await_result(test_args.new_quic_conn());
    let mut lowgear = LowGear::new(net);
    await_result_with_error(lowgear.run_key_exchange())?;
    let params = lowgear.get_setup_params().unwrap();
    await_result_with_error(lowgear.shutdown())?;

    // Make a new lowgear as we would to run the offline phase
    let new_net = await_result(test_args.new_quic_conn());
    let mut lowgear = LowGear::new_from_params(params, new_net);
    await_result_with_error(lowgear.run_offline_phase(OfflineSizingParams {
        num_input_masks: 100,
        num_inverse_pairs: 100,
        ..Default::default()
    }))?;

    let offline = lowgear.get_offline_result().unwrap();
    println!("finished offline");

    // Run an mpc
    let net = await_result(test_args.new_quic_conn());
    let fabric = MpcFabric::new(net, offline);
    let a = fabric.share_scalar(2u8, PARTY0);
    let b = fabric.share_scalar(3u8, PARTY1);
    let c = a * b;

    let c_open = await_result_with_error(c.open_authenticated())?;
    if c_open != Scalar::from(6u8) {
        return Err("Expected 6".to_string());
    }
    Ok(())
}

inventory::submit!(IntegrationTest {
    name: "lowgear::test_keygen",
    test_fn: test_setup_and_run_circuit
});
