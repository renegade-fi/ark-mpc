//! Integration tests for the lowgear offline phase

use ark_mpc_offline::lowgear::LowGear;
use futures::executor::block_on;

use crate::{
    helpers::{await_result, await_result_with_error},
    IntegrationTest, IntegrationTestArgs,
};

/// A basic smoke test that
fn test_keygen(test_args: &IntegrationTestArgs) -> Result<(), String> {
    println!("got here");
    let net = await_result(test_args.new_quic_conn());
    let mut lowgear = LowGear::new(net);

    await_result_with_error(lowgear.run_key_exchange())
}

inventory::submit!(IntegrationTest { name: "lowgear::test_keygen", test_fn: test_keygen });
