//! Defines unit tests for `MpcScalar` types
use mpc_stark::{
    algebra::stark_curve::Scalar,
    fabric::{ResultHandle, ResultValue},
    random_scalar, PARTY0, PARTY1,
};

use crate::{
    helpers::{assert_scalars_eq, await_result, share_plaintext_value, share_scalar},
    IntegrationTest, IntegrationTestArgs,
};

/// Test addition of `MpcScalar` types
fn test_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a random value
    let val = random_scalar();
    let my_value: ResultHandle<Scalar> = test_args.fabric.allocate_value(ResultValue::Scalar(val));

    // Share the value with the counterparty
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    // Add the values together to get the plaintext, expected result
    let expected_result = await_result(party0_value) + await_result(party1_value);

    // Secret share the values and add them together in the MPC circuit
    let party0_value = share_scalar(val, PARTY0, test_args);
    let party1_value = share_scalar(val, PARTY1, test_args);

    let res = &party0_value + &party1_value;
    let opened_res = await_result(res.open());

    assert_scalars_eq(opened_res, expected_result)
}

/// Test addition with a plaintext scalar constant
///
/// Party 0 chooses an MPC scalar and party 1 chooses a plaintext scalar
fn test_add_scalar_constant(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a random value
    let val = random_scalar();
    let my_value: ResultHandle<Scalar> = test_args.fabric.allocate_value(ResultValue::Scalar(val));

    // Share the value with the counterparty
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    let plaintext_constant = await_result(party1_value);

    // Add the values together to get the plaintext, expected result
    let expected_result = await_result(party0_value) + plaintext_constant;

    // Secret share the values and add them together in the MPC circuit
    let party0_value = share_scalar(val, PARTY0, test_args);

    let res = party0_value + plaintext_constant;
    let opened_res = await_result(res.open());

    assert_scalars_eq(opened_res, expected_result)
}

/// Test subtraction of `MpcScalar` types
fn test_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a random value
    let val = random_scalar();
    let my_value: ResultHandle<Scalar> = test_args.fabric.allocate_value(ResultValue::Scalar(val));

    // Share the value with the counterparty
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    // Subtract the values together to get the plaintext, expected result
    let expected_result = await_result(party0_value) - await_result(party1_value);

    // Secret share the values and subtract them together in the MPC circuit
    let party0_value = share_scalar(val, PARTY0, test_args);
    let party1_value = share_scalar(val, PARTY1, test_args);

    let res = &party0_value - &party1_value;
    let opened_res = await_result(res.open());

    assert_scalars_eq(opened_res, expected_result)
}

/// Test subtraction with a plaintext scalar constant
///
/// Party 0 chooses an MPC scalar and party 1 chooses a plaintext scalar
fn test_sub_scalar_constant(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a random value
    let val = random_scalar();
    let my_value: ResultHandle<Scalar> = test_args.fabric.allocate_value(ResultValue::Scalar(val));

    // Share the value with the counterparty
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    let plaintext_constant = await_result(party1_value);

    // Subtract the values together to get the plaintext, expected result
    let expected_result = await_result(party0_value) - plaintext_constant;

    // Secret share the values and subtract them together in the MPC circuit
    let party0_value = share_scalar(val, PARTY0, test_args);

    let res = party0_value - plaintext_constant;
    let opened_res = await_result(res.open());

    assert_scalars_eq(opened_res, expected_result)
}

/// Test negation of `MpcScalar` types
///
/// Only party0 chooses the value
fn test_neg(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a random value
    let val = random_scalar();
    let my_value: ResultHandle<Scalar> = test_args.fabric.allocate_value(ResultValue::Scalar(val));

    // Share the value with the counterparty
    let party0_value = share_plaintext_value(my_value, PARTY0, &test_args.fabric);

    // Negate the values together to get the plaintext, expected result
    let expected_result = -await_result(party0_value);

    // Secret share the values and negate them together in the MPC circuit
    let party0_value = share_scalar(val, PARTY0, test_args);

    let res = -&party0_value;
    let opened_res = await_result(res.open());

    assert_scalars_eq(opened_res, expected_result)
}

/// Test multiplication of `MpcScalar` types
fn test_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a random value
    let val = random_scalar();
    let my_value: ResultHandle<Scalar> = test_args.fabric.allocate_value(ResultValue::Scalar(val));

    // Share the value with the counterparty
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    // Multiply the values together to get the plaintext, expected result
    let expected_result = await_result(party0_value) * await_result(party1_value);

    // Secret share the values and multiply them together in the MPC circuit
    let party0_value = share_scalar(val, PARTY0, test_args);
    let party1_value = share_scalar(val, PARTY1, test_args);

    let res = &party0_value * &party1_value;
    let opened_res = await_result(res.open());

    assert_scalars_eq(opened_res, expected_result)
}

/// Test multiplication of `MpcScalar` types with a plaintext scalar constant
///
/// Party 0 chooses an MPC scalar and party 1 chooses a plaintext scalar
fn test_mul_scalar_constant(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a random value
    let val = random_scalar();
    let my_value: ResultHandle<Scalar> = test_args.fabric.allocate_value(ResultValue::Scalar(val));

    // Share the value with the counterparty
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    let plaintext_constant = await_result(party1_value);

    // Multiply the values together to get the plaintext, expected result
    let expected_result = await_result(party0_value) * plaintext_constant;

    // Secret share the values and multiply them together in the MPC circuit
    let party0_value = share_scalar(val, PARTY0, test_args);

    let res = party0_value * plaintext_constant;
    let opened_res = await_result(res.open());

    assert_scalars_eq(opened_res, expected_result)
}

// === Take Inventory === //

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_add",
    test_fn: test_add,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_add_scalar_constant",
    test_fn: test_add_scalar_constant,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_sub",
    test_fn: test_sub,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_sub_scalar_constant",
    test_fn: test_sub_scalar_constant,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_neg",
    test_fn: test_neg,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_mul",
    test_fn: test_mul,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_mul_scalar_constant",
    test_fn: test_mul_scalar_constant,
});
