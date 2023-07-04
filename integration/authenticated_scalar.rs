//! Integration tests for arithmetic on the `AuthenticatedScalar` type which provides
//! a malicious-secure primitive

use mpc_ristretto::{
    algebra::stark_curve::Scalar, fabric::ResultValue, random_scalar, PARTY0, PARTY1,
};

use crate::{
    helpers::{
        assert_scalars_eq, await_result, await_result_with_error, share_authenticated_scalar,
        share_plaintext_value,
    },
    IntegrationTest, IntegrationTestArgs,
};

/// Tests the authenticated opening of a shared value with no arithmetic done on it
fn test_open_authenticated(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value
    let my_val = Scalar::from(1); //random_scalar();

    // Share the values with the counterparty and compute the expected result
    let party0_value = share_authenticated_scalar(my_val, PARTY0, test_args);

    // Open the values and compute the expected result
    let value0_open = await_result(party0_value.open());
    let expected_res = value0_open;

    // Compute the result in the MPC circuit
    let res = party0_value.open_authenticated();

    // Open the result and check that it matches the expected result
    let res_open = await_result_with_error(res)?;
    assert_scalars_eq(expected_res, res_open)
}

/// Test addition with a public value
fn test_add_public_value(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value, party 1's value is made public
    let val = random_scalar();
    let my_value = test_args.fabric.allocate_value(ResultValue::Scalar(val));

    // Share the value with the counterparty in the plaintext and compute the expected result
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    let plaintext_constant: Scalar = await_result(party1_value);
    let expected_result = await_result(party0_value) + plaintext_constant;

    // Compute the result in the MPC circuit
    let party0_value = share_authenticated_scalar(val, PARTY0, test_args);
    let res = &party0_value + plaintext_constant;

    // Open the result and check that it matches the expected result
    let res_open = await_result_with_error(res.open_authenticated())?;
    assert_scalars_eq(expected_result, res_open)
}

/// Test addition between two secret shared values
fn test_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value
    let my_val = random_scalar();

    // Share the values with the counterparty and compute the expected result
    let party0_value = share_authenticated_scalar(my_val, PARTY0, test_args);
    let party1_value = share_authenticated_scalar(my_val, PARTY1, test_args);

    // Open the values and compute the expected result
    let value0_open = await_result(party0_value.open());
    let value1_open = await_result(party1_value.open());
    let expected_res = value0_open + value1_open;

    // Compute the result in the MPC circuit
    let res = &party0_value + &party1_value;

    // Open the result and check that it matches the expected result
    let res_open = await_result_with_error(res.open_authenticated())?;
    assert_scalars_eq(expected_res, res_open)
}

/// Test subtraction between a shared point and a public scalar
fn test_sub_public_scalar(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value, party 1's value is made public
    let val = random_scalar();
    let my_value = test_args.fabric.allocate_value(ResultValue::Scalar(val));

    // Share the value with the counterparty in the plaintext and compute the expected result
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    let plaintext_constant: Scalar = await_result(party1_value);
    let expected_result = await_result(party0_value) - plaintext_constant;

    // Compute the result in the MPC circuit
    let party0_value = share_authenticated_scalar(val, PARTY0, test_args);
    let res = &party0_value - plaintext_constant;

    // Open the result and check that it matches the expected result
    let res_open = await_result_with_error(res.open_authenticated())?;
    assert_scalars_eq(expected_result, res_open)
}

/// Test subtraction between two secret shared values
fn test_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value
    let my_val = random_scalar();

    // Share the values with the counterparty and compute the expected result
    let party0_value = share_authenticated_scalar(my_val, PARTY0, test_args);
    let party1_value = share_authenticated_scalar(my_val, PARTY1, test_args);

    // Open the values and compute the expected result
    let value0_open = await_result(party0_value.open());
    let value1_open = await_result(party1_value.open());
    let expected_res = value0_open - value1_open;

    // Compute the result in the MPC circuit
    let res = &party0_value - &party1_value;

    // Open the result and check that it matches the expected result
    let res_open = await_result_with_error(res.open_authenticated())?;
    assert_scalars_eq(expected_res, res_open)
}

/// Test negation of a value
fn test_neg(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value
    let my_val = random_scalar();

    // Share the values with the counterparty and compute the expected result
    let party0_value = share_authenticated_scalar(my_val, PARTY0, test_args);

    // Open the values and compute the expected result
    let value0_open = await_result(party0_value.open());
    let expected_res = -value0_open;

    // Compute the result in the MPC circuit
    let res = -&party0_value;

    // Open the result and check that it matches the expected result
    let res_open = await_result_with_error(res.open_authenticated())?;
    assert_scalars_eq(expected_res, res_open)
}

/// Test multiplication between a shared point and a public scalar
fn test_mul_public_scalar(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value, party 1's value is made public
    let val = random_scalar();
    let my_value = test_args.fabric.allocate_value(ResultValue::Scalar(val));

    // Share the value with the counterparty in the plaintext and compute the expected result
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    let plaintext_constant: Scalar = await_result(party1_value);
    let expected_result = await_result(party0_value) * plaintext_constant;

    // Compute the result in the MPC circuit
    let party0_value = share_authenticated_scalar(val, PARTY0, test_args);
    let res = &party0_value * plaintext_constant;

    // Open the result and check that it matches the expected result
    let res_open = await_result_with_error(res.open_authenticated())?;
    assert_scalars_eq(expected_result, res_open)
}

/// Test multiplication between two secret shared values
fn test_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value
    let my_val = random_scalar();

    // Share the values with the counterparty and compute the expected result
    let party0_value = share_authenticated_scalar(my_val, PARTY0, test_args);
    let party1_value = share_authenticated_scalar(my_val, PARTY1, test_args);

    // Open the values and compute the expected result
    let value0_open = await_result(party0_value.open());
    let value1_open = await_result(party1_value.open());
    let expected_res = value0_open * value1_open;

    // Compute the result in the MPC circuit
    let res = &party0_value * &party1_value;

    // Open the result and check that it matches the expected result
    let res_open = await_result_with_error(res.open_authenticated())?;
    assert_scalars_eq(expected_res, res_open)
}

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_open_authenticated",
    test_fn: test_open_authenticated,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_add_public_value",
    test_fn: test_add_public_value,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_add",
    test_fn: test_add,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_sub_public_scalar",
    test_fn: test_sub_public_scalar,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_sub",
    test_fn: test_sub,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_neg",
    test_fn: test_neg,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_mul_public_scalar",
    test_fn: test_mul_public_scalar,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_mul",
    test_fn: test_mul,
});
