//! Integration tests for arithmetic on the `AuthenticatedScalar` type which provides
//! a malicious-secure primitive

use mpc_ristretto::{
    algebra::stark_curve::Scalar, fabric::ResultValue, random_scalar, PARTY0, PARTY1,
};

use crate::{
    helpers::{assert_scalars_eq, await_result, share_authenticated_scalar, share_plaintext_value},
    IntegrationTest, IntegrationTestArgs,
};

/// Test addition with a public value
fn test_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
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
    let res_open = await_result(res.open());
    assert_scalars_eq(expected_result, res_open)
}

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_add",
    test_fn: test_add,
});
