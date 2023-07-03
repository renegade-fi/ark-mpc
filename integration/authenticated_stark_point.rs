//! Integration tests for the `AuthenticatedStarkPoint` type

use mpc_ristretto::{random_point, random_scalar, PARTY0, PARTY1};

use crate::{
    helpers::{
        assert_points_eq, await_result, share_authenticated_point, share_authenticated_scalar,
    },
    IntegrationTest, IntegrationTestArgs,
};

/// Test addition with a public point
fn test_addition_public_point(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a test point, party 1 will make theirs public
    let value = random_point();

    // Share the point
    let party0_point = share_authenticated_point(value, PARTY0, test_args);
    let party1_point = share_authenticated_point(value, PARTY1, test_args);

    // Share the points in the plaintext and compute the expected result
    let plaintext_constant_point = await_result(party1_point.open());
    let expected_result = await_result(party0_point.open()) + plaintext_constant_point;

    // Add the points in the MPC circuit
    let result = party0_point + plaintext_constant_point;
    let res_open = await_result(result.open());

    assert_points_eq(res_open, expected_result)
}

/// Test addition between two secret shared points
fn test_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a test point
    let value = random_point();

    // Share the point
    let party0_point = share_authenticated_point(value, PARTY0, test_args);
    let party1_point = share_authenticated_point(value, PARTY1, test_args);

    // Share the points in the plaintext and compute the expected result
    let expected_result = await_result(party0_point.open()) + await_result(party1_point.open());

    // Add the points in the MPC circuit
    let result = party0_point + party1_point;
    let res_open = await_result(result.open());

    assert_points_eq(res_open, expected_result)
}

/// Test subtraction between a shared and a public point
fn test_sub_public_point(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a test point, party 1 will make theirs public
    let value = random_point();

    // Share the point
    let party0_point = share_authenticated_point(value, PARTY0, test_args);
    let party1_point = share_authenticated_point(value, PARTY1, test_args);

    // Share the points in the plaintext and compute the expected result
    let plaintext_constant_point = await_result(party1_point.open());
    let expected_result = await_result(party0_point.open()) - plaintext_constant_point;

    // Add the points in the MPC circuit
    let result = party0_point - plaintext_constant_point;
    let res_open = await_result(result.open());

    assert_points_eq(res_open, expected_result)
}

/// Test subtraction between two secret shared points
fn test_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a test point
    let value = random_point();

    // Share the point
    let party0_point = share_authenticated_point(value, PARTY0, test_args);
    let party1_point = share_authenticated_point(value, PARTY1, test_args);

    // Share the points in the plaintext and compute the expected result
    let expected_result = await_result(party0_point.open()) - await_result(party1_point.open());

    // Add the points in the MPC circuit
    let result = party0_point - party1_point;
    let res_open = await_result(result.open());

    assert_points_eq(res_open, expected_result)
}

/// Test negation
fn test_negation(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a test point
    let value = random_point();

    // Share the point
    let party0_point = share_authenticated_point(value, PARTY0, test_args);

    // Share the points in the plaintext and compute the expected result
    let expected_result = -await_result(party0_point.open());

    // Add the points in the MPC circuit
    let result = -party0_point;
    let res_open = await_result(result.open());

    assert_points_eq(res_open, expected_result)
}

/// Test multiplication with a public scalar
fn test_multiplication_public_scalar(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a test point, party 1 will make theirs public
    let point = random_point();
    let scalar = random_scalar();

    // Share the point
    let party0_point = share_authenticated_point(point, PARTY0, test_args);
    let party1_scalar = share_authenticated_scalar(scalar, PARTY1, test_args);

    // Share the points in the plaintext and compute the expected result
    let plaintext_constant_scalar = await_result(party1_scalar.open());
    let expected_result = await_result(party0_point.open()) * plaintext_constant_scalar;

    // Add the points in the MPC circuit
    let result = party0_point * plaintext_constant_scalar;
    let res_open = await_result(result.open());

    assert_points_eq(res_open, expected_result)
}

/// Test multiplication with a secret shared scalar
fn test_multiplication(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a test point, party 1 will make theirs public
    let point = random_point();
    let scalar = random_scalar();

    // Share the point
    let party0_point = share_authenticated_point(point, PARTY0, test_args);
    let party1_scalar = share_authenticated_scalar(scalar, PARTY1, test_args);

    // Share the points in the plaintext and compute the expected result
    let expected_result = await_result(party0_point.open()) * await_result(party1_scalar.open());

    // Add the points in the MPC circuit
    let result = party0_point * party1_scalar;
    let res_open = await_result(result.open());

    assert_points_eq(res_open, expected_result)
}

inventory::submit!(IntegrationTest {
    name: "authenticated_stark_point::test_addition_public_point",
    test_fn: test_addition_public_point
});

inventory::submit!(IntegrationTest {
    name: "authenticated_stark_point::test_add",
    test_fn: test_add
});

inventory::submit!(IntegrationTest {
    name: "authenticated_stark_point::test_sub_public_point",
    test_fn: test_sub_public_point
});

inventory::submit!(IntegrationTest {
    name: "authenticated_stark_point::test_sub",
    test_fn: test_sub
});

inventory::submit!(IntegrationTest {
    name: "authenticated_stark_point::test_negation",
    test_fn: test_negation
});

inventory::submit!(IntegrationTest {
    name: "authenticated_stark_point::test_multiplication_public_scalar",
    test_fn: test_multiplication_public_scalar
});

inventory::submit!(IntegrationTest {
    name: "authenticated_stark_point::test_multiplication",
    test_fn: test_multiplication
});
