//! Integration tests for the `AuthenticatedPointResult` type

use ark_mpc::{
    algebra::{
        authenticated_curve::{
            test_helpers::{modify_mac, modify_public_modifier, modify_share},
            AuthenticatedPointResult,
        },
        scalar::Scalar,
    },
    random_point, PARTY0, PARTY1,
};
use itertools::Itertools;
use rand::thread_rng;

use crate::{
    helpers::{
        assert_err, assert_point_batches_eq, assert_points_eq, await_batch_result_with_error,
        await_result, await_result_batch, await_result_with_error, share_authenticated_point,
        share_authenticated_point_batch, share_authenticated_scalar, share_plaintext_values_batch,
    },
    IntegrationTest, IntegrationTestArgs,
};

// -----------
// | Opening |
// -----------

/// Test opening a shared point correctly
fn test_open_authenticated(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a test point
    let my_val = random_point();
    let shared_val = share_authenticated_point(my_val, PARTY0, test_args);

    // Open the point first without authenticating
    let expected_res = await_result(shared_val.open());

    let val_open = await_result_with_error(shared_val.open_authenticated())?;
    assert_points_eq(val_open, expected_res)
}

/// Test opening a shared point with a corrupted MAC
#[allow(non_snake_case)]
fn test_open_authenticated__bad_mac(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a test point
    let my_val = random_point();
    let mut shared_val = share_authenticated_point(my_val, PARTY0, test_args);

    // Corrupt the MAC and attempt to open
    modify_mac(&mut shared_val, random_point());
    let res_open = await_result_with_error(shared_val.open_authenticated());
    assert_err(res_open)
}

/// Test opening a shared point with a corrupted secret share
#[allow(non_snake_case)]
fn test_open_authenticated__bad_share(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a test point
    let my_val = random_point();
    let mut shared_val = share_authenticated_point(my_val, PARTY0, test_args);

    // Corrupt the share and attempt to open
    modify_share(&mut shared_val, random_point());
    let res_open = await_result_with_error(shared_val.open_authenticated());
    assert_err(res_open)
}

/// Test opening a shared point with a corrupted public modifier
#[allow(non_snake_case)]
fn test_open_authenticated__bad_public_modifier(
    test_args: &IntegrationTestArgs,
) -> Result<(), String> {
    // Sample a test point
    let my_val = random_point();
    let mut shared_val = share_authenticated_point(my_val, PARTY0, test_args);

    // Corrupt the public modifier and attempt to open
    modify_public_modifier(&mut shared_val, random_point());
    let res_open = await_result_with_error(shared_val.open_authenticated());
    assert_err(res_open)
}

// --------------
// | Arithmetic |
// --------------

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
    let res_open = await_result_with_error(result.open_authenticated())?;

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
    let res_open = await_result_with_error(result.open_authenticated())?;

    assert_points_eq(res_open, expected_result)
}

/// Test batch addition
fn test_batch_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let my_vals = (0..n).map(|_| random_point()).collect_vec();
    let my_vals_allocated = fabric.allocate_points(my_vals.clone());

    // Share the plaintext value with the counterparty and compute the result
    let party0_values = share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric);
    let party1_values = share_plaintext_values_batch(&my_vals_allocated, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&party1_values).into_iter())
        .map(|(x, y)| x + y)
        .collect_vec();

    // Add the points in the MPC circuit
    let party0_values = share_authenticated_point_batch(my_vals.clone(), PARTY0, test_args);
    let party1_values = share_authenticated_point_batch(my_vals, PARTY1, test_args);

    let res = AuthenticatedPointResult::batch_add(&party0_values, &party1_values);
    let res_open =
        await_batch_result_with_error(AuthenticatedPointResult::open_authenticated_batch(&res))?;

    assert_point_batches_eq(res_open, expected_result)
}

/// Test addition between a batch of `AuthenticatedPointResult`s and `CurvePoint`s
fn test_batch_add_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let my_vals = (0..n).map(|_| random_point()).collect_vec();
    let my_vals_allocated = fabric.allocate_points(my_vals.clone());

    // Share the plaintext value with the counterparty and compute the result
    let party0_values = share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric);
    let plaintext_values = share_plaintext_values_batch(&my_vals_allocated, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&plaintext_values).into_iter())
        .map(|(x, y)| x + y)
        .collect_vec();

    // Add the points in the MPC circuit
    let party0_values = share_authenticated_point_batch(my_vals, PARTY0, test_args);

    let res = AuthenticatedPointResult::batch_add_public(&party0_values, &plaintext_values);
    let res_open =
        await_batch_result_with_error(AuthenticatedPointResult::open_authenticated_batch(&res))?;

    assert_point_batches_eq(res_open, expected_result)
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
    let res_open = await_result_with_error(result.open_authenticated())?;

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
    let res_open = await_result_with_error(result.open_authenticated())?;

    assert_points_eq(res_open, expected_result)
}

/// Test batch subtraction
fn test_batch_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let my_vals = (0..n).map(|_| random_point()).collect_vec();
    let my_vals_allocated = fabric.allocate_points(my_vals.clone());

    // Share the plaintext value with the counterparty and compute the result
    let party0_values = share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric);
    let party1_values = share_plaintext_values_batch(&my_vals_allocated, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&party1_values).into_iter())
        .map(|(x, y)| x - y)
        .collect_vec();

    // Add the points in the MPC circuit
    let party0_values = share_authenticated_point_batch(my_vals.clone(), PARTY0, test_args);
    let party1_values = share_authenticated_point_batch(my_vals, PARTY1, test_args);

    let res = AuthenticatedPointResult::batch_sub(&party0_values, &party1_values);
    let res_open =
        await_batch_result_with_error(AuthenticatedPointResult::open_authenticated_batch(&res))?;

    assert_point_batches_eq(res_open, expected_result)
}

/// Test addition between a batch of `AuthenticatedPointResult`s and `CurvePoint`s
fn test_batch_sub_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let my_vals = (0..n).map(|_| random_point()).collect_vec();
    let my_vals_allocated = fabric.allocate_points(my_vals.clone());

    // Share the plaintext value with the counterparty and compute the result
    let party0_values = share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric);
    let plaintext_values = share_plaintext_values_batch(&my_vals_allocated, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&plaintext_values).into_iter())
        .map(|(x, y)| x - y)
        .collect_vec();

    // Add the points in the MPC circuit
    let party0_values = share_authenticated_point_batch(my_vals, PARTY0, test_args);

    let res = AuthenticatedPointResult::batch_sub_public(&party0_values, &plaintext_values);
    let res_open =
        await_batch_result_with_error(AuthenticatedPointResult::open_authenticated_batch(&res))?;

    assert_point_batches_eq(res_open, expected_result)
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
    let res_open = await_result_with_error(result.open_authenticated())?;

    assert_points_eq(res_open, expected_result)
}

/// Test batch negation
fn test_batch_negation(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let my_values = (0..n).map(|_| random_point()).collect_vec();
    let my_values_allocated = fabric.allocate_points(my_values.clone());

    // Party 0's values are used for the negation
    let party0_values = share_plaintext_values_batch(&my_values_allocated, PARTY0, fabric);
    let expected_res = await_result_batch(&party0_values)
        .into_iter()
        .map(|x| -x)
        .collect_vec();

    // Compute the expected result in an MPC circuit
    let party0_values = share_authenticated_point_batch(my_values, PARTY0, test_args);
    let res = AuthenticatedPointResult::batch_neg(&party0_values);
    let res_open =
        await_batch_result_with_error(AuthenticatedPointResult::open_authenticated_batch(&res))?;

    assert_point_batches_eq(expected_res, res_open)
}

/// Test multiplication with a public scalar
fn test_multiplication_public_scalar(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a test point, party 1 will make theirs public
    let mut rng = thread_rng();
    let point = random_point();
    let scalar = Scalar::random(&mut rng);

    // Share the point
    let party0_point = share_authenticated_point(point, PARTY0, test_args);
    let party1_scalar = share_authenticated_scalar(scalar, PARTY1, test_args);

    // Share the points in the plaintext and compute the expected result
    let plaintext_constant_scalar = await_result(party1_scalar.open());
    let expected_result = await_result(party0_point.open()) * plaintext_constant_scalar;

    // Add the points in the MPC circuit
    let result = party0_point * plaintext_constant_scalar;
    let res_open = await_result_with_error(result.open_authenticated())?;

    assert_points_eq(res_open, expected_result)
}

/// Test multiplication with a secret shared scalar
fn test_multiplication(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a test point, party 1 will make theirs public
    let mut rng = thread_rng();
    let point = random_point();
    let scalar = Scalar::random(&mut rng);

    // Share the point
    let party0_point = share_authenticated_point(point, PARTY0, test_args);
    let party1_scalar = share_authenticated_scalar(scalar, PARTY1, test_args);

    // Share the points in the plaintext and compute the expected result
    let expected_result = await_result(party0_point.open()) * await_result(party1_scalar.open());

    // Add the points in the MPC circuit
    let result = party0_point * party1_scalar;
    let res_open = await_result_with_error(result.open_authenticated())?;

    assert_points_eq(res_open, expected_result)
}

/// Test batch multiplication
fn test_batch_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let my_vals = (0..n).map(|_| random_point()).collect_vec();
    let my_vals_allocated = fabric.allocate_points(my_vals.clone());

    // Share the plaintext value with the counterparty and compute the result
    let party0_values = share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric);
    let party1_values = share_plaintext_values_batch(&my_vals_allocated, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&party1_values).into_iter())
        .map(|(x, y)| x - y)
        .collect_vec();

    // Add the points in the MPC circuit
    let party0_values = share_authenticated_point_batch(my_vals.clone(), PARTY0, test_args);
    let party1_values = share_authenticated_point_batch(my_vals, PARTY1, test_args);

    let res = AuthenticatedPointResult::batch_sub(&party0_values, &party1_values);
    let res_open =
        await_batch_result_with_error(AuthenticatedPointResult::open_authenticated_batch(&res))?;

    assert_point_batches_eq(res_open, expected_result)
}

/// Test addition between a batch of `AuthenticatedPointResult`s and `CurvePoint`s
fn test_batch_mul_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let my_vals = (0..n).map(|_| random_point()).collect_vec();
    let my_vals_allocated = fabric.allocate_points(my_vals.clone());

    // Share the plaintext value with the counterparty and compute the result
    let party0_values = share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric);
    let plaintext_values = share_plaintext_values_batch(&my_vals_allocated, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&plaintext_values).into_iter())
        .map(|(x, y)| x - y)
        .collect_vec();

    // Add the points in the MPC circuit
    let party0_values = share_authenticated_point_batch(my_vals, PARTY0, test_args);

    let res = AuthenticatedPointResult::batch_sub_public(&party0_values, &plaintext_values);
    let res_open =
        await_batch_result_with_error(AuthenticatedPointResult::open_authenticated_batch(&res))?;

    assert_point_batches_eq(res_open, expected_result)
}

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_open_authenticated",
    test_fn: test_open_authenticated
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_open_authenticated__bad_mac",
    test_fn: test_open_authenticated__bad_mac
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_open_authenticated__bad_share",
    test_fn: test_open_authenticated__bad_share
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_open_authenticated__bad_public_modifier",
    test_fn: test_open_authenticated__bad_public_modifier
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_addition_public_point",
    test_fn: test_addition_public_point
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_add",
    test_fn: test_add
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_batch_add",
    test_fn: test_batch_add
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_batch_add_public",
    test_fn: test_batch_add_public
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_sub_public_point",
    test_fn: test_sub_public_point
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_sub",
    test_fn: test_sub
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_batch_sub",
    test_fn: test_batch_sub
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_batch_sub_public",
    test_fn: test_batch_sub_public
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_negation",
    test_fn: test_negation
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_batch_negation",
    test_fn: test_batch_negation
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_multiplication_public_scalar",
    test_fn: test_multiplication_public_scalar
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_multiplication",
    test_fn: test_multiplication
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_batch_mul",
    test_fn: test_batch_mul
});

inventory::submit!(IntegrationTest {
    name: "authenticated_curve_point::test_batch_mul_public",
    test_fn: test_batch_mul_public
});
