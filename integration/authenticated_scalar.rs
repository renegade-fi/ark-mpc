//! Integration tests for arithmetic on the `AuthenticatedScalarResult` type
//! which provides a malicious-secure primitive

use ark_mpc::{
    algebra::{scalar_test_helpers::*, AuthenticatedScalarResult, Scalar},
    ResultValue, PARTY0, PARTY1,
};
use itertools::Itertools;
use rand::thread_rng;
use std::ops::Neg;

use crate::{
    helpers::{
        assert_err, assert_scalar_batches_eq, assert_scalars_eq, await_batch_result_with_error,
        await_result, await_result_batch, await_result_with_error, share_authenticated_scalar,
        share_authenticated_scalar_batch, share_plaintext_value, share_plaintext_values_batch,
    },
    IntegrationTest, IntegrationTestArgs, TestScalar,
};

// -----------
// | Opening |
// -----------

/// Tests the authenticated opening of a shared value with no arithmetic done on
/// it
fn test_open_authenticated(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value
    let mut rng = thread_rng();
    let my_val = Scalar::random(&mut rng);

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

/// Tests opening with a corrupted MAC
#[allow(non_snake_case)]
fn test_open_authenticated__bad_mac(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let mut rng = thread_rng();
    let my_val = Scalar::random(&mut rng);
    let mut party0_value = share_authenticated_scalar(my_val, PARTY0, test_args);

    // Corrupt the MAC
    modify_mac(&mut party0_value, Scalar::random(&mut rng));

    // Attempt to open and authenticate the value
    let res = party0_value.open_authenticated();
    assert_err(await_result_with_error(res))
}

/// Tests opening with a corrupted secret share
#[allow(non_snake_case)]
fn test_open_authenticated__bad_share(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let mut rng = thread_rng();
    let my_val = Scalar::random(&mut rng);
    let mut party0_value = share_authenticated_scalar(my_val, PARTY0, test_args);

    // Corrupt the secret share
    modify_share(&mut party0_value, Scalar::random(&mut rng));

    // Attempt to open and authenticate the value
    let res = party0_value.open_authenticated();
    assert_err(await_result_with_error(res))
}

/// Tests opening with a corrupted public modifier
#[allow(non_snake_case)]
fn test_open_authenticated__bad_public_modifier(
    test_args: &IntegrationTestArgs,
) -> Result<(), String> {
    let mut rng = thread_rng();
    let my_val = Scalar::random(&mut rng);
    let mut party0_value = share_authenticated_scalar(my_val, PARTY0, test_args);

    // Corrupt the public modifier
    modify_public_modifier(&mut party0_value, Scalar::random(&mut rng));

    // Attempt to open and authenticate the value
    let res = party0_value.open_authenticated();
    assert_err(await_result_with_error(res))
}

// --------------
// | Arithmetic |
// --------------

/// Test addition with a public value
fn test_add_public_value(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value, party 1's value is made public
    let mut rng = thread_rng();
    let val = Scalar::random(&mut rng);
    let my_value = test_args.fabric.allocate_scalar(ResultValue::Scalar(val));

    // Share the value with the counterparty in the plaintext and compute the
    // expected result
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    let plaintext_constant: TestScalar = await_result(party1_value);
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
    let mut rng = thread_rng();
    let my_val = Scalar::random(&mut rng);

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

/// Test batch addition between two secret shared values
fn test_batch_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a batch of values
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_vals = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let my_vals_allocated = fabric.allocate_scalars(my_vals.clone());

    // Share the values with the counterparty and compute the expected result
    let party0_value = share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric);
    let party1_value = share_plaintext_values_batch(&my_vals_allocated, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_value)
        .into_iter()
        .zip(await_result_batch(&party1_value))
        .map(|(x, y)| x + y)
        .collect_vec();

    // Compute the result in an MPC circuit
    let party0_values = share_authenticated_scalar_batch(my_vals.clone(), PARTY0, test_args);
    let party1_values = share_authenticated_scalar_batch(my_vals, PARTY1, test_args);

    let res = AuthenticatedScalarResult::batch_add(&party0_values, &party1_values);
    let res_open =
        await_batch_result_with_error(AuthenticatedScalarResult::open_authenticated_batch(&res))?;

    assert_scalar_batches_eq(res_open, expected_result)
}

/// Test batch addition between secret shared and public values
fn test_batch_add_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a batch of values, party 1's values are made public
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_vals = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let my_vals_allocated = fabric.allocate_scalars(my_vals.clone());

    // Share the values in the plaintext and compute the expected result
    let party0_value = share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric);
    let plaintext_value = share_plaintext_values_batch(&my_vals_allocated, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_value)
        .into_iter()
        .zip(await_result_batch(&plaintext_value))
        .map(|(x, y)| x + y)
        .collect_vec();

    // Compute the result in an MPC circuit
    let party0_values = share_authenticated_scalar_batch(my_vals, PARTY0, test_args);
    let res = AuthenticatedScalarResult::batch_add_public(&party0_values, &plaintext_value);

    let res_open =
        await_batch_result_with_error(AuthenticatedScalarResult::open_authenticated_batch(&res))?;

    assert_scalar_batches_eq(res_open, expected_result)
}

/// Test subtraction between a shared point and a public scalar
fn test_sub_public_scalar(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value, party 1's value is made public
    let mut rng = thread_rng();
    let val = Scalar::random(&mut rng);
    let my_value = test_args.fabric.allocate_scalar(ResultValue::Scalar(val));

    // Share the value with the counterparty in the plaintext and compute the
    // expected result
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    let plaintext_constant: TestScalar = await_result(party1_value);
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
    let mut rng = thread_rng();
    let my_val = Scalar::random(&mut rng);

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

/// Test batch subtraction between two secret shared values
fn test_batch_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a batch of values
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_vals = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let my_vals_allocated = fabric.allocate_scalars(my_vals.clone());

    // Share the values with the counterparty and compute the expected result
    let party0_value = share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric);
    let party1_value = share_plaintext_values_batch(&my_vals_allocated, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_value)
        .into_iter()
        .zip(await_result_batch(&party1_value))
        .map(|(x, y)| x - y)
        .collect_vec();

    // Compute the result in an MPC circuit
    let party0_values = share_authenticated_scalar_batch(my_vals.clone(), PARTY0, test_args);
    let party1_values = share_authenticated_scalar_batch(my_vals, PARTY1, test_args);

    let res = AuthenticatedScalarResult::batch_sub(&party0_values, &party1_values);
    let res_open =
        await_batch_result_with_error(AuthenticatedScalarResult::open_authenticated_batch(&res))?;

    assert_scalar_batches_eq(res_open, expected_result)
}

/// Test batch subtraction between secret shared and public values
fn test_batch_sub_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a batch of values, party 1's values are made public
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_vals = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let my_vals_allocated = fabric.allocate_scalars(my_vals.clone());

    // Share the values in the plaintext and compute the expected result
    let party0_value = share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric);
    let plaintext_value = share_plaintext_values_batch(&my_vals_allocated, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_value)
        .into_iter()
        .zip(await_result_batch(&plaintext_value))
        .map(|(x, y)| x - y)
        .collect_vec();

    // Compute the result in an MPC circuit
    let party0_values = share_authenticated_scalar_batch(my_vals, PARTY0, test_args);
    let res = AuthenticatedScalarResult::batch_sub_public(&party0_values, &plaintext_value);

    let res_open =
        await_batch_result_with_error(AuthenticatedScalarResult::open_authenticated_batch(&res))?;

    assert_scalar_batches_eq(res_open, expected_result)
}

/// Test negation of a value
fn test_neg(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value
    let mut rng = thread_rng();
    let my_val = Scalar::random(&mut rng);

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

/// Test negation of a batch of values
fn test_batch_neg(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 chooses the values alone for this test
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_vals = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let my_vals_allocated = fabric.allocate_scalars(my_vals.clone());

    // Share the values in the plaintext and compute the expected result
    let party0_value =
        await_result_batch(&share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric));
    let expected_result = party0_value.into_iter().map(Scalar::neg).collect_vec();

    // Compute the result in an MPC circuit
    let party0_values = share_authenticated_scalar_batch(my_vals, PARTY0, test_args);
    let res = AuthenticatedScalarResult::batch_neg(&party0_values);
    let res_open =
        await_batch_result_with_error(AuthenticatedScalarResult::open_authenticated_batch(&res))?;

    assert_scalar_batches_eq(res_open, expected_result)
}

/// Test multiplication between a shared point and a public scalar
fn test_mul_public_scalar(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value, party 1's value is made public
    let mut rng = thread_rng();
    let val = Scalar::random(&mut rng);
    let my_value = test_args.fabric.allocate_scalar(ResultValue::Scalar(val));

    // Share the value with the counterparty in the plaintext and compute the
    // expected result
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    let plaintext_constant: TestScalar = await_result(party1_value);
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
    let mut rng = thread_rng();
    let my_val = Scalar::random(&mut rng);

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

/// Test batch multiplication between two secret shared values
fn test_batch_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a batch of values
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_vals = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let my_vals_allocated = fabric.allocate_scalars(my_vals.clone());

    // Share the values with the counterparty and compute the expected result
    let party0_value = share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric);
    let party1_value = share_plaintext_values_batch(&my_vals_allocated, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_value)
        .into_iter()
        .zip(await_result_batch(&party1_value))
        .map(|(x, y)| x * y)
        .collect_vec();

    // Compute the result in an MPC circuit
    let party0_values = share_authenticated_scalar_batch(my_vals.clone(), PARTY0, test_args);
    let party1_values = share_authenticated_scalar_batch(my_vals, PARTY1, test_args);

    let res = AuthenticatedScalarResult::batch_mul(&party0_values, &party1_values);
    let res_open =
        await_batch_result_with_error(AuthenticatedScalarResult::open_authenticated_batch(&res))?;

    assert_scalar_batches_eq(res_open, expected_result)
}

/// Test batch addition between secret shared and public values
fn test_batch_mul_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a batch of values, party 1's values are made public
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_vals = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let my_vals_allocated = fabric.allocate_scalars(my_vals.clone());

    // Share the values in the plaintext and compute the expected result
    let party0_value = share_plaintext_values_batch(&my_vals_allocated, PARTY0, fabric);
    let plaintext_value = share_plaintext_values_batch(&my_vals_allocated, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_value)
        .into_iter()
        .zip(await_result_batch(&plaintext_value))
        .map(|(x, y)| x * y)
        .collect_vec();

    // Compute the result in an MPC circuit
    let party0_values = share_authenticated_scalar_batch(my_vals, PARTY0, test_args);
    let res = AuthenticatedScalarResult::batch_mul_public(&party0_values, &plaintext_value);

    let res_open =
        await_batch_result_with_error(AuthenticatedScalarResult::open_authenticated_batch(&res))?;

    assert_scalar_batches_eq(res_open, expected_result)
}

/// Test the case in which we add and then multiply by a public value
fn test_public_add_then_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a value, party 1's value is made public
    let mut rng = thread_rng();
    let val = Scalar::random(&mut rng);
    let my_value = test_args.fabric.allocate_scalar(ResultValue::Scalar(val));

    // Share the value with the counterparty in the plaintext and compute the
    // expected result
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    let expected_result =
        await_result((await_result(party0_value) + &party1_value) * &party1_value);

    // Compute the result in the MPC circuit
    let party0_value = share_authenticated_scalar(val, PARTY0, test_args);
    let res = (&party0_value + &party1_value) * &party1_value;

    // Open the result and check that it matches the expected result
    let res_open = await_result_with_error(res.open_authenticated())?;
    assert_scalars_eq(expected_result, res_open)
}

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_open_authenticated",
    test_fn: test_open_authenticated,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_open_authenticated__bad_mac",
    test_fn: test_open_authenticated__bad_mac,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_open_authenticated__bad_share",
    test_fn: test_open_authenticated__bad_share,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_open_authenticated__bad_public_modifier",
    test_fn: test_open_authenticated__bad_public_modifier,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_add_public_value",
    test_fn: test_add_public_value,
});

inventory::submit!(IntegrationTest { name: "authenticated_scalar::test_add", test_fn: test_add });

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_batch_add",
    test_fn: test_batch_add,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_batch_add_public",
    test_fn: test_batch_add_public,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_sub_public_scalar",
    test_fn: test_sub_public_scalar,
});

inventory::submit!(IntegrationTest { name: "authenticated_scalar::test_sub", test_fn: test_sub });

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_batch_sub",
    test_fn: test_batch_sub,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_batch_sub_public",
    test_fn: test_batch_sub_public,
});

inventory::submit!(IntegrationTest { name: "authenticated_scalar::test_neg", test_fn: test_neg });

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_batch_neg",
    test_fn: test_batch_neg,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_mul_public_scalar",
    test_fn: test_mul_public_scalar,
});

inventory::submit!(IntegrationTest { name: "authenticated_scalar::test_mul", test_fn: test_mul });

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_batch_mul",
    test_fn: test_batch_mul,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_batch_mul_public",
    test_fn: test_batch_mul_public,
});

inventory::submit!(IntegrationTest {
    name: "authenticated_scalar::test_public_add_then_mul",
    test_fn: test_public_add_then_mul,
});
