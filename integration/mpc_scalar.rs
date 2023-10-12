//! Defines unit tests for `MpcScalarResult` types
use ark_mpc::{
    algebra::{MpcScalarResult, Scalar, ScalarResult},
    PARTY0, PARTY1,
};
use itertools::Itertools;
use rand::thread_rng;
use std::ops::Neg;

use crate::{
    helpers::{
        assert_scalar_batches_eq, assert_scalars_eq, await_result, await_result_batch,
        share_plaintext_value, share_plaintext_values_batch, share_scalar, share_scalar_batch,
    },
    IntegrationTest, IntegrationTestArgs, TestCurve,
};

/// Test addition of `MpcScalarResult` types
fn test_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a random value
    let mut rng = thread_rng();
    let val = Scalar::random(&mut rng);
    let my_value: ScalarResult<TestCurve> = test_args.fabric.allocate_scalar(val);

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
    let mut rng = thread_rng();
    let val = Scalar::random(&mut rng);
    let my_value: ScalarResult<TestCurve> = test_args.fabric.allocate_scalar(val);

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

/// Tests batch addition
fn test_batch_addition(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a set of random values
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_values = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let allocated_values = my_values
        .iter()
        .map(|v| fabric.allocate_scalar(*v))
        .collect_vec();

    // Share the values in plaintext with the counterparty
    let party0_values = share_plaintext_values_batch(&allocated_values, PARTY0, fabric);
    let party1_values = share_plaintext_values_batch(&allocated_values, PARTY1, fabric);

    // Add the values together to get the plaintext, expected result
    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&party1_values))
        .map(|(x, y)| x + y)
        .collect_vec();

    // Compute the batch sum in the MPC
    let party0_values = share_scalar_batch(my_values.clone(), PARTY0, test_args);
    let party1_values = share_scalar_batch(my_values, PARTY1, test_args);

    let res = MpcScalarResult::batch_add(&party0_values, &party1_values);
    let res_opened = await_result_batch(&MpcScalarResult::open_batch(&res));

    assert_scalar_batches_eq(expected_result, res_opened)
}

/// Test batch addition between public and shared values
fn test_batch_add_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_values = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let allocated_values = my_values
        .iter()
        .map(|v| fabric.allocate_scalar(*v))
        .collect_vec();

    // Share the values in the plaintext with the counterparty, party 1's values are made public
    let party0_values = share_plaintext_values_batch(&allocated_values, PARTY0, fabric);
    let party1_values = share_plaintext_values_batch(&allocated_values, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_values)
        .iter()
        .zip(await_result_batch(&party1_values).iter())
        .map(|(x, y)| x + y)
        .collect_vec();

    // Compute the batch sum in the MPC
    let party0_values_shared = share_scalar_batch(my_values, PARTY0, test_args);
    let res = MpcScalarResult::batch_add_public(&party0_values_shared, &party1_values);
    let res_open = await_result_batch(&MpcScalarResult::open_batch(&res));

    assert_scalar_batches_eq(res_open, expected_result)
}

/// Test subtraction of `MpcScalarResult` types
fn test_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a random value
    let mut rng = thread_rng();
    let val = Scalar::random(&mut rng);
    let my_value = test_args.fabric.allocate_scalar(val);

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
    let mut rng = thread_rng();
    let val = Scalar::random(&mut rng);
    let my_value = test_args.fabric.allocate_scalar(val);

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

/// Tests batch subtraction
fn test_batch_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a set of random values
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_values = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let allocated_values = my_values
        .iter()
        .map(|v| fabric.allocate_scalar(*v))
        .collect_vec();

    // Share the values in plaintext with the counterparty
    let party0_values = share_plaintext_values_batch(&allocated_values, PARTY0, fabric);
    let party1_values = share_plaintext_values_batch(&allocated_values, PARTY1, fabric);

    // Add the values together to get the plaintext, expected result
    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&party1_values))
        .map(|(x, y)| x - y)
        .collect_vec();

    // Compute the batch sum in the MPC
    let party0_values = share_scalar_batch(my_values.clone(), PARTY0, test_args);
    let party1_values = share_scalar_batch(my_values, PARTY1, test_args);

    let res = MpcScalarResult::batch_sub(&party0_values, &party1_values);
    let res_opened = await_result_batch(&MpcScalarResult::open_batch(&res));

    assert_scalar_batches_eq(expected_result, res_opened)
}

/// Test batch subtraction between public and shared values
fn test_batch_sub_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_values = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let allocated_values = my_values
        .iter()
        .map(|v| fabric.allocate_scalar(*v))
        .collect_vec();

    // Share the values in the plaintext with the counterparty, party 1's values are made public
    let party0_values = share_plaintext_values_batch(&allocated_values, PARTY0, fabric);
    let party1_values = share_plaintext_values_batch(&allocated_values, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_values)
        .iter()
        .zip(await_result_batch(&party1_values).iter())
        .map(|(x, y)| x - y)
        .collect_vec();

    // Compute the batch sum in the MPC
    let party0_values_shared = share_scalar_batch(my_values, PARTY0, test_args);
    let res = MpcScalarResult::batch_sub_public(&party0_values_shared, &party1_values);
    let res_open = await_result_batch(&MpcScalarResult::open_batch(&res));

    assert_scalar_batches_eq(res_open, expected_result)
}

/// Test negation of `MpcScalarResult` types
///
/// Only party0 chooses the value
fn test_neg(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a random value
    let mut rng = thread_rng();
    let val = Scalar::random(&mut rng);
    let my_value = test_args.fabric.allocate_scalar(val);

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

/// Test batch negation
fn test_batch_neg(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 chooses the values
    let n = 10;
    let mut rng = thread_rng();
    let my_values = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let allocated_values = my_values
        .iter()
        .map(|v| test_args.fabric.allocate_scalar(*v))
        .collect_vec();

    // Share the values with the counterparty
    let party0_values = share_plaintext_values_batch(&allocated_values, PARTY0, &test_args.fabric);
    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .map(Scalar::neg)
        .collect_vec();

    // Compute the negation in the MPC
    let shared_values = share_scalar_batch(my_values, PARTY0, test_args);
    let res = MpcScalarResult::batch_neg(&shared_values);
    let res_open = await_result_batch(&MpcScalarResult::open_batch(&res));

    assert_scalar_batches_eq(res_open, expected_result)
}

/// Test multiplication of `MpcScalarResult` types
fn test_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a random value
    let mut rng = thread_rng();
    let val = Scalar::random(&mut rng);
    let my_value = test_args.fabric.allocate_scalar(val);

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

/// Test multiplication of `MpcScalarResult` types with a plaintext scalar constant
///
/// Party 0 chooses an MPC scalar and party 1 chooses a plaintext scalar
fn test_mul_scalar_constant(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a random value
    let mut rng = thread_rng();
    let val = Scalar::random(&mut rng);
    let my_value = test_args.fabric.allocate_scalar(val);

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

/// Tests batch multiplication
fn test_batch_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party allocates a set of random values
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_values = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let allocated_values = my_values
        .iter()
        .map(|v| fabric.allocate_scalar(*v))
        .collect_vec();

    // Share the values in plaintext with the counterparty
    let party0_values = share_plaintext_values_batch(&allocated_values, PARTY0, fabric);
    let party1_values = share_plaintext_values_batch(&allocated_values, PARTY1, fabric);

    // Add the values together to get the plaintext, expected result
    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&party1_values))
        .map(|(x, y)| x * y)
        .collect_vec();

    // Compute the batch sum in the MPC
    let party0_values = share_scalar_batch(my_values.clone(), PARTY0, test_args);
    let party1_values = share_scalar_batch(my_values, PARTY1, test_args);

    let res = MpcScalarResult::batch_mul(&party0_values, &party1_values);
    let res_opened = await_result_batch(&MpcScalarResult::open_batch(&res));

    assert_scalar_batches_eq(expected_result, res_opened)
}

/// Test batch multiplication between public and shared values
fn test_batch_mul_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let my_values = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let allocated_values = my_values
        .iter()
        .map(|v| fabric.allocate_scalar(*v))
        .collect_vec();

    // Share the values in the plaintext with the counterparty, party 1's values are made public
    let party0_values = share_plaintext_values_batch(&allocated_values, PARTY0, fabric);
    let party1_values = share_plaintext_values_batch(&allocated_values, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_values)
        .iter()
        .zip(await_result_batch(&party1_values).iter())
        .map(|(x, y)| x * y)
        .collect_vec();

    // Compute the batch sum in the MPC
    let party0_values_shared = share_scalar_batch(my_values, PARTY0, test_args);
    let res = MpcScalarResult::batch_mul_public(&party0_values_shared, &party1_values);
    let res_open = await_result_batch(&MpcScalarResult::open_batch(&res));

    assert_scalar_batches_eq(res_open, expected_result)
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
    name: "mpc_scalar::test_batch_addition",
    test_fn: test_batch_addition,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_batch_add_public",
    test_fn: test_batch_add_public,
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
    name: "mpc_scalar::test_batch_sub",
    test_fn: test_batch_sub,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_batch_sub_public",
    test_fn: test_batch_sub_public,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_neg",
    test_fn: test_neg,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_batch_neg",
    test_fn: test_batch_neg,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_mul",
    test_fn: test_mul,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_mul_scalar_constant",
    test_fn: test_mul_scalar_constant,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_batch_mul",
    test_fn: test_batch_mul,
});

inventory::submit!(IntegrationTest {
    name: "mpc_scalar::test_batch_mul_public",
    test_fn: test_batch_mul_public,
});
