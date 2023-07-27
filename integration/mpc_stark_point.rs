//! Defines tests for the `MpcStarkPoint` type and arithmetic on this type

use itertools::Itertools;
use mpc_stark::{
    algebra::{
        mpc_stark_point::MpcStarkPointResult,
        scalar::{Scalar, ScalarResult},
        stark_curve::StarkPointResult,
    },
    random_point, PARTY0, PARTY1,
};
use rand::thread_rng;

use crate::{
    helpers::{
        assert_point_batches_eq, assert_points_eq, await_result, await_result_batch,
        share_plaintext_value, share_plaintext_values_batch, share_point, share_point_batch,
        share_scalar, share_scalar_batch,
    },
    IntegrationTest, IntegrationTestArgs,
};

/// Test addition of `MpcStarkPoint` types
fn test_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let val = random_point();
    let my_value = test_args.fabric.allocate_point(val);

    // Share the value with the counterparty
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    // Add the values together to get the plaintext, expected result
    let expected_result = await_result(party0_value) + await_result(party1_value);

    // Secret share the values and add them together in the MPC circuit
    let party0_value = share_point(val, PARTY0, test_args);
    let party1_value = share_point(val, PARTY1, test_args);

    let res = &party0_value + &party1_value;
    let opened_res = await_result(res.open());

    assert_points_eq(opened_res, expected_result)
}

/// Test addition of `MpcStarkPoint` with `StarkPoint`
///
/// Party 0 chooses an MPC point and party 1 chooses a plaintext point
fn test_add_point_constant(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let val = random_point();
    let my_value = test_args.fabric.allocate_point(val);

    // Share the value with the counterparty
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    let plaintext_constant = await_result(party1_value);

    // Add the values together to get the plaintext, expected result
    let expected_result = await_result(party0_value) + plaintext_constant;

    // Secret share the values and add them together in the MPC circuit
    let party0_value = share_point(val, PARTY0, test_args);

    let res = party0_value + plaintext_constant;
    let opened_res = await_result(res.open());

    assert_points_eq(opened_res, expected_result)
}

/// Test adding a batch of `MpcStarkPoint` types
fn test_batch_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let points = (0..n).map(|_| random_point()).collect::<Vec<_>>();
    let my_values = fabric.allocate_points(points.clone());

    // Share the values with the counterparty
    let party0_values = share_plaintext_values_batch(&my_values, PARTY0, &test_args.fabric);
    let party1_values = share_plaintext_values_batch(&my_values, PARTY1, &test_args.fabric);

    // Add the values together to get the plaintext, expected result
    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&party1_values).into_iter())
        .map(|(x, y)| x + y)
        .collect_vec();

    // Secret share the values and add them together in the MPC circuit
    let party0_values = share_point_batch(points.clone(), PARTY0, test_args);
    let party1_values = share_point_batch(points, PARTY1, test_args);

    let res = MpcStarkPointResult::batch_add(&party0_values, &party1_values);
    let opened_res = await_result_batch(&MpcStarkPointResult::open_batch(&res));

    assert_point_batches_eq(opened_res, expected_result)
}

/// Tests addition between a batch of `MpcStarkPointResult`s and `StarkPointResult`s
fn test_batch_add_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let points = (0..n).map(|_| random_point()).collect::<Vec<_>>();
    let my_values = fabric.allocate_points(points.clone());

    // Share the values with the counterparty and compute the expected result
    let party0_values = share_plaintext_values_batch(&my_values, PARTY0, &test_args.fabric);
    let plaintext_values = share_plaintext_values_batch(&my_values, PARTY1, &test_args.fabric);

    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&plaintext_values).into_iter())
        .map(|(x, y)| x + y)
        .collect_vec();

    // Secret share the values and add them together in the MPC circuit
    let party0_values = share_point_batch(points, PARTY0, test_args);
    let res = MpcStarkPointResult::batch_add_public(&party0_values, &plaintext_values);
    let res_open = await_result_batch(&MpcStarkPointResult::open_batch(&res));

    assert_point_batches_eq(res_open, expected_result)
}

/// Test subtraction of `MpcStarkPoint` types
fn test_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let val = random_point();
    let my_value = test_args.fabric.allocate_point(val);

    // Share the value with the counterparty
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    // Subtract the values together to get the plaintext, expected result
    let expected_result = await_result(party0_value) - await_result(party1_value);

    // Secret share the values and add them together in the MPC circuit
    let party0_value = share_point(val, PARTY0, test_args);
    let party1_value = share_point(val, PARTY1, test_args);

    let res = &party0_value - &party1_value;
    let opened_res = await_result(res.open());

    assert_points_eq(opened_res, expected_result)
}

/// Test subtraction of `MpcStarkPoint` with `StarkPoint`
///
/// Party 0 chooses an MPC point and party 1 chooses a plaintext point
fn test_sub_point_constant(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let val = random_point();
    let my_value = test_args.fabric.allocate_point(val);

    // Share the value with the counterparty
    let party0_value = share_plaintext_value(my_value.clone(), PARTY0, &test_args.fabric);
    let party1_value = share_plaintext_value(my_value, PARTY1, &test_args.fabric);

    let plaintext_constant = await_result(party1_value);

    // Subtract the values together to get the plaintext, expected result
    let expected_result = await_result(party0_value) - plaintext_constant;

    // Secret share the values and add them together in the MPC circuit
    let party0_value = share_point(val, PARTY0, test_args);

    let res = party0_value - plaintext_constant;
    let opened_res = await_result(res.open());

    assert_points_eq(opened_res, expected_result)
}

/// Test subtracting a batch of `MpcStarkPoint` types
fn test_batch_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let points = (0..n).map(|_| random_point()).collect::<Vec<_>>();
    let my_values = fabric.allocate_points(points.clone());

    // Share the values with the counterparty
    let party0_values = share_plaintext_values_batch(&my_values, PARTY0, &test_args.fabric);
    let party1_values = share_plaintext_values_batch(&my_values, PARTY1, &test_args.fabric);

    // Add the values together to get the plaintext, expected result
    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&party1_values).into_iter())
        .map(|(x, y)| x - y)
        .collect_vec();

    // Secret share the values and add them together in the MPC circuit
    let party0_values = share_point_batch(points.clone(), PARTY0, test_args);
    let party1_values = share_point_batch(points, PARTY1, test_args);

    let res = MpcStarkPointResult::batch_sub(&party0_values, &party1_values);
    let opened_res = await_result_batch(&MpcStarkPointResult::open_batch(&res));

    assert_point_batches_eq(opened_res, expected_result)
}

/// Test subtracting a batch of `MpcStarkPoint` types and `StarkPointResult`s
fn test_batch_sub_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let points = (0..n).map(|_| random_point()).collect::<Vec<_>>();
    let my_values = fabric.allocate_points(points.clone());

    // Share the values with the counterparty and compute the expected result
    let party0_values = share_plaintext_values_batch(&my_values, PARTY0, &test_args.fabric);
    let plaintext_values = share_plaintext_values_batch(&my_values, PARTY1, &test_args.fabric);

    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&plaintext_values).into_iter())
        .map(|(x, y)| x - y)
        .collect_vec();

    // Secret share the values and add them together in the MPC circuit
    let party0_values = share_point_batch(points, PARTY0, test_args);
    let res = MpcStarkPointResult::batch_sub_public(&party0_values, &plaintext_values);
    let res_open = await_result_batch(&MpcStarkPointResult::open_batch(&res));

    assert_point_batches_eq(res_open, expected_result)
}

/// Test negation of `MpcStarkPoint` types
fn test_neg(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let val = random_point();
    let my_value = test_args.fabric.allocate_point(val);

    // Share the value with the counterparty
    let party0_value = share_plaintext_value(my_value, PARTY0, &test_args.fabric);

    // Negate the value to get the plaintext, expected result
    let expected_result = -await_result(party0_value);

    // Secret share the values and add them together in the MPC circuit
    let party0_value = share_point(val, PARTY0, test_args);

    let res = -&party0_value;
    let opened_res = await_result(res.open());

    assert_points_eq(opened_res, expected_result)
}

/// Test negating a batch of `MpcStarkPoint` types
fn test_batch_neg(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let fabric = &test_args.fabric;
    let points = (0..n).map(|_| random_point()).collect::<Vec<_>>();
    let my_values = fabric.allocate_points(points.clone());

    // Share the values with the counterparty
    let party0_values = share_plaintext_values_batch(&my_values, PARTY0, &test_args.fabric);

    // Add the values together to get the plaintext, expected result
    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .map(|x| -x)
        .collect_vec();

    // Secret share the values and add them together in the MPC circuit
    let party0_values = share_point_batch(points, PARTY0, test_args);
    let res = MpcStarkPointResult::batch_neg(&party0_values);
    let opened_res = await_result_batch(&MpcStarkPointResult::open_batch(&res));

    assert_point_batches_eq(opened_res, expected_result)
}

/// Test multiplication of an `MpcStarkPoint` type with an `MpcScalarResult` type
///
/// Party 0 chooses the point, party 1 chooses the scalar
fn test_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let mut rng = thread_rng();
    let point = random_point();
    let scalar = Scalar::random(&mut rng);

    // Share the values with the counterparty
    let plaintext_point: StarkPointResult = share_plaintext_value(
        test_args.fabric.allocate_point(point),
        PARTY0,
        &test_args.fabric,
    );
    let plaintext_scalar: ScalarResult = share_plaintext_value(
        test_args.fabric.allocate_scalar(scalar),
        PARTY1,
        &test_args.fabric,
    );

    // Multiply the values together to get the plaintext, expected result
    let expected_result = await_result(plaintext_point) * await_result(plaintext_scalar);

    // Secret share the values and add them together in the MPC circuit
    let party0_point = share_point(point, PARTY0, test_args);
    let party1_scalar = share_scalar(scalar, PARTY1, test_args);

    let res = &party0_point * &party1_scalar;
    let opened_res = await_result(res.open());

    assert_points_eq(opened_res, expected_result)
}

/// Test multiplication with a public scalar constant
///
/// Party 0 chooses the point, party 1 chooses the scalar
fn test_mul_scalar_constant(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let mut rng = thread_rng();
    let point = random_point();
    let scalar = Scalar::random(&mut rng);

    // Share the values with the counterparty
    let plaintext_point = share_plaintext_value(
        test_args.fabric.allocate_point(point),
        PARTY0,
        &test_args.fabric,
    );
    let plaintext_scalar: ScalarResult = share_plaintext_value(
        test_args.fabric.allocate_scalar(scalar),
        PARTY1,
        &test_args.fabric,
    );

    let plaintext_constant = await_result(plaintext_scalar);

    // Multiply the values together to get the plaintext, expected result
    let expected_result = await_result(plaintext_point) * plaintext_constant;

    // Secret share the values and add them together in the MPC circuit
    let party0_point = share_point(point, PARTY0, test_args);

    let res = &party0_point * plaintext_constant;
    let opened_res = await_result(res.open());

    assert_points_eq(opened_res, expected_result)
}

/// Test multiplying a batch of `MpcStarkPoint` types
///
/// Party 0 chooses the points and party 1 chooses the scalars
fn test_batch_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let mut rng = thread_rng();
    let fabric = &test_args.fabric;
    let points = (0..n).map(|_| random_point()).collect::<Vec<_>>();
    let scalars = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();

    let my_allocated_points = fabric.allocate_points(points.clone());
    let my_allocated_scalars = fabric.allocate_scalars(scalars.clone());

    // Share the values with the counterparty
    let party0_values =
        share_plaintext_values_batch(&my_allocated_points, PARTY0, &test_args.fabric);
    let party1_values =
        share_plaintext_values_batch(&my_allocated_scalars, PARTY1, &test_args.fabric);

    // Add the values together to get the plaintext, expected result
    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&party1_values).into_iter())
        .map(|(x, y)| x * y)
        .collect_vec();

    // Secret share the values and add them together in the MPC circuit
    let party0_values = share_point_batch(points, PARTY0, test_args);
    let party1_values = share_scalar_batch(scalars, PARTY1, test_args);

    let res = MpcStarkPointResult::batch_mul(&party1_values, &party0_values);
    let opened_res = await_result_batch(&MpcStarkPointResult::open_batch(&res));

    assert_point_batches_eq(opened_res, expected_result)
}

/// Test multiplication of a batch of `MpcStarkPointResult`s with `ScalarResult`s
fn test_batch_mul_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let n = 10;
    let mut rng = thread_rng();
    let fabric = &test_args.fabric;
    let scalars = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let points = (0..n).map(|_| random_point()).collect_vec();

    let my_allocated_scalars = fabric.allocate_scalars(scalars);
    let my_allocated_points = fabric.allocate_points(points.clone());

    // Share the plaintext values with the counterparty and compute the expected result
    let party0_values = share_plaintext_values_batch(&my_allocated_points, PARTY0, fabric);
    let plaintext_values = share_plaintext_values_batch(&my_allocated_scalars, PARTY1, fabric);

    let expected_result = await_result_batch(&party0_values)
        .into_iter()
        .zip(await_result_batch(&plaintext_values).into_iter())
        .map(|(x, y)| x * y)
        .collect_vec();

    // Secret share the values and add them together in the MPC circuit
    let party0_values = share_point_batch(points, PARTY0, test_args);
    let res = MpcStarkPointResult::batch_mul_public(&plaintext_values, &party0_values);
    let res_open = await_result_batch(&MpcStarkPointResult::open_batch(&res));

    assert_point_batches_eq(res_open, expected_result)
}

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_add",
    test_fn: test_add,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_add_point_constant",
    test_fn: test_add_point_constant,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_batch_add",
    test_fn: test_batch_add,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_batch_add_public",
    test_fn: test_batch_add_public,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_sub",
    test_fn: test_sub,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_sub_point_constant",
    test_fn: test_sub_point_constant,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_batch_sub",
    test_fn: test_batch_sub,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_batch_sub_public",
    test_fn: test_batch_sub_public,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_neg",
    test_fn: test_neg,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_batch_neg",
    test_fn: test_batch_neg,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_mul",
    test_fn: test_mul,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_mul_scalar_constant",
    test_fn: test_mul_scalar_constant,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_batch_mul",
    test_fn: test_batch_mul,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_batch_mul_public",
    test_fn: test_batch_mul_public,
});
