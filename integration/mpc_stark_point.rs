//! Defines tests for the `MpcStarkPoint` type and arithmetic on this type

use mpc_stark::{
    algebra::{
        scalar::{Scalar, ScalarResult},
        stark_curve::{StarkPoint, StarkPointResult},
    },
    random_point, ResultHandle, ResultValue, PARTY0, PARTY1,
};
use rand::thread_rng;

use crate::{
    helpers::{assert_points_eq, await_result, share_plaintext_value, share_point, share_scalar},
    IntegrationTest, IntegrationTestArgs,
};

/// Test addition of `MpcStarkPoint` types
fn test_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let val = random_point();
    let my_value: ResultHandle<StarkPoint> =
        test_args.fabric.allocate_value(ResultValue::Point(val));

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
    let my_value: ResultHandle<StarkPoint> =
        test_args.fabric.allocate_value(ResultValue::Point(val));

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

/// Test subtraction of `MpcStarkPoint` types
fn test_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let val = random_point();
    let my_value: ResultHandle<StarkPoint> =
        test_args.fabric.allocate_value(ResultValue::Point(val));

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
    let my_value: ResultHandle<StarkPoint> =
        test_args.fabric.allocate_value(ResultValue::Point(val));

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

/// Test negation of `MpcStarkPoint` types
fn test_neg(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let val = random_point();
    let my_value: ResultHandle<StarkPoint> =
        test_args.fabric.allocate_value(ResultValue::Point(val));

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

/// Test multiplication of an `MpcStarkPoint` type with an `MpcScalar` type
///
/// Party 0 chooses the point, party 1 chooses the scalar
fn test_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let mut rng = thread_rng();
    let point = random_point();
    let scalar = Scalar::random(&mut rng);

    // Share the values with the counterparty
    let plaintext_point: StarkPointResult = share_plaintext_value(
        test_args.fabric.allocate_value(ResultValue::Point(point)),
        PARTY0,
        &test_args.fabric,
    );
    let plaintext_scalar: ScalarResult = share_plaintext_value(
        test_args.fabric.allocate_value(ResultValue::Scalar(scalar)),
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
    let plaintext_point: StarkPointResult = share_plaintext_value(
        test_args.fabric.allocate_value(ResultValue::Point(point)),
        PARTY0,
        &test_args.fabric,
    );
    let plaintext_scalar: ScalarResult = share_plaintext_value(
        test_args.fabric.allocate_value(ResultValue::Scalar(scalar)),
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

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_add",
    test_fn: test_add,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_add_point_constant",
    test_fn: test_add_point_constant,
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
    name: "mpc_stark_point::test_neg",
    test_fn: test_neg,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_mul",
    test_fn: test_mul,
});

inventory::submit!(IntegrationTest {
    name: "mpc_stark_point::test_mul_scalar_constant",
    test_fn: test_mul_scalar_constant,
});
