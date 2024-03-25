//! Tests for more complicated operations (i.e. circuits)

use ark_mpc::{
    algebra::{AuthenticatedPointResult, AuthenticatedScalarResult, Scalar},
    random_point, PARTY0, PARTY1,
};
use itertools::Itertools;
use rand::thread_rng;

use crate::{
    helpers::{
        assert_points_eq, assert_scalars_eq, await_result, await_result_batch,
        share_plaintext_value, share_plaintext_values_batch,
    },
    IntegrationTest, IntegrationTestArgs, TestCurve, TestCurvePoint, TestScalar,
};

/// Tests an inner product between two vectors of shared scalars
///
/// We take the inner product <a, b> where party 0 chooses a, and party 1
/// chooses b
fn test_inner_product(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample local values
    let n = 100;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();

    let my_vals = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();

    // Share the values in plaintext
    let allocd_vals = my_vals.iter().map(|val| fabric.allocate_scalar(*val)).collect_vec();
    let a_plaintext =
        await_result_batch(&share_plaintext_values_batch(&allocd_vals, PARTY0, fabric));
    let b_plaintext =
        await_result_batch(&share_plaintext_values_batch(&allocd_vals, PARTY1, fabric));

    let expected_res: TestScalar = a_plaintext.iter().zip(b_plaintext).map(|(a, b)| a * b).sum();

    // Share the values
    let a = my_vals.iter().map(|val| fabric.share_scalar(*val, PARTY0)).collect_vec();
    let b = my_vals.iter().map(|val| fabric.share_scalar(*val, PARTY1)).collect_vec();

    // Compute the inner product
    let res: AuthenticatedScalarResult<TestCurve> =
        a.iter().zip(b.iter()).map(|(a, b)| a * b).sum();
    let res_open = await_result(res.open_authenticated())
        .map_err(|err| format!("error opening result: {err:?}"))?;

    assert_scalars_eq(expected_res, res_open)
}

/// Tests a multiscalar multiplication
///
/// Party 0 selects all the scalars, party 1 selects the points
fn test_msm(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample local values
    let n = 100;
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();

    let my_scalars = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
    let my_points = (0..n).map(|_| random_point()).collect_vec();

    // Share the values in plaintext
    let allocd_scalars =
        my_scalars.iter().map(|scalar| fabric.allocate_scalar(*scalar)).collect_vec();
    let allocd_points = my_points.iter().map(|point| fabric.allocate_point(*point)).collect_vec();
    let plaintext_scalars =
        await_result_batch(&share_plaintext_values_batch(&allocd_scalars, PARTY0, fabric));
    let plaintext_points =
        await_result_batch(&share_plaintext_values_batch(&allocd_points, PARTY1, fabric));

    let expected_res = TestCurvePoint::msm(&plaintext_scalars, &plaintext_points);

    // Share the values in an MPC circuit
    let shared_scalars =
        my_scalars.iter().map(|scalar| fabric.share_scalar(*scalar, PARTY0)).collect_vec();
    let shared_points =
        my_points.iter().map(|point| fabric.share_point(*point, PARTY1)).collect_vec();

    // Compare results
    let res = AuthenticatedPointResult::msm(&shared_scalars, &shared_points);
    let res_open = await_result(res.open_authenticated())
        .map_err(|err| format!("error opening msm result: {err:?}"))?;

    assert_points_eq(res_open, expected_res)
}

/// Tests evaluation of a shared polynomial on a public input
fn test_polynomial_eval(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let fabric = &test_args.fabric;
    let mut rng = thread_rng();
    let public_modifier = Scalar::random(&mut rng);
    let public_modifier =
        share_plaintext_value(fabric.allocate_scalar(public_modifier), PARTY0, fabric);

    // Party 0 and party 1 choose a public input
    let fabric = &test_args.fabric;
    let my_x = fabric.allocate_scalar(Scalar::random(&mut thread_rng()));
    let x = fabric.exchange_value(my_x.clone()) + my_x;
    let x_res = await_result(x.clone());

    // Party 0 chooses the first three coefficients, party 1 chooses the second
    // three
    let my_coeffs = (0..3).map(|_| Scalar::random(&mut rng)).collect_vec();
    let my_allocated_coeffs =
        my_coeffs.iter().map(|coeff| fabric.allocate_scalar(*coeff)).collect_vec();

    // Open the coefficients
    let first_coeffs =
        await_result_batch(&share_plaintext_values_batch(&my_allocated_coeffs, PARTY0, fabric))
            .iter()
            .map(|x| x + &public_modifier)
            .map(await_result)
            .collect_vec();
    let second_coeffs =
        await_result_batch(&share_plaintext_values_batch(&my_allocated_coeffs, PARTY1, fabric))
            .iter()
            .map(|x| x + &public_modifier)
            .map(await_result)
            .collect_vec();

    // Compute the expected result
    let expected_res = x_res
        * (first_coeffs[0]
            + x_res
                * (first_coeffs[1]
                    + x_res
                        * (first_coeffs[2]
                            + x_res
                                * (second_coeffs[0]
                                    + x_res * (second_coeffs[1] + x_res * second_coeffs[2])))));

    // Compute the result in the MPC circuit
    let first_shared_coeffs = my_coeffs
        .iter()
        .map(|coeff| fabric.share_scalar(*coeff, PARTY0))
        .map(|coeff| coeff + &public_modifier)
        .collect_vec();
    let second_shared_coeffs = my_coeffs
        .iter()
        .map(|coeff| fabric.share_scalar(*coeff, PARTY1))
        .map(|coeff| coeff + &public_modifier)
        .collect_vec();

    let res = &x
        * (&first_shared_coeffs[0]
            + &x * (&first_shared_coeffs[1]
                + &x * (&first_shared_coeffs[2]
                    + &x * (&second_shared_coeffs[0]
                        + &x * (&second_shared_coeffs[1] + &x * &second_shared_coeffs[2])))));

    let res = await_result(res.open_authenticated())
        .map_err(|err| format!("error opening polynomial eval result: {err:?}"))?;
    assert_scalars_eq(res, expected_res)
}

inventory::submit!(IntegrationTest {
    name: "circuits::test_inner_product",
    test_fn: test_inner_product
});

inventory::submit!(IntegrationTest { name: "circuits::test_msm", test_fn: test_msm });

inventory::submit!(IntegrationTest {
    name: "circuits::test_polynomial_eval",
    test_fn: test_polynomial_eval
});
