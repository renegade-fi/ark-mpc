use ::mpc_ristretto::{Visibility, Visible};
use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, error::MpcNetworkError, mpc_scalar::scalar_to_u64,
    network::QuicTwoPartyNet,
};
use rand::{thread_rng, RngCore};

use crate::{mpc_scalar::PartyIDBeaverSource, IntegrationTest, IntegrationTestArgs};

fn test_share_and_open(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 hold 2 and party 1 holds 3
    let value = if test_args.party_id == 0 { 2 } else { 3 };

    // Allocate an authenticated scalar in the network
    let my_value = AuthenticatedScalar::from_private_u64(
        value,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(),
        test_args.beaver_source.clone(),
    );

    // Share both values
    let shared_secret1 = my_value
        .share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing secret: {:?}", err))?;
    let shared_secret2 = my_value
        .share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    // Open both values and verify their correctness
    let opened_value1 = shared_secret1
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let opened_value2 = shared_secret2
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;

    if !opened_value1.value().value().eq(&Scalar::from(2u64)) {
        return Err(format!(
            "Expected {}, got {}",
            2,
            scalar_to_u64(&opened_value1.value().value())
        ));
    }

    if !opened_value2.value().value().eq(&Scalar::from(3u64)) {
        return Err(format!(
            "Expected {}, got {}",
            3,
            scalar_to_u64(&opened_value2.value().value())
        ));
    }

    Ok(())
}

fn test_authenticated_open(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 hold 2 and party 1 holds 3
    let value = if test_args.party_id == 0 { 2 } else { 3 };

    // Allocate an authenticated scalar in the network
    let my_value = AuthenticatedScalar::from_private_u64(
        value,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(),
        test_args.beaver_source.clone(),
    );

    // Share both values
    let shared_secret1 = my_value
        .share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing secret: {:?}", err))?;
    let shared_secret2 = my_value
        .share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    // Perform an authenticated opening of both values
    let opened_value1 = shared_secret1
        .open_and_authenticate()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let opened_value2 = shared_secret2
        .open_and_authenticate()
        .map_err(|err| format!("Error opening value: {:?}", err))?;

    if !opened_value1.value().value().eq(&Scalar::from(2u64)) {
        return Err(format!(
            "Expected {}, got {}",
            2,
            scalar_to_u64(&opened_value1.value().value())
        ));
    }

    if !opened_value2.value().value().eq(&Scalar::from(3u64)) {
        return Err(format!(
            "Expected {}, got {}",
            3,
            scalar_to_u64(&opened_value2.value().value())
        ));
    }

    Ok(())
}

/// Tests the ability to batch open and authenticate values
fn test_batch_open_and_authenticate(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 shares a vector of values with party 1
    let values: Vec<AuthenticatedScalar<QuicTwoPartyNet, PartyIDBeaverSource>> =
        vec![1u64, 2u64, 3u64]
            .into_iter()
            .map(|value| {
                AuthenticatedScalar::from_private_u64(
                    value,
                    test_args.mac_key.clone(),
                    test_args.net_ref.clone(),
                    test_args.beaver_source.clone(),
                )
            })
            .collect();

    // Share the values, open them, and verify the result
    let mut shared_values =
        AuthenticatedScalar::batch_share_secrets(0 /* party_id */, &values)
            .map_err(|err| format!("Error sharing values: {:?}", err))?;

    let opened_values = AuthenticatedScalar::batch_open_and_authenticate(&shared_values)
        .map_err(|err| format!("Error opening and authenticating: {:?}", err))?;

    if opened_values.ne(&values) {
        return Err(format!("Expected: {:?}, got {:?}", values, shared_values));
    }

    // Now party 1 tries to corrupt a shared value, verify that opening fails
    if test_args.party_id == 1 {
        shared_values[1] += Scalar::from(5u64);
    }

    AuthenticatedScalar::batch_open_and_authenticate(&shared_values).map_or(Ok(()), |_| {
        Err("Expected authentication error, authentication succeeded...".to_string())
    })?;

    Ok(())
}

fn test_authenticated_open_failure(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 tries to add an extra value to the result
    let value = if test_args.party_id == 0 { 2 } else { 3 };
    let my_shared_value = AuthenticatedScalar::from_private_u64(
        value,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(),
        test_args.beaver_source.clone(),
    );

    // Parites share values
    let shared_value1 = my_shared_value
        .share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_value2 = my_shared_value
        .share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    // Party 0 attempts to corrupt the result
    let res = {
        if test_args.party_id == 0 {
            shared_value1 + shared_value2 + Scalar::from(5u64)
        } else {
            shared_value1 + shared_value2
        }
    };

    // Expect authentication to fail
    res.open_and_authenticate().map_or(Ok(()), |_| {
        Err("Expected authentication failure, authentication passed...".to_string())
    })?;

    Ok(())
}

fn test_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Parties each hold a secret value and add them together, result is authenticated
    let value = if test_args.party_id == 0 { 2 } else { 3 };
    let my_value = AuthenticatedScalar::from_private_u64(
        value,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(),
        test_args.beaver_source.clone(),
    );

    let shared_value1 = my_value
        .share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_value2 = my_value
        .share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let public_value = AuthenticatedScalar::from_public_u64(
        10,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(),
        test_args.beaver_source.clone(),
    );

    // Authenticate and open the values, assert that it is the expected value
    // Shared value + shared_value
    let shared_shared = (&shared_value1 + &shared_value2)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating value: {:?}", err))?;

    if shared_shared.to_scalar().ne(&Scalar::from(5u64)) {
        return Err(format!(
            "Expected {}, got {}",
            5,
            scalar_to_u64(&shared_shared.to_scalar())
        ));
    }

    // Public value + shared value
    let public_shared = (&public_value + &shared_value1)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating value: {:?}", err))?;

    if public_shared.to_scalar().ne(&Scalar::from(12u64)) {
        return Err(format!(
            "Expected {}, got {}",
            12,
            scalar_to_u64(&public_shared.to_scalar())
        ));
    }

    // Public value + public value
    let public_public = &public_value + &public_value;
    if public_public.visibility() != Visibility::Public {
        return Err(format!(
            "Expected visibility Public, got {:?}",
            public_public.visibility()
        ));
    }

    if public_public.to_scalar().ne(&Scalar::from(20u64)) {
        return Err(format!(
            "Expected {}, got {}",
            20,
            scalar_to_u64(&public_public.to_scalar())
        ));
    }

    Ok(())
}

fn test_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 holds 10 and party 1 holds 5
    let value = if test_args.party_id == 0 { 10 } else { 5 };
    let my_value = AuthenticatedScalar::from_private_u64(
        value,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(),
        test_args.beaver_source.clone(),
    );

    // Shared values
    let shared_value1 = my_value
        .share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_value2 = my_value
        .share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let public_value = AuthenticatedScalar::from_public_u64(
        15,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(),
        test_args.beaver_source.clone(),
    );

    // Shared value - shared value
    let shared_shared = (&shared_value1 - &shared_value2)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating value: {:?}", err))?;
    if shared_shared.to_scalar().ne(&Scalar::from(5u64)) {
        return Err(format!(
            "Expected {}, got {}",
            5,
            scalar_to_u64(&shared_shared.to_scalar())
        ));
    }

    // Public value - shared value
    let public_shared = (&public_value - &shared_value1)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating value: {:?}", err))?;
    if public_shared.to_scalar().ne(&Scalar::from(5u64)) {
        return Err(format!(
            "Expected {}, got {}",
            5,
            scalar_to_u64(&public_shared.to_scalar())
        ));
    }

    // Public value - public value
    #[allow(clippy::eq_op)]
    let public_public = (&public_value - &public_value)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating value: {:?}", err))?;
    if public_public.to_scalar().ne(&Scalar::from(0u64)) {
        return Err(format!(
            "Expected {}, got {}",
            0,
            scalar_to_u64(&public_public.to_scalar())
        ));
    }

    Ok(())
}

fn test_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let value = if test_args.party_id == 0 { 5 } else { 6 };
    let my_value = AuthenticatedScalar::from_private_u64(
        value,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(),
        test_args.beaver_source.clone(),
    );

    // Share the values
    let shared_value1 = my_value
        .share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_value2 = my_value
        .share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let public_value = AuthenticatedScalar::from_public_u64(
        7,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(),
        test_args.beaver_source.clone(),
    );

    // Shared * shared
    let shared_shared = (&shared_value1 * &shared_value2)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating value: {:?}", err))?;
    if shared_shared.to_scalar().ne(&Scalar::from(30u64)) {
        return Err(format!(
            "Expected {}, got {}",
            30,
            scalar_to_u64(&shared_shared.to_scalar())
        ));
    }

    // Public * shared
    let public_shared = (&public_value * &shared_value1)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating value: {:?}", err))?;
    if public_shared.to_scalar().ne(&Scalar::from(35u64)) {
        return Err(format!(
            "Expected {}, got {}",
            35,
            scalar_to_u64(&public_shared.to_scalar())
        ));
    }

    // Public * public
    let public_public = &public_value * &public_value;
    if public_public.visibility() != Visibility::Public {
        return Err(format!(
            "Expected Public visibility, got {:?}",
            public_public.visibility()
        ));
    }

    public_public
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating value: {:?}", err))?;
    if public_public.to_scalar().ne(&Scalar::from(49u64)) {
        return Err(format!(
            "Expected {}, got {}",
            49,
            scalar_to_u64(&public_public.to_scalar())
        ));
    }

    Ok(())
}

/// Test the batch_mul method on authenticated values
fn test_batch_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Intersperse private and public values
    let values = (0..10)
        .map(|val| {
            if val % 2 == 0 {
                AuthenticatedScalar::from_public_u64(
                    val,
                    test_args.mac_key.clone(),
                    test_args.net_ref.clone(),
                    test_args.beaver_source.clone(),
                )
            } else {
                let val = AuthenticatedScalar::from_private_u64(
                    val as u64,
                    test_args.mac_key.clone(),
                    test_args.net_ref.clone(),
                    test_args.beaver_source.clone(),
                );

                val.share_secret(0 /* party_id */).unwrap()
            }
        })
        .collect::<Vec<_>>();

    // Multiply the values array with itself
    let res = AuthenticatedScalar::batch_mul(&values, &values)
        .map_err(|err| format!("Error performing batch_mul: {:?}", err))?;

    // Convert to u64 for comparison
    let res_u64 = res
        .iter()
        .map(|val| scalar_to_u64(&val.open_and_authenticate().unwrap().to_scalar()))
        .collect::<Vec<_>>();

    let expected = (0..10).map(|x| (x * x) as u64).collect::<Vec<_>>();
    if expected.ne(&res_u64) {
        return Err(format!("Expected: {:?}, got {:?}", expected, res_u64));
    }

    Ok(())
}

/// Tests the batch mul method on all public values
fn test_batch_mul_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let values = (0..10)
        .map(|x| {
            AuthenticatedScalar::from_public_u64(
                x,
                test_args.mac_key.clone(),
                test_args.net_ref.clone(),
                test_args.beaver_source.clone(),
            )
        })
        .collect::<Vec<_>>();
    let res = AuthenticatedScalar::batch_mul(&values, &values)
        .map_err(|err| format!("Error computing batch mul: {:?}", err))?
        .iter()
        .map(|val| scalar_to_u64(&val.to_scalar()))
        .collect::<Vec<_>>();

    let expected_res = (0u64..10).map(|x| x * x).collect::<Vec<_>>();

    if res.ne(&expected_res) {
        return Err(format!("Expected {:?}, got {:?}", expected_res, res));
    }

    Ok(())
}

fn test_product(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let values: Vec<u64> = if test_args.party_id == 0 {
        vec![1, 2, 3]
    } else {
        vec![4, 5, 6]
    };
    let my_values = values
        .into_iter()
        .map(|value| {
            AuthenticatedScalar::from_private_u64(
                value,
                test_args.mac_key.clone(),
                test_args.net_ref.clone(),
                test_args.beaver_source.clone(),
            )
        })
        .collect::<Vec<AuthenticatedScalar<QuicTwoPartyNet, PartyIDBeaverSource>>>();

    // Share the values
    let shared_values1 = my_values.iter()
        .map(|value| value.share_secret(0 /* party_id */))
        .collect::<Result<Vec<AuthenticatedScalar<QuicTwoPartyNet, PartyIDBeaverSource>>, MpcNetworkError>>()
        .map_err(|err| format!("Error sharing values: {:?}", err))?;

    let shared_values2 = my_values.iter()
        .map(|value| value.share_secret(1 /* party_id */))
        .collect::<Result<Vec<AuthenticatedScalar<QuicTwoPartyNet, PartyIDBeaverSource>>, MpcNetworkError>>()
        .map_err(|err| format!("Error sharing values: {:?}", err))?;

    // Take product, open and authenticate, then enforce equality
    let product: AuthenticatedScalar<QuicTwoPartyNet, PartyIDBeaverSource> =
        shared_values1.iter().chain(shared_values2.iter()).product();

    let product_open = product
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating value: {:?}", err))?;
    if product_open.to_scalar().ne(&Scalar::from(720u64)) {
        return Err(format!(
            "Expected {}, got {}",
            720,
            scalar_to_u64(&product_open.to_scalar())
        ));
    }

    Ok(())
}

fn test_sum(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let values: Vec<u64> = if test_args.party_id == 0 {
        vec![1, 2, 3]
    } else {
        vec![4, 5, 6]
    };
    let my_values = values
        .into_iter()
        .map(|value| {
            AuthenticatedScalar::from_private_u64(
                value,
                test_args.mac_key.clone(),
                test_args.net_ref.clone(),
                test_args.beaver_source.clone(),
            )
        })
        .collect::<Vec<AuthenticatedScalar<QuicTwoPartyNet, PartyIDBeaverSource>>>();

    // Share the values
    let shared_values1 = my_values.iter()
        .map(|value| value.share_secret(0 /* party_id */))
        .collect::<Result<Vec<AuthenticatedScalar<QuicTwoPartyNet, PartyIDBeaverSource>>, MpcNetworkError>>()
        .map_err(|err| format!("Error sharing values: {:?}", err))?;

    let shared_values2 = my_values.iter()
        .map(|value| value.share_secret(1 /* party_id */))
        .collect::<Result<Vec<AuthenticatedScalar<QuicTwoPartyNet, PartyIDBeaverSource>>, MpcNetworkError>>()
        .map_err(|err| format!("Error sharing values: {:?}", err))?;

    // Take the sum, open and authenticate, then enforce equality
    let sum: AuthenticatedScalar<QuicTwoPartyNet, PartyIDBeaverSource> =
        shared_values1.iter().chain(shared_values2.iter()).sum();

    let sum_open = sum
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating: {:?}", err))?;
    if sum_open.to_scalar().ne(&Scalar::from(21u64)) {
        return Err(format!(
            "Expected {}, got {}",
            21,
            scalar_to_u64(&sum_open.to_scalar())
        ));
    }

    Ok(())
}

fn test_linear_combination(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let values: Vec<u64> = if test_args.party_id == 0 {
        vec![1, 2, 3]
    } else {
        vec![4, 5, 6]
    };
    let my_values = values
        .into_iter()
        .map(|value| {
            AuthenticatedScalar::from_private_u64(
                value,
                test_args.mac_key.clone(),
                test_args.net_ref.clone(),
                test_args.beaver_source.clone(),
            )
        })
        .collect::<Vec<AuthenticatedScalar<QuicTwoPartyNet, PartyIDBeaverSource>>>();

    // Share the values
    let shared_values = my_values.iter()
        .map(|value| value.share_secret(0 /* party_id */))
        .collect::<Result<Vec<AuthenticatedScalar<QuicTwoPartyNet, PartyIDBeaverSource>>, MpcNetworkError>>()
        .map_err(|err| format!("Error sharing values: {:?}", err))?;

    let shared_coefficients = my_values.iter()
        .map(|value| value.share_secret(1 /* party_id */))
        .collect::<Result<Vec<AuthenticatedScalar<QuicTwoPartyNet, PartyIDBeaverSource>>, MpcNetworkError>>()
        .map_err(|err| format!("Error sharing values: {:?}", err))?;

    // Correctly open the linear combination
    let mut res = AuthenticatedScalar::linear_combination(&shared_values, &shared_coefficients)
        .map_err(|err| format!("Error computing linear combination: {:?}", err))?;
    let res_open = res
        .open_and_authenticate()
        .map_err(|err| format!("Error opening linear combination result: {:?}", err))?;

    if res_open.to_scalar().ne(&Scalar::from(32u64)) {
        return Err(format!(
            "Expected {}, got {}",
            32,
            scalar_to_u64(&res.to_scalar())
        ));
    }

    // Party 1 now tries to corrupt the linear combination, verify that authentication of the result fails
    if test_args.party_id == 1 {
        res *= Scalar::from(5u64);
    }

    res.open_and_authenticate().map_or(Ok(()), |_| {
        Err("Expected authentication failure, authentication passed...".to_string())
    })?;

    Ok(())
}

/// Tests a random linear combination
fn test_random_linear_comb(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Parties take turns allocating coefficients and values
    let n = 15;
    let mut rng = thread_rng();

    let mut values = Vec::new();
    let mut coeffs = Vec::new();
    for i in 0..n {
        values.push(
            AuthenticatedScalar::from_private_u64(
                (rng.next_u32() / 2) as u64,
                test_args.mac_key.clone(),
                test_args.net_ref.clone(),
                test_args.beaver_source.clone(),
            )
            .share_secret(i % 2 /* party_id */)
            .unwrap(),
        );

        coeffs.push(
            AuthenticatedScalar::from_private_u64(
                (rng.next_u32() / 2) as u64,
                test_args.mac_key.clone(),
                test_args.net_ref.clone(),
                test_args.beaver_source.clone(),
            )
            .share_secret(1 - (i % 2) /* party_id */)
            .unwrap(),
        );
    }

    // Compute linear combination
    let mut res = AuthenticatedScalar::linear_combination(&values, &coeffs)
        .map_err(|err| format!("Error computing linear combination: {:?}", err))?;
    let res_open = res
        .open_and_authenticate()
        .map_err(|err| format!("Error opening linear combination result: {:?}", err))?;

    // Open the coeffs and scalars to compute the expected result
    let opened_scalars = AuthenticatedScalar::batch_open_and_authenticate(&values)
        .map_err(|err| format!("Error opening values: {:?}", err))?
        .iter()
        .map(|scalar| scalar_to_u64(&scalar.to_scalar()))
        .collect::<Vec<_>>();
    let opened_coeffs = AuthenticatedScalar::batch_open_and_authenticate(&coeffs)
        .map_err(|err| format!("Error opening coeffs: {:?}", err))?
        .iter()
        .map(|scalar| scalar_to_u64(&scalar.to_scalar()))
        .collect::<Vec<_>>();

    let mut expected_res = 0u128;
    for (scalar, coeff) in opened_scalars.iter().zip(opened_coeffs.iter()) {
        expected_res += (scalar * coeff) as u128;
    }

    if res_open.to_scalar().ne(&Scalar::from(expected_res)) {
        return Err(format!(
            "Expected {:?}, got {:?}",
            expected_res,
            scalar_to_u64(&res.to_scalar())
        ));
    }

    // Party 0 tries to corrupt the linear combination, verify that opening fails
    if test_args.party_id == 0 {
        res += Scalar::from(5u64);
    }

    res.open_and_authenticate().map_or(Ok(()), |_| {
        Err("Expected authentication failure, authentication passed...".to_string())
    })?;

    Ok(())
}

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_share_and_open",
    test_fn: test_share_and_open,
});

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_authenticated_open",
    test_fn: test_authenticated_open
});

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_batch_open_and_authenticate",
    test_fn: test_batch_open_and_authenticate,
});

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_authenticated_open_failure",
    test_fn: test_authenticated_open_failure,
});

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_add",
    test_fn: test_add,
});

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_sub",
    test_fn: test_sub,
});

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_mul",
    test_fn: test_mul
});

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_batch_mul",
    test_fn: test_batch_mul,
});

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_batch_mul_public",
    test_fn: test_batch_mul_public,
});

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_product",
    test_fn: test_product,
});

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_sum",
    test_fn: test_sum,
});

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_linear_combination",
    test_fn: test_linear_combination,
});

inventory::submit!(IntegrationTest {
    name: "authenticated-scalar::test_random_linear_comb",
    test_fn: test_random_linear_comb,
});
