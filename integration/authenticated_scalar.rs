use curve25519_dalek::scalar::{Scalar, self};
use ::mpc_ristretto::{Visible, Visibility};
use mpc_ristretto::{authenticated_scalar::AuthenticatedScalar, mpc_scalar::scalar_to_u64};

use crate::{IntegrationTestArgs, IntegrationTest};


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
    let shared_secret1 = my_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing secret: {:?}", err))?;
    let shared_secret2 = my_value.share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    // Open both values and verify their correctness
    let opened_value1 = shared_secret1.open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let opened_value2 = shared_secret2.open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    
    if !opened_value1.value().value().eq(&Scalar::from(2u64)) {
        return Err(format!("Expected {}, got {}", 2, scalar_to_u64(&opened_value1.value().value())))
    }

    if !opened_value2.value().value().eq(&Scalar::from(3u64)) {
        return Err(format!("Expected {}, got {}", 3, scalar_to_u64(&opened_value2.value().value())));
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
    let shared_secret1 = my_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing secret: {:?}", err))?;
    let shared_secret2 = my_value.share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    
    // Perform an authenticated opening of both values
    let opened_value1 = shared_secret1.open_and_authenticate()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let opened_value2 = shared_secret2.open_and_authenticate()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    
    if !opened_value1.value().value().eq(&Scalar::from(2u64)) {
        return Err(format!("Expected {}, got {}", 2, scalar_to_u64(&opened_value1.value().value())))
    }

    if !opened_value2.value().value().eq(&Scalar::from(3u64)) {
        return Err(format!("Expected {}, got {}", 3, scalar_to_u64(&opened_value2.value().value())));
    }

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
    let shared_value1 = my_shared_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_value2 = my_shared_value.share_secret(1 /* party_id */)
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
    res.open_and_authenticate()
        .map_or(
            Ok(()), 
            |_| Err("Expected authentication failure, authentication passed...".to_string())
        )?;

    Ok(())
}

fn test_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Parties each hold a secret value and add them together, result is authenticated
    let value = if test_args.party_id == 0 { 2 } else { 3 };
    let my_value = AuthenticatedScalar::from_private_u64(
        value, 
        test_args.mac_key.clone(), 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    let shared_value1 = my_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_value2 = my_value.share_secret(1 /* party_id */)
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
        return Err(format!("Expected {}, got {}", 5, scalar_to_u64(&shared_shared.to_scalar())))
    }

    // Public value + shared value
    let public_shared = (&public_value + &shared_value1)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating value: {:?}", err))?;
    
    if public_shared.to_scalar().ne(&Scalar::from(12u64)) {
        return Err(format!("Expected {}, got {}", 12, scalar_to_u64(&public_shared.to_scalar())))
    }

    // Public value + public value
    let public_public = &public_value + &public_value;
    if public_public.visibility() != Visibility::Public {
        return Err(format!("Expected visibility Public, got {:?}", public_public.visibility()))
    }

    if public_public.to_scalar().ne(&Scalar::from(20u64)) {
        return Err(format!("Expected {}, got {}", 20, scalar_to_u64(&public_public.to_scalar())))
    }

    Ok(())
}

inventory::submit!(IntegrationTest{
    name: "authenticated-scalar::test_share_and_open",
    test_fn: test_share_and_open,
});

inventory::submit!(IntegrationTest{
    name: "authenticated-scalar::test_authenticated_open",
    test_fn: test_authenticated_open
});

inventory::submit!(IntegrationTest{
    name: "authenticated-scalar::test_authenticated_open_failure",
    test_fn: test_authenticated_open_failure,
});

inventory::submit!(IntegrationTest{
    name: "authenticated-scalar::test_add",
    test_fn: test_add,
});