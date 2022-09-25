use ::mpc_ristretto::{Visible, Visibility};
use mpc_ristretto::{authenticated_ristretto::AuthenticatedRistretto, mpc_ristretto::MpcRistrettoPoint, network::QuicTwoPartyNet, authenticated_scalar::AuthenticatedScalar};

use crate::{IntegrationTest, IntegrationTestArgs, mpc_ristretto::is_equal_u64, mpc_scalar::PartyIDBeaverSource};

/// Tests that sharing a value and then opening the value works properly
fn test_share_and_open(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let shared_value = AuthenticatedRistretto::from_private_u64(
        42, test_args.mac_key.clone(), test_args.net_ref.clone(), test_args.beaver_source.clone()
    )
        .share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    
    let opened_value = shared_value.open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    
    if !is_equal_u64(opened_value.to_ristretto(), 42) {
        return Err(format!("Expected {}, got {:?}", 42, opened_value.value()))
    }

    Ok(())
}

/// Tests that sharing a value then performing an authenticated opening works properly
fn test_authenticated_open(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let shared_value = AuthenticatedRistretto::from_private_u64(
        42, test_args.mac_key.clone(), test_args.net_ref.clone(), test_args.beaver_source.clone()
    )
        .share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    
    let opened_value = shared_value.open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    
    if !is_equal_u64(opened_value.to_ristretto(), 42) {
        return Err(format!("Expected {}, got {:?}", 42, opened_value.value()))
    }

    Ok(())
}

/// Tests that a cheating party is caught in authentication stage when modifying MPC circuit
fn test_authenticated_open_failure(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let value = if test_args.party_id == 0 { 5 } else { 6 };
    let my_value = AuthenticatedRistretto::from_private_u64(
        value,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(),
        test_args.beaver_source.clone()
    );

    // Share vlaues
    let shared_value1 = my_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_value2 = my_value.share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    
    let mut res = &shared_value1 + &shared_value2;

    // Party 1 attempts to corrupt the result
    if test_args.party_id == 1 {
        res += MpcRistrettoPoint::<QuicTwoPartyNet, PartyIDBeaverSource>::base_point_mul_u64(5);
    }

    // Open and verify that an error is returned
    res.open_and_authenticate()
        .map_or(
            Ok(()),
            |_| Err("Expected authentication failure, authentication passed...".to_string()), 
        )?;

    Ok(())
}

/// Tests that adding two authenticated Ristretto points works properly
fn test_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let value = if test_args.party_id == 0 { 5 } else { 6 };
    let my_value = AuthenticatedRistretto::from_private_u64(
        value,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(),
        test_args.beaver_source.clone()
    );

    // Share vlaues
    let shared_value1 = my_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_value2 = my_value.share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let public_value = AuthenticatedRistretto::from_public_u64(
        7,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(),
        test_args.beaver_source.clone(),
    );

    // Shared value + shared value
    let shared_shared = (&shared_value1 + &shared_value2)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating: {:?}", err))?;
    if !is_equal_u64(shared_shared.to_ristretto(), 11) {
        return Err(format!("Expected {}, got {:?}", 11, shared_shared.to_ristretto()))
    }

    // Shared value + public value
    let shared_public = &shared_value1 + &public_value;
    if shared_public.visibility() != Visibility::Shared {
        return Err(format!("Expected visibility {:?}, got {:?}", Visibility::Shared, shared_public.visibility()))
    }

    let shared_public_open = shared_public.open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating: {:?}", err))?;
    if !is_equal_u64(shared_public_open.to_ristretto(), 12) {
        return Err(format!("Expected {}, got {:?}", 12, shared_public_open.to_ristretto()))
    }

    // Public value + public value
    let public_public = &public_value + &public_value;
    if public_public.visibility() != Visibility::Public {
        return Err(format!("Expected visibility {:?}, got {:?}", Visibility::Public, public_public.visibility()))
    }

    let public_public_open = public_public.open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating value: {:?}", err))?;
    if !is_equal_u64(public_public_open.to_ristretto(), 14) {
        return Err(format!("Expected {}, got {:?}", 14, public_public_open.to_ristretto()))
    }

    Ok(())
}

/// Tests that subtracting points of different visibilities works
fn test_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 holds 42 and party 1 holds 33
    let value = if test_args.party_id == 0 { 42 } else { 33 };

    let my_value = AuthenticatedRistretto::from_private_u64(
        value, 
        test_args.mac_key.clone(),
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    let value1_shared = my_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let value2_shared = my_value.share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let public_value  = AuthenticatedRistretto::from_public_u64(
        58,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    // Shared value - shared value
    let shared_shared = (&value1_shared - &value2_shared)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(shared_shared.to_ristretto(), 9) {
        return Err(format!("Expected {}, got {:?}", 9, shared_shared.value()))
    }

    // Public value - shared value
    let public_shared = (&public_value - &value1_shared)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(public_shared.to_ristretto(), 16) {
        return Err(format!("Expected {}, got {:?}", 16, public_shared.value()))?;
    }

    // Public value - public value
    #[allow(clippy::eq_op)]
    let public_public = (&public_value - &public_value)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(public_public.to_ristretto(), 0) {
        return Err(format!("Expected {}, got {:?}", 0, public_public.value()));
    }

    Ok(())
}

/// Tests that multiplication with different visibilitites works properly
fn test_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let value = if test_args.party_id == 0 { 5 } else { 6 };

    // Construct a shared point and a shared scalar
    let point_shared = AuthenticatedRistretto::from_private_u64(
        value, test_args.mac_key.clone(), test_args.net_ref.clone(), test_args.beaver_source.clone()
    )
        .share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let scalar_shared = AuthenticatedScalar::from_private_u64(
        value, test_args.mac_key.clone(), test_args.net_ref.clone(), test_args.beaver_source.clone()
    )
        .share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    // Construct a public point and a public scalar
    let public_point  = AuthenticatedRistretto::from_public_u64(
        7,
        test_args.mac_key.clone(),
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );
    let public_scalar = AuthenticatedScalar::from_public_u64(
        8, 
        test_args.mac_key.clone(),
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    // Shared scalar * shared point
    let shared_shared = (&scalar_shared * &point_shared)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(shared_shared.to_ristretto(), 30) {
        return Err(format!("Expected {}, got {:?}", 30, shared_shared.value()));
    }

    // Shared scalar * public point
    let shared_public1 = (&scalar_shared * &public_point)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(shared_public1.to_ristretto(), 42) {
        return Err(format!("Expected {}, got {:?}", 42, shared_public1.value()));
    }

    // Public scalar * shared point
    let shared_public2 = (&public_scalar * &point_shared)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(shared_public2.to_ristretto(), 40) {
        return Err(format!("Expected {}, got {:?}", 40, shared_public2.value()));
    }

    // Public scalar * public point
    let public_public = (&public_scalar * &public_point)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(public_public.to_ristretto(), 56) {
        return Err(format!("Expected {}, got {:?}", 48, public_public.value()));
    }

    Ok(())
}

inventory::submit!(IntegrationTest{
    name: "authenticated-ristretto::test_share_and_open",
    test_fn: test_share_and_open
});

inventory::submit!(IntegrationTest{
    name: "authenticated-ristretto::test_authenticated_open",
    test_fn: test_authenticated_open
});

inventory::submit!(IntegrationTest{
    name: "authenticated-ristretto::test_authenticated_open_failure",
    test_fn: test_authenticated_open_failure,
});

inventory::submit!(IntegrationTest{
    name: "authenticated-ristretto::test_add",
    test_fn: test_add,
});

inventory::submit!(IntegrationTest{
    name: "authenticated-ristretto::test_sub",
    test_fn: test_sub,
});

inventory::submit!(IntegrationTest{
    name: "authenticated-ristretto::test_mul",
    test_fn: test_mul
});