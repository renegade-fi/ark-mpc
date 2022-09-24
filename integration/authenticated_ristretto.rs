use mpc_ristretto::{authenticated_ristretto::AuthenticatedRistretto};

use crate::{IntegrationTest, IntegrationTestArgs, mpc_ristretto::is_equal_u64};

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

inventory::submit!(IntegrationTest{
    name: "authenticated-ristretto::test_share_and_open",
    test_fn: test_share_and_open
});

inventory::submit!(IntegrationTest{
    name: "authenticated-ristretto::test_authenticated_open",
    test_fn: test_authenticated_open
});