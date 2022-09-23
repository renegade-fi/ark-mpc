use curve25519_dalek::scalar::Scalar;
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

inventory::submit!(IntegrationTest{
    name: "authenticated-scalar::test_share_and_open",
    test_fn: test_share_and_open,
});