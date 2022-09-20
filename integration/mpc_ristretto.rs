use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, constants::RISTRETTO_BASEPOINT_POINT};
use mpc_ristretto::{mpc_ristretto::MpcRistrettoPoint, mpc_scalar::Visibility};

use crate::{IntegrationTestArgs, IntegrationTest};

/// Helper to test equality of Ristretto points; dlog is assumed hard so to test equality
/// with a u64 we have to perform a base point mul
fn is_equal_u64(point: RistrettoPoint, value: u64) -> bool {
    point.eq(
        &(RISTRETTO_BASEPOINT_POINT * Scalar::from(value))
    )
}

/// Test that sharing and opening a value works properly
fn test_share_and_open(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // The parties each hold values; they share them and then open
    let (value1, value2) = (5, 6);
    let my_value = if test_args.party_id == 0 { value1 } else { value2 };

    // Allocate the value in the network
    let my_mpc_value = MpcRistrettoPoint::from_u64_with_visibility(
        my_value, 
        Visibility::Private, 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    // Parties create secret shares of their values, first party 0, then party 1
    let secret_share1 = my_mpc_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let secret_share2 = my_mpc_value.share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    
    // Both parties open their shares
    let opened_value1 = secret_share1.open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let opened_value2 = secret_share2.open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;

    if !is_equal_u64(opened_value1.value(), value1) {
        return Err(format!("Expected {}, got {:?}", value1, opened_value1.value()))
    }

    if !is_equal_u64(opened_value2.value(), value2) {
        return Err(format!("Expected {}, got {:?}", value2, opened_value2.value()))
    }

    Ok(())
}

inventory::submit!(IntegrationTest{
    name: "test_share_and_open",
    test_fn: test_share_and_open,
});