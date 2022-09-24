

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, constants::RISTRETTO_BASEPOINT_POINT, traits::MultiscalarMul};

use mpc_ristretto::{mpc_ristretto::MpcRistrettoPoint, mpc_scalar::MpcScalar};

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
    let my_mpc_value = MpcRistrettoPoint::from_private_u64(
        my_value, 
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

/// Test that commiting and opening a value works properly
fn test_commit_and_open(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let my_share = MpcRistrettoPoint::from_private_u64(
        42, test_args.net_ref.clone(), test_args.beaver_source.clone()
    )
        .share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let opened = my_share.commit_and_open()
        .map_err(|err| format!("Error committing and opening value: {:?}", err))?;

    if !is_equal_u64(opened.value(), 42) {
        return Err(format!("Expected {}, got {:?}", 42, opened.value()))
    }

    Ok(())
}

/// Test that receiving a value from the sending party works
fn test_receive_value(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let share = {
        if test_args.party_id == 0 {
            MpcRistrettoPoint::from_private_u64(
                10, 
                test_args.net_ref.clone(), 
                test_args.beaver_source.clone(),
            )
                .share_secret(0 /* party_id */)
                .map_err(|err| format!("Error sharing value: {:?}", err))?
        } else {
            MpcRistrettoPoint::receive_value(test_args.net_ref.clone(), test_args.beaver_source.clone())
                .map_err(|err| format!("Error receiving value: {:?}", err))?
        }
    };

    let share_opened = share.open().map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(share_opened.value(), 10) {
        return Err(format!("Expected {}, got {:?}", 10, share_opened.value()));
    }

    Ok(())
}

/// Test add with a variety of visibilities
fn test_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 holds 42 and party 1 holds 33
    let value = if test_args.party_id == 0 { 42 } else { 33 };

    let my_value = MpcRistrettoPoint::from_private_u64(
        value, 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    let value1_shared = my_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;


    let value2_shared = my_value.share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let public_value  = MpcRistrettoPoint::from_public_u64(
        58,
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    // Shared value + shared value
    let shared_shared = (&value1_shared + &value2_shared)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(shared_shared.value(), 75) {
        return Err("".to_string())
        // return Err(format!("Expected {}, got {:?}", 75, shared_shared.value()));
    }

    // Shared value + public value
    let shared_public = (&value1_shared + &public_value)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(shared_public.value(), 100) {
        // return Err(format!("Expected {}, got {:?}", 100, shared_public.value()));
        return Err("".to_string())
    }

    // Public value + public value
    let public_public = (&public_value + &public_value)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(public_public.value(), 116) {
        return Err(format!("Expected {}, got {:?}", 116, public_public.value()));
    }

    Ok(())
}

/// Tests subtraction of Ristretto points with various visibilities
fn test_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 holds 42 and party 1 holds 33
    let value = if test_args.party_id == 0 { 42 } else { 33 };

    let my_value = MpcRistrettoPoint::from_private_u64(
        value, 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    let value1_shared = my_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let value2_shared = my_value.share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let public_value  = MpcRistrettoPoint::from_public_u64(
        58,
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    // Shared value - shared value
    let shared_shared = (&value1_shared - &value2_shared)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(shared_shared.value(), 9) {
        return Err(format!("Expected {}, got {:?}", 9, shared_shared.value()))
    }

    // Public value - shared value
    let public_shared = (&public_value - &value1_shared)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(public_shared.value(), 16) {
        return Err(format!("Expected {}, got {:?}", 16, public_shared.value()))?;
    }

    // Public value - public value
    #[allow(clippy::eq_op)]
    let public_public = (&public_value - &public_value)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(public_public.value(), 0) {
        return Err(format!("Expected {}, got {:?}", 0, public_public.value()));
    }

    Ok(())
}

/// Tests multiplication of Ristretto points with various visibilities
fn test_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let value = if test_args.party_id == 0 { 5 } else { 6 };

    // Construct a shared point and a shared scalar
    let point_shared = MpcRistrettoPoint::from_private_u64(
        value, test_args.net_ref.clone(), test_args.beaver_source.clone()
    )
        .share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let scalar_shared = MpcScalar::from_private_u64(
        value, test_args.net_ref.clone(), test_args.beaver_source.clone()
    )
        .share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    // Construct a public point and a public scalar
    let public_point  = MpcRistrettoPoint::from_public_u64(
        7,
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );
    let public_scalar = MpcScalar::from_public_u64(
        8, 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    // Shared scalar * shared point
    let shared_shared = (&scalar_shared * &point_shared)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(shared_shared.value(), 30) {
        return Err(format!("Expected {}, got {:?}", 30, shared_shared.value()));
    }

    // Shared scalar * public point
    let shared_public1 = (&scalar_shared * &public_point)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(shared_public1.value(), 42) {
        return Err(format!("Expected {}, got {:?}", 42, shared_public1.value()));
    }

    // Public scalar * shared point
    let shared_public2 = (&public_scalar * &point_shared)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(shared_public2.value(), 40) {
        return Err(format!("Expected {}, got {:?}", 40, shared_public2.value()));
    }

    // Public scalar * public point
    let public_public = (&public_scalar * &public_point)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(public_public.value(), 56) {
        return Err(format!("Expected {}, got {:?}", 48, public_public.value()));
    }

    Ok(())
}

fn test_multiscalar_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Both parties hold a scalar and a point
    // Computing 1 * 2 + 3 * 4 == 14
    let my_value = if test_args.party_id == 0 { 2 } else { 4 };

    let my_point = MpcRistrettoPoint::from_private_u64(
        my_value,
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    // Share the values with the peer
    let shared_point1 = my_point.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_point2 = my_point.share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    
    let res = MpcRistrettoPoint::multiscalar_mul(
        vec![Scalar::from(1u64), Scalar::from(3u64)], 
        vec![shared_point1, shared_point2]
    );

    let res_open = res.open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    if !is_equal_u64(res_open.value(), 14) {
        return Err(format!("Expected {}, got {:?}", 14, res_open.value()));
    }

    Ok(())
}

inventory::submit!(IntegrationTest{
    name: "mpc-ristretto::test_share_and_open",
    test_fn: test_share_and_open,
});

inventory::submit!(IntegrationTest{
    name: "mpc-ristretto::test_commit_and_open",
    test_fn: test_commit_and_open,
});

inventory::submit!(IntegrationTest{
    name: "mpc-ristretto::test_receive_value",
    test_fn: test_receive_value,
});

inventory::submit!(IntegrationTest{
    name: "mpc-ristretto::test_add",
    test_fn: test_add,
});

inventory::submit!(IntegrationTest{
    name: "mpc-ristretto::test_sub",
    test_fn: test_sub,
});

inventory::submit!(IntegrationTest{
    name: "mpc-ristretto::test_mul",
    test_fn: test_mul,
});

inventory::submit!(IntegrationTest{
    name: "mpc-ristretto::test_multiscalar_mul",
    test_fn: test_multiscalar_mul,
});