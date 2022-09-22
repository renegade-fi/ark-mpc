use curve25519_dalek::scalar::{Scalar};

use mpc_ristretto::{mpc_scalar::{MpcScalar, scalar_to_u64}, beaver::SharedValueSource, error::MpcNetworkError};

use crate::{IntegrationTestArgs, IntegrationTest};

/// Returns beaver triples (0, 0, 0) for party 0 and (1, 1, 1) for party 1
#[derive(Debug)]
pub(crate) struct PartyIDBeaverSource {
    party_id: u64
}

impl PartyIDBeaverSource {
    pub fn new(party_id: u64) -> Self {
        Self { party_id }
    }
}

/// The PartyIDBeaverSource returns beaver triplets split statically between the
/// parties. We assume a = 2, b = 3 ==> c = 6. [a] = (1, 1); [b] = (3, 0) [c] = (2, 4)
impl SharedValueSource<Scalar> for PartyIDBeaverSource {
    fn next_triplet(&mut self) -> (Scalar, Scalar, Scalar) {
        if self.party_id == 0 {
            (
                Scalar::from(1u64),
                Scalar::from(3u64),
                Scalar::from(2u64),
            )
        } else {
            (
                Scalar::from(1u64),
                Scalar::from(0u64),
                Scalar::from(4u64),
            )
        }
    }
    
    fn next_shared_value(&mut self) -> Scalar {
        Scalar::from(self.party_id)
    }
}

/// Simple test of an add circuit with different visibilities
fn test_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 holds 42 and party 1 holds 33
    let value = if test_args.party_id == 0 { 42 } else { 33 };

    let my_value = MpcScalar::from_private_u64(
        value, 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    let value1_shared = my_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let value2_shared = my_value.share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let public_value  = MpcScalar::from_public_u64(
        58,
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );
    
    // Shared value + shared value
    let double_shared = (&value1_shared + value2_shared)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let expected = Scalar::from(75u64);
    
    if double_shared.value().ne(&expected) {
        return Err(format!(
            "Expected {}, got {}",
            scalar_to_u64(&expected),
            scalar_to_u64(&double_shared.value())
        ));
    }

    // Shared value + public value
    let shared_public = (&value1_shared + &public_value)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let expected = Scalar::from(100u64);

    if shared_public.value().ne(&expected) {
        return Err(format!(
            "Expected {}, got {}",
            scalar_to_u64(&expected),
            scalar_to_u64(&shared_public.value())
        ))
    }

    // Public value + public value
    let public_public = (&public_value + &public_value)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let expected = Scalar::from(116u64);

    if public_public.value().ne(&expected) {
        return Err(format!(
            "Expected {}, got {}",
            scalar_to_u64(&expected),
            scalar_to_u64(&public_public.value())
        ))
    }
    
    Ok(())
}

fn test_sub(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let value = if test_args.party_id == 0 { 10 } else { 6 };
    let my_value = MpcScalar::from_private_u64(
        value, 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    // Share values with counterparty
    let shared_value1 = my_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_value2 = my_value.share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let public_value = MpcScalar::from_public_u64(
        15u64, 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    // Shared value - shared value
    let shared_shared = (&shared_value1 - &shared_value2)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let expected = Scalar::from(4u8);

    if shared_shared.value().ne(&expected) {
        return Err(format!(
            "Expected {}, got {}",
            scalar_to_u64(&expected),
            scalar_to_u64(&shared_shared.value())
        ))
    }

    // Public value - shared value
    let public_shared = (&public_value - &shared_value1)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let expected = Scalar::from(5u8);

    if public_shared.value().ne(&expected) {
        return Err(format!(
            "Expected {}, got {}",
            scalar_to_u64(&expected),
            scalar_to_u64(&public_shared.value())
        ))
    }

    // Public value - public value
    #[allow(clippy::eq_op)]
    let public_public = (&public_value - &public_value)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let expected = Scalar::from(0u8);

    if public_public.value().ne(&expected) {
        return Err(format!(
            "Expected {}, got {}",
            scalar_to_u64(&expected),
            scalar_to_u64(&public_public.value())
        ))
    }

    Ok(())
}

/// Tests multiplication with different visibilities
fn test_mul(test_args: &IntegrationTestArgs)  -> Result<(), String> {
    let value = if test_args.party_id == 0 { 10 } else { 6 };
    let my_value = MpcScalar::from_private_u64(
        value, 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    // Share values with counterparty
    let shared_value1 = my_value.share_secret(0 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_value2 = my_value.share_secret(1 /* party_id */)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let public_value = MpcScalar::from_public_u64(
        15u64, 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    // Shared value * shared value
    let shared_shared = (&shared_value1 * &shared_value2)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let expected = Scalar::from(60u64);

    if shared_shared.value().ne(&expected) {
        return Err(format!(
            "Expected {}, got {}",
            scalar_to_u64(&expected),
            scalar_to_u64(&shared_shared.value())
        ))
    }

    // Public value * shared value
    let public_shared = (&public_value * &shared_value1)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let expected = Scalar::from(150u64);

    if public_shared.value().ne(&expected) {
        return Err(format!(
            "Expected {}, got {}",
            scalar_to_u64(&expected),
            scalar_to_u64(&public_shared.value())
        ))
    }

    // Public value * public value
    let public_public = (&public_value * &public_value)
        .open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    let expected = Scalar::from(225u64);

    if public_public.value().ne(&expected) {
        return Err(format!(
            "Expected {}, got {}",
            scalar_to_u64(&expected),
            scalar_to_u64(&public_public.value())
        ))
    }

    Ok(())
}

/// Party 0 shares a value then opens it, the result should be the initial value
fn test_open_value(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let val: u64 = 42;
    let private_val = MpcScalar::from_private_u64(
        val, 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    let share = private_val.share_secret(0)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let opened_val = share.open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    
    if MpcScalar::from_public_u64(val, test_args.net_ref.clone(), test_args.beaver_source.clone()).eq(
        &opened_val
    ) {
        Ok(())
    } else {
        Err(format!("Expected {} got {:?}", val, opened_val))
    }
}

/// Party 0 sends a value and party 1 receives
fn test_receive_value(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let share = {
        if test_args.party_id == 0 {
            // Send 10 as an MpcScalar
            MpcScalar::from_private_u64(
                10, 
                test_args.net_ref.clone(), 
                test_args.beaver_source.clone()
            )
                .share_secret(0 /* party_id */)
                .map_err(|err| format!("Error sharing secret: {:?}", err))?
        } else {
            MpcScalar::receive_value(test_args.net_ref.clone(), test_args.beaver_source.clone())
                .map_err(|err| format!("Error receiving value: {:?}", err))?
        }
    };

    let share_opened = share.open().map_err(|err| format!("Error opening share: {:?}", err))?;
    if !share_opened.value().eq(&Scalar::from(10u64)) {
        return Err(format!("Expected {}, got {}", 10, scalar_to_u64(&share_opened.value())));
    }

    Ok(())
}

/// Tests summing over a sequence of shared values
fn test_sum(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 allocates the first values list, party 1 allocates the second list
    let values: Vec<u64> = if test_args.party_id == 0 { vec![1, 2, 3] } else { vec![4, 5, 6] };
    
    let network_values: Vec<MpcScalar<_, _>> = values.into_iter()
        .map(|value| MpcScalar::from_public_u64(value, test_args.net_ref.clone(), test_args.beaver_source.clone())
    ).collect();

    // Share values with peer
    let shared_values1: Vec<MpcScalar<_, _>> = network_values.iter()
        .map(|value| value.share_secret(0 /* party_id */))
        .collect::<Result<Vec<MpcScalar<_, _>>, MpcNetworkError>>()
        .map_err(|err| format!("Error sharing party 0 values: {:?}", err))?;

    let shared_values2: Vec<MpcScalar<_, _>> = network_values.iter()
        .map(|value| value.share_secret(1 /* party_id */))
        .collect::<Result<Vec<MpcScalar<_, _>>, MpcNetworkError>>()
        .map_err(|err| format!("Error sharing party 1 values: {:?}", err))?;

    // Sum over all values; we expect 1 + 2 + 3 + 4 + 5 + 6 = 21
    let shared_sum: MpcScalar<_, _> = shared_values1.iter()
        .chain(shared_values2.iter())
        .sum();
    
    let res = shared_sum.open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    
    let expected = MpcScalar::from_public_u64(21, test_args.net_ref.clone(), test_args.beaver_source.clone());

    if res.eq(&expected) { Ok(()) } else { Err(format!("Expected: {:?}\nGot: {:?}\n", expected.value(), res.value())) }
}

/// Tests the product over a series of values
fn test_product(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 allocates the first values list, party 1 allocates the second list
    let values: Vec<u64> = if test_args.party_id == 0 { vec![1, 2, 3] } else { vec![4, 5, 6] };
    
    let network_values: Vec<MpcScalar<_, _>> = values.into_iter()
        .map(|value| MpcScalar::from_public_u64(value, test_args.net_ref.clone(), test_args.beaver_source.clone())
    ).collect();

    // Share values with peer
    let shared_values1: Vec<MpcScalar<_, _>> = network_values.iter()
        .map(|value| value.share_secret(0 /* party_id */))
        .collect::<Result<Vec<MpcScalar<_, _>>, MpcNetworkError>>()
        .map_err(|err| format!("Error sharing party 0 values: {:?}", err))?;

    let shared_values2: Vec<MpcScalar<_, _>> = network_values.iter()
        .map(|value| value.share_secret(1 /* party_id */))
        .collect::<Result<Vec<MpcScalar<_, _>>, MpcNetworkError>>()
        .map_err(|err| format!("Error sharing party 1 values: {:?}", err))?;
    
    // Take the product over all values, we expecte 1 * 2 * 3 * 4 * 5 * 6 = 720
    let shared_product: MpcScalar<_, _> = shared_values1.iter()
        .chain(shared_values2.iter())
        .product();

    let res = shared_product.open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    
    let expected = MpcScalar::from_public_u64(720, test_args.net_ref.clone(), test_args.beaver_source.clone());

    if res.eq(&expected) { Ok(()) } else { Err(format!("Expected: {:?}\nGot: {:?}\n", expected.value(), res.value())) }
}

/// Tests that taking a linear combination of shared values works properly
fn test_linear_combination(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Assume that party 0 allocates the values and party 1 allocates the coefficients
    let network_values: Vec<MpcScalar<_, _>> = {
        if test_args.party_id == 0 {
            1..6
        } else {
            7..12
        }
    }.map(
        |a| MpcScalar::from_public_u64(a, test_args.net_ref.clone(), test_args.beaver_source.clone())
    ).collect::<Vec<MpcScalar<_, _>>>();

    // Share the values
    let shared_values: Vec<MpcScalar<_, _>> = network_values.iter()
        .map(|val| val.share_secret(0 /* party_id */))    
        .collect::<Result<Vec<MpcScalar<_, _>>, MpcNetworkError>>()
        .map_err(|err| format!("Error sharing values: {:?}", err))?;
    
    let shared_coeffs: Vec<MpcScalar<_, _>> = network_values.iter()
        .map(|val| val.share_secret(1 /* party_id */))
        .collect::<Result<Vec<MpcScalar<_, _>>, MpcNetworkError>>()
        .map_err(|err| format!("Error sharing coefficients: {:?}", err))?;
    
    let shared_combination = shared_values.iter()
        .zip(shared_coeffs.iter())
        .fold(
            MpcScalar::from_public_u64(0u64, test_args.net_ref.clone(), test_args.beaver_source.clone()), 
            |acc, pair| acc + pair.0 * pair.1
        );
    
    let res = shared_combination.open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;

    // The expected value
    let linear_comb = (1..6).zip(7..12)
        .fold(0, |acc, val| acc + val.0 * val.1);

    let expected = MpcScalar::from_public_u64(
        linear_comb, test_args.net_ref.clone(), test_args.beaver_source.clone()
    );

    if res.eq(&expected) { Ok(()) } else { Err(format!("Expected: {:?}\nGot: {:?}\n", expected.value(), res.value())) }
}

/// Each party inputs their party_id + 1 and the two together compute the square
/// Party IDs are 0 and 1, so the expected result is (0 + 1 + 1 + 1)^2 = 9
fn test_simple_mpc(test_args: &IntegrationTestArgs,) -> Result<(), String> {
    let value = MpcScalar::from_private_u64(
        test_args.party_id, 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    // Construct secret shares from the owned value
    let shared_value1 = value.share_secret(0)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_value2 = value.share_secret(1)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    
    // Add one to each value
    let shared_value1 = shared_value1 + Scalar::from(1u8);
    let shared_value2 = shared_value2 + Scalar::from(1u8);

    let sum = shared_value1 + shared_value2;
    let sum_squared = &sum * &sum;
    
    // Open the value, assert that it equals 9
    let res = sum_squared.open()
        .map_err(|err| format!("Error opening: {:?}", err))?;
    let expected = MpcScalar::from_public_u64(9, test_args.net_ref.clone(), test_args.beaver_source.clone());
    
    if res.eq(&expected) { Ok(()) } else { 
        Err(format!("Result does not equal expected\n\tResult: {:?}\n\tExpected: {:?}", res.value(), expected.value()))
    }
}

// Register the tests
inventory::submit!(IntegrationTest{
    name: "mpc-scalar::test_add",
    test_fn: test_add,
});

inventory::submit!(IntegrationTest{
    name: "mpc-scalar::test_sub",
    test_fn: test_sub,
});

inventory::submit!(IntegrationTest{
    name: "mpc-scalar::test_mul",
    test_fn: test_mul
});

inventory::submit!(IntegrationTest{
    name: "mpc-scalar::test_open_value",
    test_fn: test_open_value,
});

inventory::submit!(IntegrationTest{
    name: "mpc-scalar::test_receive_value",
    test_fn: test_receive_value,
});

inventory::submit!(IntegrationTest{
    name: "mpc-scalar::test_sum",
    test_fn: test_sum,
});

inventory::submit!(IntegrationTest{
    name: "mpc-scalar::test_product",
    test_fn: test_product,
});

inventory::submit!(IntegrationTest{
    name: "mpc-scalar::test_linear_combination",
    test_fn: test_linear_combination,
});

inventory::submit!(IntegrationTest{
    name: "mpc-scalar::test_simple_mpc",
    test_fn: test_simple_mpc,
});
