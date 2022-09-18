

use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{mpc_scalar::{MpcScalar, Visibility}, beaver::SharedValueSource};

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

impl SharedValueSource<Scalar> for PartyIDBeaverSource {
    fn next_triplet(&mut self) -> (Scalar, Scalar, Scalar) {
        (
            Scalar::from(self.party_id),
            Scalar::from(self.party_id),
            Scalar::from(self.party_id),
        )
    }
    
    fn next_shared_value(&mut self) -> Scalar {
        Scalar::from(self.party_id)
    }
}

/// Party 0 shares a value then opens it, the result should be the initial value
pub(crate) fn test_open_value(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let val: u64 = 42;
    let private_val = MpcScalar::from_u64_with_visibility(
        val, 
        Visibility::Private, 
        test_args.net_ref.clone(), 
        test_args.beaver_source.clone()
    );

    let share = private_val.share_secret(0)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let opened_val = share.open()
        .map_err(|err| format!("Error opening value: {:?}", err))?;
    
    if MpcScalar::from_u64(val, test_args.net_ref.clone(), test_args.beaver_source.clone()).eq(
        &opened_val
    ) {
        Ok(())
    } else {
        Err(format!("Expected {} got {:?}", val, opened_val))
    }
}

/// Each party inputs their party_id + 1 and the two together compute the square
/// Party IDs are 0 and 1, so the expected result is (0 + 1 + 1 + 1)^2 = 9
pub(crate) fn test_simple_mpc(
    test_args: &IntegrationTestArgs,
) -> Result<(), String> {
    let value = MpcScalar::from_u64_with_visibility(
        test_args.party_id, 
        Visibility::Private, 
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
    let expected = MpcScalar::from_u64(9, test_args.net_ref.clone(), test_args.beaver_source.clone());
    
    if res.eq(&expected) { Ok(()) } else { 
        Err(format!("Result does not equal expected\n\tResult: {:?}\n\tExpected: {:?}", res.value(), expected.value()))
    }
}

// Register the tests
inventory::submit!(IntegrationTest{
    name: "test_open_value",
    test_fn: test_open_value
});

inventory::submit!(IntegrationTest{
    name: "test_simple_mpc",
    test_fn: test_simple_mpc,
});
