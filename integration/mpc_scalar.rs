use std::{rc::Rc, cell::RefCell};

use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{mpc_scalar::{MpcScalar, Visibility}, beaver::SharedValueSource};

use crate::{IntegrationTestArgs, IntegrationTest};

/// Returns beaver triples (0, 0, 0) for party 0 and (1, 1, 1) for party 1
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

/// Each party inputs their party_id + 1 and the two together compute the square
/// Party IDs are 0 and 1, so the expected result is (0 + 1 + 1 + 1)^2 = 9
pub(crate) fn test_simple_mpc(
    test_args: &IntegrationTestArgs,
) -> Result<(), String> {
    let beaver_source = Rc::new(RefCell::new(
        PartyIDBeaverSource::new(test_args.party_id)
    ));

    let value = MpcScalar::from_u64_with_visibility(
        test_args.party_id, 
        Visibility::Private, 
        test_args.net_ref.clone(), 
        beaver_source.clone()
    );

    let shared_value1 = value.share_secret(0)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_value2 = value.share_secret(1)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let shared_value1 = shared_value1 + Scalar::from(1u8);
    let shared_value2 = shared_value2 + Scalar::from(1u8);

    let sum = shared_value1 + shared_value2;
    let sum_squared = (&sum * &sum)
        .map_err(|err| format!("Error multiplying: {:?}", err))?;
    
    // Open the value, assert that it equals 9
    let res = sum_squared.open()
        .map_err(|err| format!("Error opening: {:?}", err))?;
    let expected = MpcScalar::from_u64(9, test_args.net_ref.clone(), beaver_source);
    
    if res.eq(&expected) { Ok(()) } else { 
        Err(format!("Result does not equal expected\n\tResult: {:?}\n\tExpected: {:?}", res.value(), expected.value()))
    }
}

inventory::submit!(IntegrationTest{
    name: "test_simple_mpc",
    test_fn: test_simple_mpc,
});