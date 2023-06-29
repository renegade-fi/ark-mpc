//! Defines testing mocks

use mpc_ristretto::{
    algebra::stark_curve::Scalar,
    beaver::SharedValueSource,
    fabric::{ResultHandle, ResultValue},
    random_scalar,
};
use tokio::runtime::Handle;

// -----------
// | Helpers |
// -----------

/// Compares two scalars, returning a result that can be propagated up an integration test
/// stack in the case that the scalars are not equal
pub(crate) fn assert_scalars_eq(a: Scalar, b: Scalar) -> Result<(), String> {
    if a == b {
        Ok(())
    } else {
        Err(format!("{a:?} != {b:?}"))
    }
}

/// Construct two secret shares of a given value
pub(crate) fn create_secret_shares(a: Scalar) -> (Scalar, Scalar) {
    let random = random_scalar();
    (a - random, random)
}

/// Await a result in the computation graph by blocking the current task
pub(crate) fn await_result<T: From<ResultValue>>(res: ResultHandle<T>) -> T {
    Handle::current().block_on(res)
}

// ---------
// | Mocks |
// ---------

/// Returns beaver triples (0, 0, 0) for party 0 and (1, 1, 1) for party 1
#[derive(Clone, Debug)]
pub(crate) struct PartyIDBeaverSource {
    party_id: u64,
}

impl PartyIDBeaverSource {
    pub fn new(party_id: u64) -> Self {
        Self { party_id }
    }
}

/// The PartyIDBeaverSource returns beaver triplets split statically between the
/// parties. We assume a = 2, b = 3 ==> c = 6. [a] = (1, 1); [b] = (3, 0) [c] = (2, 4)
impl SharedValueSource for PartyIDBeaverSource {
    fn next_shared_bit(&mut self) -> Scalar {
        // Simply output partyID, assume partyID \in {0, 1}
        assert!(self.party_id == 0 || self.party_id == 1);
        Scalar::from(self.party_id)
    }

    fn next_triplet(&mut self) -> (Scalar, Scalar, Scalar) {
        if self.party_id == 0 {
            (Scalar::from(1u64), Scalar::from(3u64), Scalar::from(2u64))
        } else {
            (Scalar::from(1u64), Scalar::from(0u64), Scalar::from(4u64))
        }
    }

    fn next_shared_inverse_pair(&mut self) -> (Scalar, Scalar) {
        (Scalar::from(1), Scalar::from(1))
    }

    fn next_shared_value(&mut self) -> Scalar {
        Scalar::from(self.party_id)
    }
}
