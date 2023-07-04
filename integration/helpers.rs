//! Defines testing mocks

use std::fmt::Debug;

use futures::Future;
use mpc_ristretto::{
    algebra::{
        authenticated_scalar::AuthenticatedScalarResult,
        authenticated_stark_point::AuthenticatedStarkPointResult,
        mpc_scalar::MpcScalarResult,
        mpc_stark_point::MpcStarkPointResult,
        stark_curve::{Scalar, StarkPoint},
    },
    beaver::SharedValueSource,
    fabric::{MpcFabric, ResultHandle, ResultValue},
    network::{NetworkPayload, PartyId},
    random_point, random_scalar,
};
use tokio::runtime::Handle;

// -----------
// | Helpers |
// -----------

use crate::IntegrationTestArgs;

/// Compares two scalars, returning a result that can be propagated up an integration test
/// stack in the case that the scalars are not equal
pub(crate) fn assert_scalars_eq(a: Scalar, b: Scalar) -> Result<(), String> {
    if a == b {
        Ok(())
    } else {
        Err(format!("{a:?} != {b:?}"))
    }
}

/// Compares two points, returning a result that can be propagated up an integration test
/// stack in the case that the points are not equal
pub(crate) fn assert_points_eq(a: StarkPoint, b: StarkPoint) -> Result<(), String> {
    if a == b {
        Ok(())
    } else {
        Err(format!("{a:?} != {b:?}"))
    }
}

/// Construct two secret shares of a given scalar value
pub(crate) fn create_scalar_secret_shares(a: Scalar) -> (Scalar, Scalar) {
    let random = random_scalar();
    (a - random, random)
}

/// Construct two secret shares of a given point value
pub(crate) fn create_point_secret_shares(a: StarkPoint) -> (StarkPoint, StarkPoint) {
    let random = random_point();
    (a - random, random)
}

/// Await a result in the computation graph by blocking the current task
pub(crate) fn await_result<R, T: Future<Output = R>>(res: T) -> R {
    Handle::current().block_on(res)
}

pub(crate) fn await_result_with_error<R, E: Debug, T: Future<Output = Result<R, E>>>(
    res: T,
) -> Result<R, String> {
    Handle::current()
        .block_on(res)
        .map_err(|err| format!("Error awaiting result: {:?}", err))
}

/// Send or receive a secret shared scalar from the given party
pub(crate) fn share_scalar(
    value: Scalar,
    sender: PartyId,
    test_args: &IntegrationTestArgs,
) -> MpcScalarResult {
    let scalar = if test_args.party_id == sender {
        let (my_share, their_share) = create_scalar_secret_shares(value);
        test_args.fabric.allocate_shared_value(
            ResultValue::Scalar(my_share),
            ResultValue::Scalar(their_share),
        )
    } else {
        test_args.fabric.receive_value()
    };

    MpcScalarResult::new_shared(scalar)
}

/// Send or receive a secret shared point from the given party
pub(crate) fn share_point(
    value: StarkPoint,
    sender: PartyId,
    test_args: &IntegrationTestArgs,
) -> MpcStarkPointResult {
    let point = if test_args.party_id == sender {
        let (my_share, their_share) = create_point_secret_shares(value);
        test_args.fabric.allocate_shared_value(
            ResultValue::Point(my_share),
            ResultValue::Point(their_share),
        )
    } else {
        test_args.fabric.receive_value()
    };

    MpcStarkPointResult::new_shared(point, test_args.fabric.clone())
}

/// Send or receive a secret shared scalar from the given party and allocate it as an authenticated value
pub(crate) fn share_authenticated_scalar(
    value: Scalar,
    sender: PartyId,
    test_args: &IntegrationTestArgs,
) -> AuthenticatedScalarResult {
    let scalar = if test_args.party_id == sender {
        let (my_share, their_share) = create_scalar_secret_shares(value);
        test_args.fabric.allocate_shared_value(
            ResultValue::Scalar(my_share),
            ResultValue::Scalar(their_share),
        )
    } else {
        test_args.fabric.receive_value()
    };

    AuthenticatedScalarResult::new_shared(scalar)
}

/// Send or receive a secret shared point from the given party and allocate it as an authenticated value
pub(crate) fn share_authenticated_point(
    value: StarkPoint,
    sender: PartyId,
    test_args: &IntegrationTestArgs,
) -> AuthenticatedStarkPointResult {
    let point = if test_args.party_id == sender {
        let (my_share, their_share) = create_point_secret_shares(value);
        test_args.fabric.allocate_shared_value(
            ResultValue::Point(my_share),
            ResultValue::Point(their_share),
        )
    } else {
        test_args.fabric.receive_value()
    };

    AuthenticatedStarkPointResult::new_shared(point)
}

/// Share a value with the counterparty by sender ID, the sender sends and the receiver receives
pub(crate) fn share_plaintext_value<T: From<ResultValue> + Into<NetworkPayload>>(
    value: ResultHandle<T>,
    sender: PartyId,
    fabric: &MpcFabric,
) -> ResultHandle<T> {
    if fabric.party_id() == sender {
        fabric.send_value(value)
    } else {
        fabric.receive_value()
    }
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
