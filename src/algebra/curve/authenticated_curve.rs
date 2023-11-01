//! Defines an malicious secure wrapper around an `MpcCurvePoint<C>` type that
//! includes a MAC for ensuring computational integrity of an opened point

use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    iter::Sum,
    ops::{Add, Mul, Neg, Sub},
    pin::Pin,
    task::{Context, Poll},
};

use ark_ec::CurveGroup;
use futures::{Future, FutureExt};
use itertools::{izip, Itertools};

use crate::{
    algebra::macros::*,
    algebra::scalar::*,
    commitment::{HashCommitment, HashCommitmentResult},
    error::MpcError,
    fabric::{MpcFabric, ResultValue},
    ResultId, PARTY0,
};

use super::{
    curve::{BatchCurvePointResult, CurvePoint, CurvePointResult},
    mpc_curve::MpcPointResult,
};

/// The number of underlying results in an `AuthenticatedPointResult`
pub(crate) const AUTHENTICATED_POINT_RESULT_LEN: usize = 3;

/// A maliciously secure wrapper around `MpcPointResult` that includes a MAC as
/// per the SPDZ protocol: https://eprint.iacr.org/2011/535.pdf
#[derive(Clone)]
pub struct AuthenticatedPointResult<C: CurveGroup> {
    /// The local secret share of the underlying authenticated point
    pub(crate) share: MpcPointResult<C>,
    /// A SPDZ style, unconditionally secure MAC of the value
    /// This is used to ensure computational integrity of the opened value
    ///
    /// See the doc comment in `AuthenticatedScalar` for more details
    pub(crate) mac: MpcPointResult<C>,
    /// The public modifier tracks additions and subtractions of public values
    /// to the shares
    ///
    /// Only the first party adds/subtracts public values to their share, but
    /// the other parties must track this to validate the MAC when it is
    /// opened
    pub(crate) public_modifier: CurvePointResult<C>,
}

impl<C: CurveGroup> Debug for AuthenticatedPointResult<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedPointResult")
            .field("value", &self.share.id())
            .field("mac", &self.mac.id())
            .field("public_modifier", &self.public_modifier.id)
            .finish()
    }
}

impl<C: CurveGroup> AuthenticatedPointResult<C> {
    /// Creates a new authenticated point from a given underlying point
    pub fn new_shared(value: CurvePointResult<C>) -> AuthenticatedPointResult<C> {
        // Create an mpc point from the value
        let fabric_clone = value.fabric.clone();

        let mpc_value = MpcPointResult::new_shared(value);
        let mac = fabric_clone.borrow_mac_key() * &mpc_value;

        // Allocate a zero point for the public modifier
        let public_modifier = fabric_clone.allocate_point(CurvePoint::identity());

        Self {
            share: mpc_value,
            mac,
            public_modifier,
        }
    }

    /// Creates a batch of `AuthenticatedPointResult`s from a given batch of
    /// underlying points
    pub fn new_shared_batch(values: &[CurvePointResult<C>]) -> Vec<AuthenticatedPointResult<C>> {
        if values.is_empty() {
            return vec![];
        }

        // Create mpc points from the value
        let n = values.len();
        let fabric = values[0].fabric();
        let mpc_values = values
            .iter()
            .map(|p| MpcPointResult::new_shared(p.clone()))
            .collect_vec();

        let mac_keys = (0..n)
            .map(|_| fabric.borrow_mac_key().clone())
            .collect_vec();
        let macs = MpcPointResult::batch_mul(&mac_keys, &mpc_values);

        mpc_values
            .into_iter()
            .zip(macs)
            .map(|(share, mac)| Self {
                share,
                mac,
                public_modifier: fabric.curve_identity(),
            })
            .collect_vec()
    }

    /// Creates a batch of `AuthenticatedPointResult`s from a batch result
    ///
    /// The batch result combines the batch into one result, so it must be split
    /// out first before creating the `AuthenticatedPointResult`s
    pub fn new_shared_from_batch_result(
        values: BatchCurvePointResult<C>,
        n: usize,
    ) -> Vec<AuthenticatedPointResult<C>> {
        // Convert to a set of scalar results
        let scalar_results: Vec<CurvePointResult<C>> =
            values
                .fabric()
                .new_batch_gate_op(vec![values.id()], n, |mut args| {
                    let args: Vec<CurvePoint<C>> = args.pop().unwrap().into();
                    args.into_iter().map(ResultValue::Point).collect_vec()
                });

        Self::new_shared_batch(&scalar_results)
    }

    /// Get the ID of the underlying share's result
    pub fn id(&self) -> ResultId {
        self.share.id()
    }

    /// Get the IDs of the results that make up the `AuthenticatedPointResult`
    /// representation
    pub(crate) fn ids(&self) -> Vec<ResultId> {
        vec![self.share.id(), self.mac.id(), self.public_modifier.id]
    }

    /// Borrow the fabric that this result is allocated in
    pub fn fabric(&self) -> &MpcFabric<C> {
        self.share.fabric()
    }

    /// Get the underlying share as an `MpcPointResult`
    #[cfg(feature = "test_helpers")]
    pub fn mpc_share(&self) -> MpcPointResult<C> {
        self.share.clone()
    }

    /// Open the value without checking the MAC
    pub fn open(&self) -> CurvePointResult<C> {
        self.share.open()
    }

    /// Open a batch of values without checking the MAC
    pub fn open_batch(values: &[Self]) -> Vec<CurvePointResult<C>> {
        MpcPointResult::open_batch(&values.iter().map(|v| v.share.clone()).collect_vec())
    }

    /// Convert a flattened iterator into a batch of `AuthenticatedPointResult`s
    ///
    /// We assume that the iterator has been flattened in the same way order
    /// that `Self::id`s returns the `AuthenticatedScalar`'s values:
    /// `[share, mac, public_modifier]`
    pub fn from_flattened_iterator<I>(iter: I) -> Vec<Self>
    where
        I: Iterator<Item = CurvePointResult<C>>,
    {
        iter.chunks(AUTHENTICATED_POINT_RESULT_LEN)
            .into_iter()
            .map(|mut chunk| Self {
                share: chunk.next().unwrap().into(),
                mac: chunk.next().unwrap().into(),
                public_modifier: chunk.next().unwrap(),
            })
            .collect_vec()
    }

    /// Verify the MAC check on an authenticated opening
    fn verify_mac_check(
        my_mac_share: CurvePoint<C>,
        peer_mac_share: CurvePoint<C>,
        peer_mac_commitment: Scalar<C>,
        peer_blinder: Scalar<C>,
    ) -> bool {
        // Check that the MAC check value is the correct opening of the
        // given commitment
        let peer_comm = HashCommitment {
            value: peer_mac_share,
            blinder: peer_blinder,
            commitment: peer_mac_commitment,
        };
        if !peer_comm.verify() {
            return false;
        }

        // Check that the MAC check shares add up to the additive identity in
        // the curve group
        if my_mac_share + peer_mac_share != CurvePoint::identity() {
            return false;
        }

        true
    }

    /// Open the value and check the MAC
    ///
    /// This follows the protocol detailed in
    ///     https://securecomputation.org/docs/pragmaticmpc.pdf
    pub fn open_authenticated(&self) -> AuthenticatedPointOpenResult<C> {
        // Both parties open the underlying value
        let recovered_value = self.share.open();

        // Add a gate to compute hte MAC check value: `key_share * opened_value -
        // mac_share`
        let mac_check: CurvePointResult<C> = self.fabric().new_gate_op(
            vec![
                self.fabric().borrow_mac_key().id(),
                recovered_value.id(),
                self.public_modifier.id(),
                self.mac.id(),
            ],
            |mut args| {
                let mac_key_share: Scalar<C> = args.remove(0).into();
                let value: CurvePoint<C> = args.remove(0).into();
                let modifier: CurvePoint<C> = args.remove(0).into();
                let mac_share: CurvePoint<C> = args.remove(0).into();

                ResultValue::Point((value + modifier) * mac_key_share - mac_share)
            },
        );

        // Compute a commitment to this value and share it with the peer
        let my_comm = HashCommitmentResult::commit(mac_check.clone());
        let peer_commit = self.fabric().exchange_value(my_comm.commitment);

        // Once the parties have exchanged their commitments, they can open the
        // underlying MAC check value as they are bound by the commitment
        let peer_mac_check = self.fabric().exchange_value(my_comm.value.clone());
        let blinder_result: ScalarResult<C> = self.fabric().allocate_scalar(my_comm.blinder);
        let peer_blinder = self.fabric().exchange_value(blinder_result);

        // Check the peer's commitment and the sum of the MAC checks
        let commitment_check: ScalarResult<C> = self.fabric().new_gate_op(
            vec![
                mac_check.id,
                peer_mac_check.id,
                peer_blinder.id,
                peer_commit.id,
            ],
            move |mut args| {
                let my_mac_check: CurvePoint<C> = args.remove(0).into();
                let peer_mac_check: CurvePoint<C> = args.remove(0).into();
                let peer_blinder: Scalar<C> = args.remove(0).into();
                let peer_commitment: Scalar<C> = args.remove(0).into();

                ResultValue::Scalar(Scalar::from(Self::verify_mac_check(
                    my_mac_check,
                    peer_mac_check,
                    peer_commitment,
                    peer_blinder,
                )))
            },
        );

        AuthenticatedPointOpenResult {
            value: recovered_value,
            mac_check: commitment_check,
        }
    }

    /// Open a batch of values and check the MACs
    pub fn open_authenticated_batch(values: &[Self]) -> Vec<AuthenticatedPointOpenResult<C>> {
        if values.is_empty() {
            return Vec::new();
        }

        let n = values.len();
        let fabric = values[0].fabric();

        // Open the values
        let opened_values = Self::open_batch(values);

        // --- MAC Check --- //

        // Compute the shares of the MAC check in batch
        let mut mac_check_deps = Vec::with_capacity(1 + AUTHENTICATED_POINT_RESULT_LEN * n);
        mac_check_deps.push(fabric.borrow_mac_key().id());
        for i in 0..n {
            mac_check_deps.push(opened_values[i].id());
            mac_check_deps.push(values[i].public_modifier.id());
            mac_check_deps.push(values[i].mac.id());
        }

        let mac_checks: Vec<CurvePointResult<C>> =
            fabric.new_batch_gate_op(mac_check_deps, n /* output_arity */, move |mut args| {
                let mac_key_share: Scalar<C> = args.remove(0).into();
                let mut check_result = Vec::with_capacity(n);

                for _ in 0..n {
                    let value: CurvePoint<C> = args.remove(0).into();
                    let modifier: CurvePoint<C> = args.remove(0).into();
                    let mac_share: CurvePoint<C> = args.remove(0).into();

                    check_result.push(mac_key_share * (value + modifier) - mac_share);
                }

                check_result.into_iter().map(ResultValue::Point).collect()
            });

        // --- Commit to the MAC checks --- //

        let my_comms = mac_checks
            .iter()
            .cloned()
            .map(HashCommitmentResult::commit)
            .collect_vec();
        let peer_comms = fabric.exchange_values(
            &my_comms
                .iter()
                .map(|comm| comm.commitment.clone())
                .collect_vec(),
        );

        // --- Exchange the MAC Checks and Commitment Blinders --- //

        let peer_mac_checks = fabric.exchange_values(&mac_checks);
        let peer_blinders = fabric.exchange_values(
            &my_comms
                .iter()
                .map(|comm| fabric.allocate_scalar(comm.blinder))
                .collect_vec(),
        );

        // --- Check the MAC Checks --- //

        let mut mac_check_gate_deps = my_comms.iter().map(|comm| comm.value.id).collect_vec();
        mac_check_gate_deps.push(peer_mac_checks.id);
        mac_check_gate_deps.push(peer_blinders.id);
        mac_check_gate_deps.push(peer_comms.id);

        let commitment_checks: Vec<ScalarResult<C>> = fabric.new_batch_gate_op(
            mac_check_gate_deps,
            n, // output_arity
            move |mut args| {
                let my_comms: Vec<CurvePoint<C>> =
                    args.drain(..n).map(|comm| comm.into()).collect();
                let peer_mac_checks: Vec<CurvePoint<C>> = args.remove(0).into();
                let peer_blinders: Vec<Scalar<C>> = args.remove(0).into();
                let peer_comms: Vec<Scalar<C>> = args.remove(0).into();

                // Build a commitment from the gate inputs
                let mut mac_checks = Vec::with_capacity(n);
                for (my_mac_share, peer_mac_share, peer_blinder, peer_commitment) in izip!(
                    my_comms.into_iter(),
                    peer_mac_checks.into_iter(),
                    peer_blinders.into_iter(),
                    peer_comms.into_iter()
                ) {
                    let mac_check = Self::verify_mac_check(
                        my_mac_share,
                        peer_mac_share,
                        peer_commitment,
                        peer_blinder,
                    );
                    mac_checks.push(ResultValue::Scalar(Scalar::from(mac_check)));
                }

                mac_checks
            },
        );

        // --- Return the results --- //

        opened_values
            .into_iter()
            .zip(commitment_checks)
            .map(|(value, check)| AuthenticatedPointOpenResult {
                value,
                mac_check: check,
            })
            .collect_vec()
    }
}

/// The value that results from opening an `AuthenticatedPointResult` and
/// checking its MAC. This encapsulates both the underlying value and the result
/// of the MAC check
#[derive(Clone)]
pub struct AuthenticatedPointOpenResult<C: CurveGroup> {
    /// The underlying value
    pub value: CurvePointResult<C>,
    /// The result of the MAC check
    pub mac_check: ScalarResult<C>,
}

impl<C: CurveGroup> Debug for AuthenticatedPointOpenResult<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("AuthenticatedPointOpenResult")
            .field("value", &self.value.id)
            .field("mac_check", &self.mac_check.id)
            .finish()
    }
}

impl<C: CurveGroup> Future for AuthenticatedPointOpenResult<C>
where
    C::ScalarField: Unpin,
{
    type Output = Result<CurvePoint<C>, MpcError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Await both of the underlying values
        let value = futures::ready!(self.as_mut().value.poll_unpin(cx));
        let mac_check = futures::ready!(self.as_mut().mac_check.poll_unpin(cx));

        if mac_check == Scalar::from(1u8) {
            Poll::Ready(Ok(value))
        } else {
            Poll::Ready(Err(MpcError::AuthenticationError))
        }
    }
}

impl<C: CurveGroup> Sum for AuthenticatedPointResult<C> {
    // Assumes the iterator is non-empty
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        let first = iter
            .next()
            .expect("AuthenticatedPointResult<C>::sum requires a non-empty iterator");
        iter.fold(first, |acc, x| acc + x)
    }
}

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl<C: CurveGroup> Add<&CurvePoint<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn add(self, other: &CurvePoint<C>) -> AuthenticatedPointResult<C> {
        let new_share = if self.fabric().party_id() == PARTY0 {
            // Party zero adds the public value to their share
            &self.share + other
        } else {
            // Other parties just add the identity to the value to allocate a new op and
            // keep in sync with party 0
            &self.share + CurvePoint::identity()
        };

        // Add the public value to the MAC
        let new_modifier = &self.public_modifier - other;
        AuthenticatedPointResult {
            share: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Add, add, +, CurvePoint<C>, C: CurveGroup);
impl_commutative!(AuthenticatedPointResult<C>, Add, add, +, CurvePoint<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&CurvePointResult<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn add(self, other: &CurvePointResult<C>) -> AuthenticatedPointResult<C> {
        let new_share = if self.fabric().party_id() == PARTY0 {
            // Party zero adds the public value to their share
            &self.share + other
        } else {
            // Other parties just add the identity to the value to allocate a new op and
            // keep in sync with party 0
            &self.share + CurvePoint::identity()
        };

        // Add the public value to the MAC
        let new_modifier = &self.public_modifier - other;
        AuthenticatedPointResult {
            share: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Add, add, +, CurvePointResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedPointResult<C>, Add, add, +, CurvePointResult<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&AuthenticatedPointResult<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn add(self, other: &AuthenticatedPointResult<C>) -> AuthenticatedPointResult<C> {
        let new_share = &self.share + &other.share;

        // Add the public value to the MAC
        let new_mac = &self.mac + &other.mac;
        AuthenticatedPointResult {
            share: new_share,
            mac: new_mac,
            public_modifier: self.public_modifier.clone() + other.public_modifier.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Add, add, +, AuthenticatedPointResult<C>, C: CurveGroup);

impl<C: CurveGroup> AuthenticatedPointResult<C> {
    /// Add two batches of `AuthenticatedPointResult`s
    pub fn batch_add(
        a: &[AuthenticatedPointResult<C>],
        b: &[AuthenticatedPointResult<C>],
    ) -> Vec<AuthenticatedPointResult<C>> {
        assert_eq!(a.len(), b.len(), "batch_add requires equal length vectors");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().chain(b.iter()).flat_map(|p| p.ids()).collect_vec();

        let res: Vec<CurvePointResult<C>> = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_POINT_RESULT_LEN * n,
            move |mut args| {
                let len = args.len();
                let a_vals = args.drain(..len / 2).collect_vec();
                let b_vals = args;

                let mut result = Vec::with_capacity(AUTHENTICATED_POINT_RESULT_LEN * n);
                for (a_chunk, b_chunk) in a_vals
                    .chunks(AUTHENTICATED_POINT_RESULT_LEN)
                    .zip(b_vals.chunks(AUTHENTICATED_POINT_RESULT_LEN))
                {
                    let a_share: CurvePoint<C> = a_chunk[0].clone().into();
                    let a_mac: CurvePoint<C> = a_chunk[1].clone().into();
                    let a_modifier: CurvePoint<C> = a_chunk[2].clone().into();

                    let b_share: CurvePoint<C> = b_chunk[0].clone().into();
                    let b_mac: CurvePoint<C> = b_chunk[1].clone().into();
                    let b_modifier: CurvePoint<C> = b_chunk[2].clone().into();

                    result.push(ResultValue::Point(a_share + b_share));
                    result.push(ResultValue::Point(a_mac + b_mac));
                    result.push(ResultValue::Point(a_modifier + b_modifier));
                }

                result
            },
        );

        Self::from_flattened_iterator(res.into_iter())
    }

    /// Add a batch of `AuthenticatedPointResult`s to a batch of
    /// `CurvePointResult`s
    pub fn batch_add_public(
        a: &[AuthenticatedPointResult<C>],
        b: &[CurvePointResult<C>],
    ) -> Vec<AuthenticatedPointResult<C>> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_add_public requires equal length vectors"
        );
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a
            .iter()
            .flat_map(|a| a.ids())
            .chain(b.iter().map(|b| b.id()))
            .collect_vec();

        let party_id = fabric.party_id();
        let res: Vec<CurvePointResult<C>> = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_POINT_RESULT_LEN * n,
            move |mut args| {
                let a_vals = args
                    .drain(..AUTHENTICATED_POINT_RESULT_LEN * n)
                    .collect_vec();
                let b_vals = args;

                let mut result = Vec::with_capacity(AUTHENTICATED_POINT_RESULT_LEN * n);
                for (a_chunk, b_val) in a_vals
                    .chunks(AUTHENTICATED_POINT_RESULT_LEN)
                    .zip(b_vals.into_iter())
                {
                    let a_share: CurvePoint<C> = a_chunk[0].clone().into();
                    let a_mac: CurvePoint<C> = a_chunk[1].clone().into();
                    let a_modifier: CurvePoint<C> = a_chunk[2].clone().into();

                    let public_value: CurvePoint<C> = b_val.into();

                    // Only the first party adds the public value to their share
                    if party_id == PARTY0 {
                        result.push(ResultValue::Point(a_share + public_value));
                    } else {
                        result.push(ResultValue::Point(a_share))
                    }

                    result.push(ResultValue::Point(a_mac));
                    result.push(ResultValue::Point(a_modifier - public_value));
                }

                result
            },
        );

        Self::from_flattened_iterator(res.into_iter())
    }
}

// === Subtraction === //

impl<C: CurveGroup> Sub<&CurvePoint<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn sub(self, other: &CurvePoint<C>) -> AuthenticatedPointResult<C> {
        let new_share = if self.fabric().party_id() == PARTY0 {
            // Party zero subtracts the public value from their share
            &self.share - other
        } else {
            // Other parties just subtract the identity from the value to allocate a new op
            // and keep in sync with party 0
            &self.share - CurvePoint::identity()
        };

        // Subtract the public value from the MAC
        let new_modifier = &self.public_modifier + other;
        AuthenticatedPointResult {
            share: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Sub, sub, -, CurvePoint<C>, C: CurveGroup);
impl_commutative!(AuthenticatedPointResult<C>, Sub, sub, -, CurvePoint<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&CurvePointResult<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn sub(self, other: &CurvePointResult<C>) -> AuthenticatedPointResult<C> {
        let new_share = if self.fabric().party_id() == PARTY0 {
            // Party zero subtracts the public value from their share
            &self.share - other
        } else {
            // Other parties just subtract the identity from the value to allocate a new op
            // and keep in sync with party 0
            &self.share - CurvePoint::identity()
        };

        // Subtract the public value from the MAC
        let new_modifier = &self.public_modifier + other;
        AuthenticatedPointResult {
            share: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Sub, sub, -, CurvePointResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedPointResult<C>, Sub, sub, -, CurvePointResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&AuthenticatedPointResult<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn sub(self, other: &AuthenticatedPointResult<C>) -> AuthenticatedPointResult<C> {
        let new_share = &self.share - &other.share;

        // Subtract the public value from the MAC
        let new_mac = &self.mac - &other.mac;
        AuthenticatedPointResult {
            share: new_share,
            mac: new_mac,
            public_modifier: self.public_modifier.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Sub, sub, -, AuthenticatedPointResult<C>, C: CurveGroup);

impl<C: CurveGroup> AuthenticatedPointResult<C> {
    /// Add two batches of `AuthenticatedPointResult`s
    pub fn batch_sub(
        a: &[AuthenticatedPointResult<C>],
        b: &[AuthenticatedPointResult<C>],
    ) -> Vec<AuthenticatedPointResult<C>> {
        assert_eq!(a.len(), b.len(), "batch_add requires equal length vectors");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().chain(b.iter()).flat_map(|p| p.ids()).collect_vec();

        let res: Vec<CurvePointResult<C>> = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_POINT_RESULT_LEN * n,
            move |mut args| {
                let len = args.len();
                let a_vals = args.drain(..len / 2).collect_vec();
                let b_vals = args;

                let mut result = Vec::with_capacity(AUTHENTICATED_POINT_RESULT_LEN * n);
                for (a_chunk, b_chunk) in a_vals
                    .chunks(AUTHENTICATED_POINT_RESULT_LEN)
                    .zip(b_vals.chunks(AUTHENTICATED_POINT_RESULT_LEN))
                {
                    let a_share: CurvePoint<C> = a_chunk[0].clone().into();
                    let a_mac: CurvePoint<C> = a_chunk[1].clone().into();
                    let a_modifier: CurvePoint<C> = a_chunk[2].clone().into();

                    let b_share: CurvePoint<C> = b_chunk[0].clone().into();
                    let b_mac: CurvePoint<C> = b_chunk[1].clone().into();
                    let b_modifier: CurvePoint<C> = b_chunk[2].clone().into();

                    result.push(ResultValue::Point(a_share - b_share));
                    result.push(ResultValue::Point(a_mac - b_mac));
                    result.push(ResultValue::Point(a_modifier - b_modifier));
                }

                result
            },
        );

        Self::from_flattened_iterator(res.into_iter())
    }

    /// Subtract a batch of `AuthenticatedPointResult`s to a batch of
    /// `CurvePointResult`s
    pub fn batch_sub_public(
        a: &[AuthenticatedPointResult<C>],
        b: &[CurvePointResult<C>],
    ) -> Vec<AuthenticatedPointResult<C>> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_add_public requires equal length vectors"
        );
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a
            .iter()
            .flat_map(|a| a.ids())
            .chain(b.iter().map(|b| b.id()))
            .collect_vec();

        let party_id = fabric.party_id();
        let res: Vec<CurvePointResult<C>> = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_POINT_RESULT_LEN * n,
            move |mut args| {
                let a_vals = args
                    .drain(..AUTHENTICATED_POINT_RESULT_LEN * n)
                    .collect_vec();
                let b_vals = args;

                let mut result = Vec::with_capacity(AUTHENTICATED_POINT_RESULT_LEN * n);
                for (a_chunk, b_val) in a_vals
                    .chunks(AUTHENTICATED_POINT_RESULT_LEN)
                    .zip(b_vals.into_iter())
                {
                    let a_share: CurvePoint<C> = a_chunk[0].clone().into();
                    let a_mac: CurvePoint<C> = a_chunk[1].clone().into();
                    let a_modifier: CurvePoint<C> = a_chunk[2].clone().into();

                    let b_share: CurvePoint<C> = b_val.into();

                    // Only the first party adds the public value to their share
                    if party_id == PARTY0 {
                        result.push(ResultValue::Point(a_share - b_share));
                    } else {
                        result.push(ResultValue::Point(a_share))
                    }

                    result.push(ResultValue::Point(a_mac));
                    result.push(ResultValue::Point(a_modifier + b_share));
                }

                result
            },
        );

        Self::from_flattened_iterator(res.into_iter())
    }
}

// === Negation == //

impl<C: CurveGroup> Neg for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn neg(self) -> AuthenticatedPointResult<C> {
        let new_share = -&self.share;

        // Negate the public value in the MAC
        let new_mac = -&self.mac;
        AuthenticatedPointResult {
            share: new_share,
            mac: new_mac,
            public_modifier: self.public_modifier.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Neg, neg, -, C: CurveGroup);

impl<C: CurveGroup> AuthenticatedPointResult<C> {
    /// Negate a batch of `AuthenticatedPointResult`s
    pub fn batch_neg(a: &[AuthenticatedPointResult<C>]) -> Vec<AuthenticatedPointResult<C>> {
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().flat_map(|p| p.ids()).collect_vec();

        let res: Vec<CurvePointResult<C>> =
            fabric.new_batch_gate_op(all_ids, AUTHENTICATED_POINT_RESULT_LEN * n, move |args| {
                args.into_iter()
                    .map(CurvePoint::from)
                    .map(CurvePoint::neg)
                    .map(ResultValue::Point)
                    .collect_vec()
            });

        Self::from_flattened_iterator(res.into_iter())
    }
}

// === Scalar<C> Multiplication === //

impl<C: CurveGroup> Mul<&Scalar<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn mul(self, other: &Scalar<C>) -> AuthenticatedPointResult<C> {
        let new_share = &self.share * other;

        // Multiply the public value in the MAC
        let new_mac = &self.mac * other;
        let new_modifier = &self.public_modifier * other;
        AuthenticatedPointResult {
            share: new_share,
            mac: new_mac,
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
impl_commutative!(AuthenticatedPointResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&ScalarResult<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn mul(self, other: &ScalarResult<C>) -> AuthenticatedPointResult<C> {
        let new_share = &self.share * other;

        // Multiply the public value in the MAC
        let new_mac = &self.mac * other;
        let new_modifier = &self.public_modifier * other;
        AuthenticatedPointResult {
            share: new_share,
            mac: new_mac,
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedPointResult<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&AuthenticatedScalarResult<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    // Beaver trick
    fn mul(self, rhs: &AuthenticatedScalarResult<C>) -> AuthenticatedPointResult<C> {
        // Sample a beaver triple
        let generator = CurvePoint::generator();
        let (a, b, c) = self.fabric().next_authenticated_triple();

        // Open the values d = [rhs - a] and e = [lhs - bG] for curve group generator G
        let masked_rhs = rhs - &a;
        let masked_lhs = self - (&generator * &b);

        #[allow(non_snake_case)]
        let eG_open = masked_lhs.open();
        let d_open = masked_rhs.open();

        // Identity [x * yG] = deG + d[bG] + [a]eG + [c]G
        &d_open * &eG_open + &d_open * &(&generator * &b) + &a * eG_open + &c * generator
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Mul, mul, *, AuthenticatedScalarResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedPointResult<C>, Mul, mul, *, AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> AuthenticatedPointResult<C> {
    /// Multiply a batch of `AuthenticatedPointResult`s by a batch of
    /// `AuthenticatedScalarResult`s
    #[allow(non_snake_case)]
    pub fn batch_mul(
        a: &[AuthenticatedScalarResult<C>],
        b: &[AuthenticatedPointResult<C>],
    ) -> Vec<AuthenticatedPointResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();

        // Sample a set of beaver triples for the multiplications
        let (beaver_a, beaver_b, beaver_c) = fabric.next_authenticated_triple_batch(n);
        let beaver_b_gen = AuthenticatedPointResult::batch_mul_generator(&beaver_b);

        let masked_rhs = AuthenticatedScalarResult::batch_sub(a, &beaver_a);
        let masked_lhs = AuthenticatedPointResult::batch_sub(b, &beaver_b_gen);

        let eG_open = AuthenticatedPointResult::open_batch(&masked_lhs);
        let d_open = AuthenticatedScalarResult::open_batch(&masked_rhs);

        // Identity [x * yG] = deG + d[bG] + [a]eG + [c]G
        let deG = CurvePointResult::batch_mul(&d_open, &eG_open);
        let dbG = AuthenticatedPointResult::batch_mul_public(&d_open, &beaver_b_gen);
        let aeG = CurvePointResult::batch_mul_authenticated(&beaver_a, &eG_open);
        let cG = AuthenticatedPointResult::batch_mul_generator(&beaver_c);

        let de_db_G = AuthenticatedPointResult::batch_add_public(&dbG, &deG);
        let ae_c_G = AuthenticatedPointResult::batch_add(&aeG, &cG);

        AuthenticatedPointResult::batch_add(&de_db_G, &ae_c_G)
    }

    /// Multiply a batch of `AuthenticatedPointResult`s by a batch of
    /// `ScalarResult`s
    pub fn batch_mul_public(
        a: &[ScalarResult<C>],
        b: &[AuthenticatedPointResult<C>],
    ) -> Vec<AuthenticatedPointResult<C>> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_mul_public requires equal length vectors"
        );
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a
            .iter()
            .map(|a| a.id())
            .chain(b.iter().flat_map(|p| p.ids()))
            .collect_vec();

        let results: Vec<CurvePointResult<C>> = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_POINT_RESULT_LEN * n, // output_arity
            move |mut args| {
                let scalars: Vec<Scalar<C>> = args.drain(..n).map(Scalar::from).collect_vec();
                let points: Vec<CurvePoint<C>> =
                    args.into_iter().map(CurvePoint::from).collect_vec();

                let mut result = Vec::with_capacity(AUTHENTICATED_POINT_RESULT_LEN * n);
                for (scalar, points) in scalars
                    .into_iter()
                    .zip(points.chunks(AUTHENTICATED_POINT_RESULT_LEN))
                {
                    let share: CurvePoint<C> = points[0];
                    let mac: CurvePoint<C> = points[1];
                    let modifier: CurvePoint<C> = points[2];

                    result.push(ResultValue::Point(share * scalar));
                    result.push(ResultValue::Point(mac * scalar));
                    result.push(ResultValue::Point(modifier * scalar));
                }

                result
            },
        );

        Self::from_flattened_iterator(results.into_iter())
    }

    /// Multiply a batch of scalars by the generator
    pub fn batch_mul_generator(
        a: &[AuthenticatedScalarResult<C>],
    ) -> Vec<AuthenticatedPointResult<C>> {
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().flat_map(|v| v.ids()).collect_vec();

        // Multiply the shares in a batch gate
        let results = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_POINT_RESULT_LEN * n, // output_arity
            move |args| {
                let scalars = args.into_iter().map(Scalar::from).collect_vec();
                let generator = CurvePoint::generator();

                scalars
                    .into_iter()
                    .map(|x| x * generator)
                    .map(ResultValue::Point)
                    .collect_vec()
            },
        );

        Self::from_flattened_iterator(results.into_iter())
    }
}

// === Multiscalar Multiplication === //

impl<C: CurveGroup> AuthenticatedPointResult<C> {
    /// Multiscalar multiplication
    ///
    /// TODO: Maybe make use of a fast MSM operation under the hood once the
    /// blinded points are revealed
    pub fn msm(
        scalars: &[AuthenticatedScalarResult<C>],
        points: &[AuthenticatedPointResult<C>],
    ) -> AuthenticatedPointResult<C> {
        assert_eq!(
            scalars.len(),
            points.len(),
            "multiscalar_mul requires equal length vectors"
        );
        assert!(
            !scalars.is_empty(),
            "multiscalar_mul requires non-empty vectors"
        );

        let mul_out = AuthenticatedPointResult::batch_mul(scalars, points);

        // Create a gate to sum the points
        let fabric = scalars[0].fabric();
        let all_ids = mul_out.iter().flat_map(|p| p.ids()).collect_vec();

        let results = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_POINT_RESULT_LEN, // output_arity
            move |args| {
                // Accumulators
                let mut share = CurvePoint::identity();
                let mut mac = CurvePoint::identity();
                let mut modifier = CurvePoint::identity();

                for mut chunk in args
                    .into_iter()
                    .map(CurvePoint::from)
                    .chunks(AUTHENTICATED_POINT_RESULT_LEN)
                    .into_iter()
                {
                    share += chunk.next().unwrap();
                    mac += chunk.next().unwrap();
                    modifier += chunk.next().unwrap();
                }

                vec![
                    ResultValue::Point(share),
                    ResultValue::Point(mac),
                    ResultValue::Point(modifier),
                ]
            },
        );

        AuthenticatedPointResult {
            share: results[0].clone().into(),
            mac: results[1].clone().into(),
            public_modifier: results[2].clone(),
        }
    }

    /// Multiscalar multiplication on iterator types
    pub fn msm_iter<S, P>(scalars: S, points: P) -> AuthenticatedPointResult<C>
    where
        S: IntoIterator<Item = AuthenticatedScalarResult<C>>,
        P: IntoIterator<Item = AuthenticatedPointResult<C>>,
    {
        let scalars = scalars.into_iter().collect::<Vec<_>>();
        let points = points.into_iter().collect::<Vec<_>>();

        Self::msm(&scalars, &points)
    }
}

// ----------------
// | Test Helpers |
// ----------------

/// Defines testing helpers for testing secure opening, these methods are not
/// safe to use outside of tests
#[cfg(feature = "test_helpers")]
pub mod test_helpers {
    use ark_ec::CurveGroup;

    use crate::algebra::curve::CurvePoint;

    use super::AuthenticatedPointResult;

    /// Corrupt the MAC of a given authenticated point
    pub fn modify_mac<C: CurveGroup>(
        point: &mut AuthenticatedPointResult<C>,
        new_mac: CurvePoint<C>,
    ) {
        point.mac = point.fabric().allocate_point(new_mac).into()
    }

    /// Corrupt the underlying secret share of a given authenticated point
    pub fn modify_share<C: CurveGroup>(
        point: &mut AuthenticatedPointResult<C>,
        new_share: CurvePoint<C>,
    ) {
        point.share = point.fabric().allocate_point(new_share).into()
    }

    /// Corrupt the public modifier of a given authenticated point
    pub fn modify_public_modifier<C: CurveGroup>(
        point: &mut AuthenticatedPointResult<C>,
        new_modifier: CurvePoint<C>,
    ) {
        point.public_modifier = point.fabric().allocate_point(new_modifier)
    }
}
