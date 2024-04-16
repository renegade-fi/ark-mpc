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
    algebra::{macros::*, scalar::*},
    commitment::{HashCommitment, HashCommitmentResult},
    error::MpcError,
    fabric::ResultValue,
    network::NetworkPayload,
    ResultHandle, ResultId, PARTY0,
};

use super::{
    curve::{BatchCurvePointResult, CurvePoint, CurvePointResult},
    PointShare,
};

/// A maliciously secure wrapper around `MpcPointResult` that includes a MAC as
/// per the SPDZ protocol: https://eprint.iacr.org/2011/535.pdf
#[allow(type_alias_bounds)]
pub type AuthenticatedPointResult<C: CurveGroup> = ResultHandle<C, PointShare<C>>;

impl<C: CurveGroup> AuthenticatedPointResult<C> {
    /// Get the IDs of the results that make up the `AuthenticatedPointResult`
    /// representation
    pub(crate) fn ids(&self) -> Vec<ResultId> {
        vec![self.id()]
    }

    /// Open the value without checking the MAC
    pub fn open(&self) -> CurvePointResult<C> {
        let (val0, val1) = if self.party_id() == PARTY0 {
            let party0_value = self.fabric().new_network_op(self.ids(), |mut args| {
                let share: PointShare<C> = args.next().unwrap().into();
                NetworkPayload::Point(share.share())
            });
            let party1_value: CurvePointResult<C> = self.fabric().receive_value();

            (party0_value, party1_value)
        } else {
            let party0_value: CurvePointResult<C> = self.fabric().receive_value();
            let party1_value = self.fabric().new_network_op(self.ids(), |mut args| {
                let share: PointShare<C> = args.next().unwrap().into();
                NetworkPayload::Point(share.share())
            });

            (party0_value, party1_value)
        };

        val0 + val1
    }

    /// Open a batch of values without checking the MAC
    pub fn open_batch(values: &[Self]) -> Vec<CurvePointResult<C>> {
        if values.is_empty() {
            return Vec::new();
        }

        let n = values.len();
        let fabric = values[0].fabric();
        let my_results = values.iter().map(|val| val.id()).collect_vec();

        // Party zero sends first then receives
        let (party0_vals, party1_vals) = if values[0].fabric().party_id() == PARTY0 {
            // Send the local shares
            let party0_vals: BatchCurvePointResult<C> = fabric.new_network_op(my_results, |args| {
                let shares: Vec<CurvePoint<C>> =
                    args.map(PointShare::from).map(|s| s.share()).collect();
                NetworkPayload::PointBatch(shares)
            });
            let party1_vals: BatchCurvePointResult<C> = fabric.receive_value();

            (party0_vals, party1_vals)
        } else {
            let party0_vals: BatchCurvePointResult<C> = fabric.receive_value();
            let party1_vals: BatchCurvePointResult<C> = fabric.new_network_op(my_results, |args| {
                let shares: Vec<CurvePoint<C>> =
                    args.map(PointShare::from).map(|s| s.share()).collect();
                NetworkPayload::PointBatch(shares)
            });

            (party0_vals, party1_vals)
        };

        // Create the new values by combining the additive shares
        fabric.new_batch_gate_op(vec![party0_vals.id, party1_vals.id], n, move |mut args| {
            let party0_vals: Vec<CurvePoint<C>> = args.next().unwrap().into();
            let party1_vals: Vec<CurvePoint<C>> = args.next().unwrap().into();

            let mut results = Vec::with_capacity(n);
            for i in 0..n {
                results.push(ResultValue::Point(party0_vals[i] + party1_vals[i]));
            }

            results
        })
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
            values: vec![peer_mac_share],
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
        let recovered_value = self.open();
        let fabric = self.fabric();

        // Add a gate to compute hte MAC check value: `key_share * opened_value -
        // mac_share`
        let mac_key = fabric.mac_key();
        let mac_check: CurvePointResult<C> =
            fabric.new_gate_op(vec![recovered_value.id(), self.id()], move |mut args| {
                let value: CurvePoint<C> = args.next().unwrap().into();
                let share: PointShare<C> = args.next().unwrap().into();

                ResultValue::Point(value * mac_key - share.mac())
            });

        // Compute a commitment to this value and share it with the peer
        let my_comm = HashCommitmentResult::commit(mac_check.clone());
        let peer_commit = self.fabric().exchange_value(my_comm.commitment);

        // Once the parties have exchanged their commitments, they can open the
        // underlying MAC check value as they are bound by the commitment
        let peer_mac_check = self.fabric().exchange_value(my_comm.values[0].clone());
        let blinder_result: ScalarResult<C> = self.fabric().allocate_scalar(my_comm.blinder);
        let peer_blinder = self.fabric().exchange_value(blinder_result);

        // Check the peer's commitment and the sum of the MAC checks
        let commitment_check: ScalarResult<C> = self.fabric().new_gate_op(
            vec![mac_check.id, peer_mac_check.id, peer_blinder.id, peer_commit.id],
            move |mut args| {
                let my_mac_check: CurvePoint<C> = args.next().unwrap().into();
                let peer_mac_check: CurvePoint<C> = args.next().unwrap().into();
                let peer_blinder: Scalar<C> = args.next().unwrap().into();
                let peer_commitment: Scalar<C> = args.next().unwrap().into();

                ResultValue::Scalar(Scalar::from(Self::verify_mac_check(
                    my_mac_check,
                    peer_mac_check,
                    peer_commitment,
                    peer_blinder,
                )))
            },
        );

        AuthenticatedPointOpenResult { value: recovered_value, mac_check: commitment_check }
    }

    /// Open a batch of values and check the MACs
    pub fn open_authenticated_batch(values: &[Self]) -> Vec<AuthenticatedPointOpenResult<C>> {
        if values.is_empty() {
            return Vec::new();
        }

        let n = values.len();
        let fabric = values[0].fabric();
        let mac_key = fabric.mac_key();

        // Open the values
        let opened_values = Self::open_batch(values);

        // --- MAC Check --- //

        // Compute the shares of the MAC check in batch
        let mut mac_check_deps = Vec::with_capacity(1 + 2 * n);
        for i in 0..n {
            mac_check_deps.push(opened_values[i].id());
            mac_check_deps.push(values[i].id());
        }

        let mac_checks: Vec<CurvePointResult<C>> =
            fabric.new_batch_gate_op(mac_check_deps, n /* output_arity */, move |mut args| {
                let mut check_result = Vec::with_capacity(n);

                for _ in 0..n {
                    let value: CurvePoint<C> = args.next().unwrap().into();
                    let share: PointShare<C> = args.next().unwrap().into();

                    check_result.push(mac_key * value - share.mac());
                }

                check_result.into_iter().map(ResultValue::Point).collect()
            });

        // --- Commit to the MAC checks --- //

        let my_comms = mac_checks.iter().cloned().map(HashCommitmentResult::commit).collect_vec();
        let peer_comms = fabric
            .exchange_values(&my_comms.iter().map(|comm| comm.commitment.clone()).collect_vec());

        // --- Exchange the MAC Checks and Commitment Blinders --- //

        let peer_mac_checks = fabric.exchange_values(&mac_checks);
        let peer_blinders = fabric.exchange_values(
            &my_comms.iter().map(|comm| fabric.allocate_scalar(comm.blinder)).collect_vec(),
        );

        // --- Check the MAC Checks --- //

        let mut mac_check_gate_deps = Vec::with_capacity(n + 3);
        mac_check_gate_deps.push(peer_mac_checks.id);
        mac_check_gate_deps.push(peer_blinders.id);
        mac_check_gate_deps.push(peer_comms.id);
        mac_check_gate_deps.extend(my_comms.iter().map(|comm| comm.values[0].id));

        let commitment_checks: Vec<ScalarResult<C>> = fabric.new_batch_gate_op(
            mac_check_gate_deps,
            n, // output_arity
            move |mut args| {
                let peer_mac_checks: Vec<CurvePoint<C>> = args.next().unwrap().into();
                let peer_blinders: Vec<Scalar<C>> = args.next().unwrap().into();
                let peer_comms: Vec<Scalar<C>> = args.next().unwrap().into();
                let my_comms: Vec<CurvePoint<C>> = args.map(|comm| comm.into()).collect();

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
            .map(|(value, check)| AuthenticatedPointOpenResult { value, mac_check: check })
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
        let first =
            iter.next().expect("AuthenticatedPointResult<C>::sum requires a non-empty iterator");
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
        let fabric = self.fabric();
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();

        let rhs = *other;
        fabric.new_gate_op(self.ids(), move |mut args| {
            let lhs: PointShare<C> = args.next().unwrap().into();
            let new_share = lhs.add_public(rhs, mac_key, party_id);

            ResultValue::PointShare(new_share)
        })
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Add, add, +, CurvePoint<C>, C: CurveGroup);
impl_commutative!(AuthenticatedPointResult<C>, Add, add, +, CurvePoint<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&CurvePointResult<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn add(self, other: &CurvePointResult<C>) -> AuthenticatedPointResult<C> {
        let fabric = self.fabric();
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();

        fabric.new_gate_op(vec![self.id(), other.id()], move |mut args| {
            let lhs: PointShare<C> = args.next().unwrap().into();
            let rhs: CurvePoint<C> = args.next().unwrap().into();

            let new_share = lhs.add_public(rhs, mac_key, party_id);
            ResultValue::PointShare(new_share)
        })
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Add, add, +, CurvePointResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedPointResult<C>, Add, add, +, CurvePointResult<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&AuthenticatedPointResult<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn add(self, other: &AuthenticatedPointResult<C>) -> AuthenticatedPointResult<C> {
        self.fabric.new_gate_op(vec![self.id(), other.id()], |mut args| {
            let lhs: PointShare<C> = args.next().unwrap().into();
            let rhs: PointShare<C> = args.next().unwrap().into();

            ResultValue::PointShare(lhs + rhs)
        })
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

        let mut all_ids = Vec::with_capacity(2 * n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.push(a.id());
            all_ids.push(b.id());
        }

        fabric.new_batch_gate_op(all_ids, n, move |args| {
            let mut result = Vec::with_capacity(n);
            for mut chunk in &args.chunks(2) {
                let a_share: PointShare<C> = chunk.next().unwrap().into();
                let b_share: PointShare<C> = chunk.next().unwrap().into();

                result.push(ResultValue::PointShare(a_share + b_share));
            }

            result
        })
    }

    /// Add a batch of `AuthenticatedPointResult`s to a batch of
    /// `CurvePointResult`s
    pub fn batch_add_public(
        a: &[AuthenticatedPointResult<C>],
        b: &[CurvePointResult<C>],
    ) -> Vec<AuthenticatedPointResult<C>> {
        assert_eq!(a.len(), b.len(), "batch_add_public requires equal length vectors");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();

        let mut all_ids = Vec::with_capacity(2 * n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.push(a.id());
            all_ids.push(b.id());
        }

        fabric.new_batch_gate_op(all_ids, n, move |args| {
            let mut result = Vec::with_capacity(n);
            for mut chunk in &args.chunks(2) {
                let a_share: PointShare<C> = chunk.next().unwrap().into();
                let public_value: CurvePoint<C> = chunk.next().unwrap().into();
                let new_share = a_share.add_public(public_value, mac_key, party_id);

                result.push(ResultValue::PointShare(new_share));
            }

            result
        })
    }
}

// === Subtraction === //

impl<C: CurveGroup> Sub<&CurvePoint<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn sub(self, other: &CurvePoint<C>) -> AuthenticatedPointResult<C> {
        let fabric = self.fabric();
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();

        let rhs = *other;
        fabric.new_gate_op(self.ids(), move |mut args| {
            let lhs: PointShare<C> = args.next().unwrap().into();

            let new_share = lhs.sub_public(rhs, mac_key, party_id);
            ResultValue::PointShare(new_share)
        })
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Sub, sub, -, CurvePoint<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&CurvePointResult<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn sub(self, other: &CurvePointResult<C>) -> AuthenticatedPointResult<C> {
        let fabric = self.fabric();
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();

        fabric.new_gate_op(vec![self.id(), other.id()], move |mut args| {
            let lhs: PointShare<C> = args.next().unwrap().into();
            let rhs: CurvePoint<C> = args.next().unwrap().into();
            let new_share = lhs.sub_public(rhs, mac_key, party_id);

            ResultValue::PointShare(new_share)
        })
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Sub, sub, -, CurvePointResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&AuthenticatedPointResult<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn sub(self, other: &AuthenticatedPointResult<C>) -> AuthenticatedPointResult<C> {
        self.fabric.new_gate_op(vec![self.id(), other.id()], |mut args| {
            let lhs: PointShare<C> = args.next().unwrap().into();
            let rhs: PointShare<C> = args.next().unwrap().into();

            ResultValue::PointShare(lhs - rhs)
        })
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

        let mut all_ids = Vec::with_capacity(2 * n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.push(a.id());
            all_ids.push(b.id());
        }

        fabric.new_batch_gate_op(all_ids, n, move |args| {
            let mut result = Vec::with_capacity(n);
            for mut chunk in &args.chunks(2) {
                let a_share: PointShare<C> = chunk.next().unwrap().into();
                let b_share: PointShare<C> = chunk.next().unwrap().into();

                result.push(ResultValue::PointShare(a_share - b_share));
            }

            result
        })
    }

    /// Subtract a batch of `AuthenticatedPointResult`s to a batch of
    /// `CurvePointResult`s
    pub fn batch_sub_public(
        a: &[AuthenticatedPointResult<C>],
        b: &[CurvePointResult<C>],
    ) -> Vec<AuthenticatedPointResult<C>> {
        assert_eq!(a.len(), b.len(), "batch_add_public requires equal length vectors");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();

        let mut all_ids = Vec::with_capacity(2 * n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.push(a.id());
            all_ids.push(b.id());
        }

        fabric.new_batch_gate_op(all_ids, n, move |args| {
            let mut result = Vec::with_capacity(n);
            for mut chunk in &args.chunks(2) {
                let a_share: PointShare<C> = chunk.next().unwrap().into();
                let b_share: CurvePoint<C> = chunk.next().unwrap().into();
                let new_share = a_share.sub_public(b_share, mac_key, party_id);

                result.push(ResultValue::PointShare(new_share));
            }

            result
        })
    }
}

// === Negation == //

impl<C: CurveGroup> Neg for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn neg(self) -> AuthenticatedPointResult<C> {
        self.fabric.new_gate_op(self.ids(), |mut args| {
            let share: PointShare<C> = args.next().unwrap().into();
            ResultValue::PointShare(-share)
        })
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

        fabric.new_batch_gate_op(all_ids, n, move |args| {
            args.into_iter()
                .map(PointShare::from)
                .map(PointShare::neg)
                .map(ResultValue::PointShare)
                .collect_vec()
        })
    }
}

// === Scalar<C> Multiplication === //

impl<C: CurveGroup> Mul<&Scalar<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn mul(self, other: &Scalar<C>) -> AuthenticatedPointResult<C> {
        let rhs = *other;
        self.fabric().new_gate_op(self.ids(), move |mut args| {
            let share: PointShare<C> = args.next().unwrap().into();
            ResultValue::PointShare(share * rhs)
        })
    }
}
impl_borrow_variants!(AuthenticatedPointResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
impl_commutative!(AuthenticatedPointResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&ScalarResult<C>> for &AuthenticatedPointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn mul(self, other: &ScalarResult<C>) -> AuthenticatedPointResult<C> {
        self.fabric().new_gate_op(vec![self.id(), other.id()], move |mut args| {
            let share: PointShare<C> = args.next().unwrap().into();
            let rhs: Scalar<C> = args.next().unwrap().into();

            ResultValue::PointShare(share * rhs)
        })
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
        let (a, b, c) = self.fabric().next_triple();

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
        let (beaver_a, beaver_b, beaver_c) = fabric.next_triple_batch(n);
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
        assert_eq!(a.len(), b.len(), "batch_mul_public requires equal length vectors");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();

        let mut all_ids = Vec::with_capacity(2 * n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.push(a.id());
            all_ids.push(b.id());
        }

        fabric.new_batch_gate_op(
            all_ids,
            n, // output_arity
            move |args| {
                let mut res = Vec::with_capacity(n);
                for mut chunk in &args.chunks(2) {
                    let scalar: Scalar<C> = chunk.next().unwrap().into();
                    let share: PointShare<C> = chunk.next().unwrap().into();

                    res.push(ResultValue::PointShare(share * scalar));
                }

                res
            },
        )
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
        fabric.new_batch_gate_op(
            all_ids,
            n, // output_arity
            move |args| {
                let scalars = args.into_iter().map(ScalarShare::from).collect_vec();
                let generator = CurvePoint::generator();

                scalars
                    .into_iter()
                    .map(|x| x * generator)
                    .map(ResultValue::PointShare)
                    .collect_vec()
            },
        )
    }
}

// === Multiscalar Multiplication === //

impl<C: CurveGroup> AuthenticatedPointResult<C> {
    /// Multiscalar multiplication
    pub fn msm(
        scalars: &[AuthenticatedScalarResult<C>],
        points: &[AuthenticatedPointResult<C>],
    ) -> AuthenticatedPointResult<C> {
        assert_eq!(scalars.len(), points.len(), "multiscalar_mul requires equal length vectors");
        assert!(!scalars.is_empty(), "multiscalar_mul requires non-empty vectors");

        let mul_out = AuthenticatedPointResult::batch_mul(scalars, points);

        // Create a gate to sum the points
        let fabric = scalars[0].fabric();
        let all_ids = mul_out.iter().flat_map(|p| p.ids()).collect_vec();

        fabric.new_gate_op(all_ids, move |mut args| {
            let mut share: PointShare<C> = args.next().unwrap().into();
            args.map(PointShare::from).for_each(|x| share = share + x);

            ResultValue::PointShare(share)
        })
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

    use crate::{
        algebra::{curve::CurvePoint, PointShare},
        ResultValue,
    };

    use super::AuthenticatedPointResult;

    /// Corrupt the MAC of a given authenticated point
    pub fn modify_mac<C: CurveGroup>(
        point: &mut AuthenticatedPointResult<C>,
        new_mac: CurvePoint<C>,
    ) {
        *point = point.fabric.new_gate_op(point.ids(), move |mut args| {
            let mut point: PointShare<C> = args.next().unwrap().into();
            point.mac = new_mac;

            ResultValue::PointShare(point)
        });
    }

    /// Corrupt the underlying secret share of a given authenticated point
    pub fn modify_share<C: CurveGroup>(
        point: &mut AuthenticatedPointResult<C>,
        new_share: CurvePoint<C>,
    ) {
        *point = point.fabric.new_gate_op(point.ids(), move |mut args| {
            let mut point: PointShare<C> = args.next().unwrap().into();
            point.mac = new_share;

            ResultValue::PointShare(point)
        });
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use rand::thread_rng;

    use crate::{
        algebra::{AuthenticatedPointResult, CurvePoint, Scalar},
        random_point,
        test_helpers::{execute_mock_mpc, open_await_all_points, TestCurve},
        PARTY0, PARTY1,
    };

    // ------------
    // | Addition |
    // ------------

    /// Tests addition with a constant value
    #[tokio::test]
    async fn test_add_constant() {
        let a = random_point();
        let b = random_point();

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_point(a, PARTY0);
            let res = &a_shared + b;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), a + b)
    }

    /// Tests addition with a public (allocated but not shared) value
    #[tokio::test]
    async fn test_add_public() {
        let a = random_point();
        let b = random_point();

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_point(a, PARTY0);
            let b = fabric.allocate_point(b);
            let res = &a_shared + b;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), a + b)
    }

    /// Tests authenticated curve point addition
    #[tokio::test]
    async fn test_add() {
        let p1 = random_point();
        let p2 = random_point();

        let expected = p1 + p2;

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let p1_shared = fabric.share_point(p1, PARTY0);
            let p2_shared = fabric.share_point(p2, PARTY1);

            let res = p1_shared + p2_shared;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), expected);
    }

    /// Tests batch addition with public (allocated but not shared) values
    #[tokio::test]
    async fn test_batch_add_public() {
        const N: usize = 100;
        let a = (0..N).map(|_| random_point()).collect_vec();
        let b = (0..N).map(|_| random_point()).collect_vec();
        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a + b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a_shared = fabric.batch_share_point(a, PARTY0);
                let b = fabric.allocate_points(b);
                let res = AuthenticatedPointResult::batch_add_public(&a_shared, &b);

                open_await_all_points(&res).await
            }
        })
        .await;

        assert_eq!(res, expected_res)
    }

    /// Tests batch addition with authenticated curve points
    #[tokio::test]
    async fn test_batch_add() {
        const N: usize = 100;
        let a = (0..N).map(|_| random_point()).collect_vec();
        let b = (0..N).map(|_| random_point()).collect_vec();
        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a + b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a_shared = fabric.batch_share_point(a, PARTY0);
                let b_shared = fabric.batch_share_point(b, PARTY1);
                let res = AuthenticatedPointResult::batch_add(&a_shared, &b_shared);

                open_await_all_points(&res).await
            }
        })
        .await;

        assert_eq!(res, expected_res)
    }

    // ---------------
    // | Subtraction |
    // ---------------

    /// Tests subtraction between a shared value and a constant
    #[tokio::test]
    async fn test_sub_constant() {
        let a = random_point();
        let b = random_point();

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_point(a, PARTY0);
            let res = &a_shared - b;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), a - b)
    }

    /// Tests subtraction between a shared value and a public value
    #[tokio::test]
    async fn test_sub_public() {
        let a = random_point();
        let b = random_point();

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_point(a, PARTY0);
            let b = fabric.allocate_point(b);
            let res = a_shared - b;

            res.open_authenticated().await.unwrap()
        })
        .await;

        assert_eq!(res, a - b)
    }

    /// Tests subtraction between two shared values
    #[tokio::test]
    async fn test_sub() {
        let a = random_point();
        let b = random_point();

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_point(a, PARTY0);
            let b_shared = fabric.share_point(b, PARTY1);
            let res = a_shared - b_shared;

            res.open_authenticated().await.unwrap()
        })
        .await;

        assert_eq!(res, a - b)
    }

    /// Tests batch subtraction between a shared value and a public value
    #[tokio::test]
    async fn test_batch_sub_public() {
        const N: usize = 100;
        let a = (0..N).map(|_| random_point()).collect_vec();
        let b = (0..N).map(|_| random_point()).collect_vec();
        let expected = a.iter().zip(b.iter()).map(|(a, b)| a - b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a_shared = fabric.batch_share_point(a, PARTY0);
                let b = fabric.allocate_points(b);
                let res = AuthenticatedPointResult::batch_sub_public(&a_shared, &b);

                open_await_all_points(&res).await
            }
        })
        .await;

        assert_eq!(res, expected)
    }

    /// Tests batch subtraction between two shared values
    #[tokio::test]
    async fn test_batch_sub() {
        const N: usize = 100;
        let a = (0..N).map(|_| random_point()).collect_vec();
        let b = (0..N).map(|_| random_point()).collect_vec();
        let expected = a.iter().zip(b.iter()).map(|(a, b)| a - b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a_shared = fabric.batch_share_point(a, PARTY0);
                let b_shared = fabric.batch_share_point(b, PARTY1);
                let res = AuthenticatedPointResult::batch_sub(&a_shared, &b_shared);

                open_await_all_points(&res).await
            }
        })
        .await;

        assert_eq!(res, expected)
    }

    // ------------
    // | Negation |
    // ------------

    /// Tests negation of a curve point
    #[tokio::test]
    async fn test_negation() {
        let p = random_point();
        let expected = -p;

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let p_shared = fabric.share_point(p, PARTY0);
            let res = -p_shared;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), expected)
    }

    /// Tests batch negation of curve points
    #[tokio::test]
    async fn test_batch_negation() {
        const N: usize = 100;
        let p = (0..N).map(|_| random_point()).collect_vec();
        let expected = p.iter().map(|p| -p).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let p = p.clone();
            async move {
                let p_shared = fabric.batch_share_point(p, PARTY0);
                let res = AuthenticatedPointResult::batch_neg(&p_shared);

                open_await_all_points(&res).await
            }
        })
        .await;

        assert_eq!(res, expected)
    }

    // ------------------
    // | Multiplication |
    // ------------------

    /// Tests multiplication with a constant scalar
    #[tokio::test]
    async fn test_mul_constant() {
        let mut rng = thread_rng();
        let p = random_point();
        let s = Scalar::random(&mut rng);
        let expected = p * s;

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let p_shared = fabric.share_point(p, PARTY0);
            let res = &p_shared * s;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), expected)
    }

    /// Tests multiplication with a public (allocated but not shared) scalar
    #[tokio::test]
    async fn test_mul_public_scalar() {
        let mut rng = thread_rng();
        let p = random_point();
        let s = Scalar::random(&mut rng);
        let expected = p * s;

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let p_shared = fabric.share_point(p, PARTY0);
            let s = fabric.allocate_scalar(s);
            let res = &p_shared * s;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), expected)
    }

    /// Tests multiplication with a shared scalar
    #[tokio::test]
    async fn test_mul_shared_scalar() {
        let mut rng = thread_rng();
        let p = random_point();
        let s = Scalar::random(&mut rng);
        let expected = p * s;

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let p_shared = fabric.share_point(p, PARTY0);
            let s_shared = fabric.share_scalar(s, PARTY1);
            let res = &p_shared * s_shared;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), expected)
    }

    /// Tests batch multiplication with public (allocated but not shared)
    /// scalars
    #[tokio::test]
    async fn test_batch_mul_public() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let a = (0..N).map(|_| random_point()).collect_vec();
        let b = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a * b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a_shared = fabric.batch_share_point(a, PARTY0);
                let b = fabric.allocate_scalars(b);
                let res = AuthenticatedPointResult::batch_mul_public(&b, &a_shared);

                open_await_all_points(&res).await
            }
        })
        .await;

        assert_eq!(res, expected_res)
    }

    /// Tests batch multiplication with shared scalars
    #[tokio::test]
    async fn test_batch_mul() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let a = (0..N).map(|_| random_point()).collect_vec();
        let b = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a * b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a_shared = fabric.batch_share_point(a, PARTY0);
                let b = fabric.allocate_scalars(b);
                let res = AuthenticatedPointResult::batch_mul_public(&b, &a_shared);

                open_await_all_points(&res).await
            }
        })
        .await;

        assert_eq!(res, expected_res)
    }

    /// Tests batch multiplication with generator
    #[tokio::test]
    async fn test_batch_mul_generator() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let a = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let expected_res = a.iter().map(|x| x * CurvePoint::<TestCurve>::generator()).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            async move {
                let a_shared = fabric.batch_share_scalar(a, PARTY0);
                let res = AuthenticatedPointResult::batch_mul_generator(&a_shared);

                open_await_all_points(&res).await
            }
        })
        .await;

        assert_eq!(res, expected_res)
    }

    // ------------------------------
    // | Multiscalar Multiplication |
    // ------------------------------

    /// Tests multiscalar multiplication
    #[tokio::test]
    async fn test_msm() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let a = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| random_point()).collect_vec();
        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a * b).sum();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a_shared = fabric.batch_share_scalar(a, PARTY0);
                let b = fabric.batch_share_point(b, PARTY1);
                let res = AuthenticatedPointResult::msm(&a_shared, &b);

                res.open_authenticated().await.unwrap()
            }
        })
        .await;

        assert_eq!(res, expected_res)
    }
}
