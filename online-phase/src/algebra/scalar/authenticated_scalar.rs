//! Defines the authenticated (malicious secure) variant of the MPC scalar type

use std::{
    iter::{self, Sum},
    ops::{Add, Div, Mul, Neg, Sub},
    pin::Pin,
    task::{Context, Poll},
};

use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_poly::EvaluationDomain;
use futures::{Future, FutureExt};
use itertools::{izip, Itertools};

use crate::{
    algebra::{macros::*, AuthenticatedPointResult, CurvePoint, CurvePointResult},
    commitment::{HashCommitment, HashCommitmentResult},
    error::MpcError,
    fabric::{ResultId, ResultValue},
    network::NetworkPayload,
    ResultHandle, PARTY0,
};

use super::{
    scalar::{BatchScalarResult, Scalar, ScalarResult},
    ScalarShare,
};

// -----------------------------
// | AuthenticatedScalarResult |
// -----------------------------

/// A maliciously secure wrapper around an `MpcScalarResult`, includes a MAC as
/// per the SPDZ protocol: https://eprint.iacr.org/2011/535.pdf
/// that ensures security against a malicious adversary
#[allow(type_alias_bounds)]
pub type AuthenticatedScalarResult<C: CurveGroup> = ResultHandle<C, ScalarShare<C>>;

impl<C: CurveGroup> AuthenticatedScalarResult<C> {
    /// Get the ids of the results that must be awaited
    /// before the value is ready
    pub fn ids(&self) -> Vec<ResultId> {
        vec![self.id()]
    }

    /// Compute the inverse of a
    pub fn inverse(&self) -> AuthenticatedScalarResult<C> {
        let mut res = Self::batch_inverse(&[self.clone()]);
        res.remove(0)
    }

    /// Compute a batch of inverses of an `AuthenticatedScalarResult`s
    ///
    /// This follows the protocol detailed in:
    ///     https://dl.acm.org/doi/pdf/10.1145/72981.72995
    /// Which gives a two round implementation
    pub fn batch_inverse(
        values: &[AuthenticatedScalarResult<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        let n = values.len();
        assert!(n > 0, "cannot invert empty batch of scalars");

        let fabric = values[0].fabric();

        // For the following steps, let the input values be x_i for i=1..n

        // 1. Sample a random shared group element from the shared value source
        // call these values r_i for i=1..n
        let shared_scalars = fabric.random_shared_scalars(n);

        // 2. Mask the values by multiplying them with the random scalars, i.e. compute
        //    m_i = (r_i * x_i)
        // Open the masked values to both parties
        let masked_values = AuthenticatedScalarResult::batch_mul(values, &shared_scalars);
        let masked_values_open = Self::open_authenticated_batch(&masked_values);

        // 3. Compute the inverse of the masked values: m_i^-1 = (x_i^-1 * r_i^-1)
        let opening_values = masked_values_open.into_iter().map(|val| val.value).collect_vec();
        let inverted_openings = ScalarResult::batch_inverse(&opening_values);

        // 4. Multiply these inverted openings with the original shared scalars r_i:
        //    m_i^-1 * r_i = (x_i^-1 * r_i^-1) * r_i = x_i^-1
        AuthenticatedScalarResult::batch_mul_public(&shared_scalars, &inverted_openings)
    }

    /// Compute the exponentiation of the given value
    /// via recursive squaring
    pub fn pow(&self, exp: u64) -> Self {
        if exp == 0 {
            return self.fabric().zero_authenticated();
        } else if exp == 1 {
            return self.clone();
        }

        let recursive = self.pow(exp / 2);
        let mut res = &recursive * &recursive;

        if exp % 2 == 1 {
            res = res * self.clone();
        }
        res
    }
}

/// Opening implementations
impl<C: CurveGroup> AuthenticatedScalarResult<C> {
    /// Open the value without checking its MAC
    pub fn open(&self) -> ScalarResult<C> {
        let (val0, val1) = if self.party_id() == PARTY0 {
            let party0_value = self.fabric().new_network_op(self.ids(), |mut args| {
                let share: ScalarShare<C> = args.next().unwrap().into();
                NetworkPayload::Scalar(share.share())
            });
            let party1_value: ScalarResult<C> = self.fabric().receive_value();

            (party0_value, party1_value)
        } else {
            let party0_value: ScalarResult<C> = self.fabric().receive_value();
            let party1_value = self.fabric().new_network_op(self.ids(), |mut args| {
                let share: ScalarShare<C> = args.next().unwrap().into();
                NetworkPayload::Scalar(share.share())
            });

            (party0_value, party1_value)
        };

        val0 + val1
    }

    /// Open a batch of values without checking their MACs
    pub fn open_batch(values: &[Self]) -> Vec<ScalarResult<C>> {
        if values.is_empty() {
            return Vec::new();
        }

        let n = values.len();
        let fabric = values[0].fabric();
        let my_results = values.iter().map(|val| val.id()).collect_vec();

        // Party zero sends first then receives
        let (party0_vals, party1_vals) = if values[0].fabric().party_id() == PARTY0 {
            // Send the local shares
            let party0_vals: BatchScalarResult<C> = fabric.new_network_op(my_results, |args| {
                let shares: Vec<Scalar<C>> =
                    args.map(ScalarShare::from).map(|s| s.share()).collect();
                NetworkPayload::ScalarBatch(shares)
            });
            let party1_vals: BatchScalarResult<C> = fabric.receive_value();

            (party0_vals, party1_vals)
        } else {
            let party0_vals: BatchScalarResult<C> = fabric.receive_value();
            let party1_vals: BatchScalarResult<C> = fabric.new_network_op(my_results, |args| {
                let shares: Vec<Scalar<C>> =
                    args.map(ScalarShare::from).map(|s| s.share()).collect();
                NetworkPayload::ScalarBatch(shares)
            });

            (party0_vals, party1_vals)
        };

        // Create the new values by combining the additive shares
        fabric.new_batch_gate_op(vec![party0_vals.id, party1_vals.id], n, move |mut args| {
            let party0_vals: Vec<Scalar<C>> = args.next().unwrap().into();
            let party1_vals: Vec<Scalar<C>> = args.next().unwrap().into();

            let mut results = Vec::with_capacity(n);
            for i in 0..n {
                results.push(ResultValue::Scalar(party0_vals[i] + party1_vals[i]));
            }

            results
        })
    }

    /// Check the commitment to a MAC check and that the MAC checks sum to zero
    pub fn verify_mac_check(
        my_mac_share: Scalar<C>,
        peer_mac_share: Scalar<C>,
        peer_mac_commitment: Scalar<C>,
        peer_commitment_blinder: Scalar<C>,
    ) -> bool {
        let their_comm = HashCommitment {
            values: vec![peer_mac_share],
            blinder: peer_commitment_blinder,
            commitment: peer_mac_commitment,
        };

        // Verify that the commitment to the MAC check opens correctly
        if !their_comm.verify() {
            return false;
        }

        // Sum of the commitments should be zero
        if peer_mac_share + my_mac_share != Scalar::zero() {
            return false;
        }

        true
    }

    /// Verify a batch of MAC checks
    pub fn batch_verify_mac_check(
        my_mac_shares: &[Scalar<C>],
        peer_mac_shares: &[Scalar<C>],
        peer_commitment_blinder: Scalar<C>,
        peer_mac_commitment: Scalar<C>,
    ) -> bool {
        // Verify a commitment to the openings
        let comm = HashCommitment {
            values: peer_mac_shares.to_vec(),
            blinder: peer_commitment_blinder,
            commitment: peer_mac_commitment,
        };
        if !comm.verify() {
            return false;
        }

        // Build a commitment from the gate inputs
        izip!(my_mac_shares, peer_mac_shares)
            .all(|(my_share, peer_share)| my_share + peer_share == Scalar::zero())
    }

    /// Open the value and check its MAC
    ///
    /// This follows the protocol detailed in:
    ///     https://securecomputation.org/docs/pragmaticmpc.pdf
    /// Section 6.6.2
    pub fn open_authenticated(&self) -> AuthenticatedScalarOpenResult<C> {
        // Both parties open the underlying value
        let recovered_value = self.open();
        let fabric = self.fabric();

        // Add a gate to compute the MAC check value: `key_share * opened_value -
        // mac_share`
        let mac_key = fabric.mac_key();
        let mac_check_value: ScalarResult<C> =
            fabric.new_gate_op(vec![recovered_value.id, self.id()], move |mut args| {
                let value: Scalar<C> = args.next().unwrap().into();
                let share: ScalarShare<C> = args.next().unwrap().into();

                ResultValue::Scalar(mac_key * value - share.mac())
            });

        // Compute a commitment to this value and share it with the peer
        let my_comm = HashCommitmentResult::commit(mac_check_value);
        let peer_commit = self.fabric().exchange_value(my_comm.commitment);

        // Once the parties have exchanged their commitments, they can open them, they
        // have already exchanged the underlying values and their commitments so
        // all that is left is the blinder
        let peer_mac_check = self.fabric().exchange_value(my_comm.values[0].clone());

        let blinder_result: ScalarResult<C> = self.fabric().allocate_scalar(my_comm.blinder);
        let peer_blinder = self.fabric().exchange_value(blinder_result);

        // Check the commitment and the MAC result
        let commitment_check: ScalarResult<C> = self.fabric().new_gate_op(
            vec![my_comm.values[0].id, peer_mac_check.id, peer_blinder.id, peer_commit.id],
            |mut args| {
                let my_comm_value: Scalar<C> = args.next().unwrap().into();
                let peer_value: Scalar<C> = args.next().unwrap().into();
                let blinder: Scalar<C> = args.next().unwrap().into();
                let commitment: Scalar<C> = args.next().unwrap().into();

                // Build a commitment from the gate inputs
                ResultValue::Scalar(Scalar::from(Self::verify_mac_check(
                    my_comm_value,
                    peer_value,
                    commitment,
                    blinder,
                )))
            },
        );

        AuthenticatedScalarOpenResult { value: recovered_value, mac_check: commitment_check }
    }

    /// Open a batch of values and check their MACs
    pub fn open_authenticated_batch(values: &[Self]) -> Vec<AuthenticatedScalarOpenResult<C>> {
        if values.is_empty() {
            return vec![];
        }

        let n = values.len();
        let fabric = &values[0].fabric();
        let mac_key = fabric.mac_key();

        // Both parties open the underlying values
        let values_open = Self::open_batch(values);

        // --- Mac Checks --- //

        // Compute the shares of the MAC check in batch
        let mut mac_check_deps = Vec::with_capacity(2 * n);
        for i in 0..n {
            mac_check_deps.push(values_open[i].id());
            mac_check_deps.push(values[i].id());
        }

        let mac_checks: Vec<ScalarResult<C>> =
            fabric.new_batch_gate_op(mac_check_deps, n /* output_arity */, move |mut args| {
                let mut check_result = Vec::with_capacity(n);

                for _ in 0..n {
                    let value: Scalar<C> = args.next().unwrap().into();
                    let share: ScalarShare<C> = args.next().unwrap().into();

                    check_result.push(mac_key * value - share.mac());
                }

                check_result.into_iter().map(ResultValue::Scalar).collect()
            });

        // --- Commit to MAC Checks --- //

        let my_comm = HashCommitmentResult::batch_commit(mac_checks.clone());
        let peer_comm = fabric.exchange_value(my_comm.commitment);

        // --- Exchange the MAC Checks and Commitment Blinders --- //

        let peer_mac_checks = fabric.exchange_values(&mac_checks);
        let peer_blinder = fabric.exchange_value(fabric.allocate_scalar(my_comm.blinder));

        // --- Check the MAC Checks --- //

        let mut mac_check_gate_deps = Vec::with_capacity(3 + n);
        mac_check_gate_deps.push(peer_mac_checks.id);
        mac_check_gate_deps.push(peer_blinder.id);
        mac_check_gate_deps.push(peer_comm.id);
        mac_check_gate_deps.extend(my_comm.values.iter().map(|v| v.id()));

        let commitment_check: ScalarResult<C> =
            fabric.new_gate_op(mac_check_gate_deps, move |mut args| {
                let peer_mac_checks: Vec<Scalar<C>> = args.next().unwrap().into();
                let peer_blinder: Scalar<C> = args.next().unwrap().into();
                let peer_comm: Scalar<C> = args.next().unwrap().into();
                let my_comms: Vec<Scalar<C>> = args.map(|comm| comm.into()).collect();

                let res = Self::batch_verify_mac_check(
                    &my_comms,
                    &peer_mac_checks,
                    peer_blinder,
                    peer_comm,
                );
                ResultValue::Scalar(Scalar::from(res))
            });

        // --- Return the results --- //

        values_open
            .into_iter()
            .zip(iter::repeat(commitment_check))
            .map(|(value, check)| AuthenticatedScalarOpenResult { value, mac_check: check })
            .collect_vec()
    }
}

/// The value that results from opening an `AuthenticatedScalarResult` and
/// checking its MAC. This encapsulates both the underlying value and the result
/// of the MAC check
#[derive(Clone)]
pub struct AuthenticatedScalarOpenResult<C: CurveGroup> {
    /// The underlying value
    pub value: ScalarResult<C>,
    /// The result of the MAC check
    pub mac_check: ScalarResult<C>,
}

impl<C: CurveGroup> Future for AuthenticatedScalarOpenResult<C>
where
    C::ScalarField: Unpin,
{
    type Output = Result<Scalar<C>, MpcError>;

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

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl<C: CurveGroup> Add<&Scalar<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn add(self, rhs: &Scalar<C>) -> Self::Output {
        // Both parties add the public value to their modifier, and the MACs do not
        // change when adding a public value
        let fabric = self.fabric();
        let party_id = self.party_id();
        let mac_key = fabric.mac_key();

        let rhs_copy = *rhs;
        fabric.new_gate_op(self.ids(), move |mut args| {
            let share: ScalarShare<C> = args.next().unwrap().into();
            let new_share = share.add_public(rhs_copy, mac_key, party_id);

            ResultValue::ScalarShare(new_share)
        })
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Add, add, +, Scalar<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedScalarResult<C>, Add, add, +, Scalar<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&ScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: &ScalarResult<C>) -> Self::Output {
        // As above, only party 0 adds the public value to their share, but both parties
        // track this with the modifier
        //
        // Party 1 adds a zero value to their share to allocate a new ID for the result
        let fabric = self.fabric();
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();

        fabric.new_gate_op(vec![self.id(), rhs.id()], move |mut args| {
            let share: ScalarShare<C> = args.next().unwrap().into();
            let rhs: Scalar<C> = args.next().unwrap().into();

            let new_share = share.add_public(rhs, mac_key, party_id);
            ResultValue::ScalarShare(new_share)
        })
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Add, add, +, ScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedScalarResult<C>, Add, add, +, ScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&AuthenticatedScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn add(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        self.fabric().new_gate_op(vec![self.id(), rhs.id()], |mut args| {
            let lhs: ScalarShare<C> = args.next().unwrap().into();
            let rhs: ScalarShare<C> = args.next().unwrap().into();

            let new_share = lhs + rhs;
            ResultValue::ScalarShare(new_share)
        })
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Add, add, +, AuthenticatedScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> AuthenticatedScalarResult<C> {
    /// Add two batches of `AuthenticatedScalarResult`s
    pub fn batch_add(
        a: &[AuthenticatedScalarResult<C>],
        b: &[AuthenticatedScalarResult<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Cannot add batches of different sizes");

        let n = a.len();
        let fabric = a[0].fabric();

        // Collect ids chunking the result into the order in which they will be added
        let mut all_ids = Vec::with_capacity(2 * n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.push(a.id());
            all_ids.push(b.id());
        }

        // Add the underlying values
        fabric.new_batch_gate_op(
            all_ids,
            n, // output_arity
            move |args| {
                let mut result = Vec::with_capacity(n);
                for mut chunk in &args.chunks(2) {
                    let a_share: ScalarShare<C> = chunk.next().unwrap().into();
                    let b_share: ScalarShare<C> = chunk.next().unwrap().into();

                    result.push(ResultValue::ScalarShare(a_share + b_share));
                }

                result
            },
        )
    }

    /// Add a batch of `AuthenticatedScalarResult`s to a batch of
    /// `ScalarResult`s
    pub fn batch_add_public(
        a: &[AuthenticatedScalarResult<C>],
        b: &[ScalarResult<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        let n = a.len();
        assert_eq!(n, b.len(), "Cannot add batches of different sizes");
        let fabric = a[0].fabric();

        let mut all_ids = Vec::with_capacity(n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.push(a.id());
            all_ids.push(b.id());
        }

        // Add the underlying values
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();

        fabric.new_batch_gate_op(
            all_ids,
            n, // output_arity
            move |args| {
                // Split the args
                let mut result = Vec::with_capacity(n);
                for mut chunk in &args.chunks(2) {
                    let a_share: ScalarShare<C> = chunk.next().unwrap().into();
                    let public_value: Scalar<C> = chunk.next().unwrap().into();

                    let new_share = a_share.add_public(public_value, mac_key, party_id);
                    result.push(ResultValue::ScalarShare(new_share));
                }

                result
            },
        )
    }

    /// Add a batch of `Scalar`s to a batch of  `AuthenticatedScalarResult`s
    pub fn batch_add_constant(
        a: &[AuthenticatedScalarResult<C>],
        b: &[Scalar<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Cannot add batches of different sizes");

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().map(|v| v.id()).collect_vec();

        // Add the underlying values
        let b = b.to_vec();
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();
        fabric.new_batch_gate_op(
            all_ids,
            n, // output_arity
            move |args| {
                let mut result = Vec::with_capacity(n);
                for (arg, public_value) in args.into_iter().zip(b.into_iter()) {
                    let a_share: ScalarShare<C> = arg.into();
                    let new_share = a_share.add_public(public_value, mac_key, party_id);

                    result.push(ResultValue::ScalarShare(new_share));
                }

                result
            },
        )
    }
}

impl<C: CurveGroup> Sum for AuthenticatedScalarResult<C> {
    /// Assumes the iterator is non-empty
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let values = iter.collect_vec();
        let fabric = values[0].fabric();

        // Add the underlying values
        let ids = values.iter().map(|v| v.id()).collect_vec();
        fabric.new_gate_op(ids, move |args| {
            let sum = args.map(ScalarShare::from).sum();
            ResultValue::ScalarShare(sum)
        })
    }
}

// === Subtraction === //

impl<C: CurveGroup> Sub<&Scalar<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn sub(self, rhs: &Scalar<C>) -> Self::Output {
        self + -rhs
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Sub, sub, -, Scalar<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&AuthenticatedScalarResult<C>> for &Scalar<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn sub(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        let val = *self;
        let fabric = rhs.fabric();
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();

        fabric.new_gate_op(rhs.ids(), move |mut args| {
            let share: ScalarShare<C> = args.next().unwrap().into();
            let new_share = (-share).add_public(val, mac_key, party_id);

            ResultValue::ScalarShare(new_share)
        })
    }
}
impl_borrow_variants!(Scalar<C>, Sub, sub, -, AuthenticatedScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&ScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn sub(self, rhs: &ScalarResult<C>) -> Self::Output {
        let fabric = self.fabric();
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();

        fabric.new_gate_op(vec![self.id(), rhs.id()], move |mut args| {
            let share: ScalarShare<C> = args.next().unwrap().into();
            let rhs: Scalar<C> = args.next().unwrap().into();

            let new_share = share.sub_public(rhs, mac_key, party_id);
            ResultValue::ScalarShare(new_share)
        })
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Sub, sub, -, ScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&AuthenticatedScalarResult<C>> for &ScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn sub(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        let fabric = rhs.fabric();
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();

        fabric.new_gate_op(vec![self.id(), rhs.id()], move |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            let share: ScalarShare<C> = args.next().unwrap().into();

            let new_share = (-share).add_public(lhs, mac_key, party_id);
            ResultValue::ScalarShare(new_share)
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Sub, sub, -, AuthenticatedScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&AuthenticatedScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn sub(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id(), rhs.id()], |mut args| {
            let lhs: ScalarShare<C> = args.next().unwrap().into();
            let rhs: ScalarShare<C> = args.next().unwrap().into();

            ResultValue::ScalarShare(lhs - rhs)
        })
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Sub, sub, -, AuthenticatedScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> AuthenticatedScalarResult<C> {
    /// Add two batches of `AuthenticatedScalarResult`s
    pub fn batch_sub(
        a: &[AuthenticatedScalarResult<C>],
        b: &[AuthenticatedScalarResult<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        let n = a.len();
        assert_eq!(n, b.len(), "Cannot add batches of different sizes");
        let fabric = &a[0].fabric();

        let mut all_ids = Vec::with_capacity(n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.push(a.id());
            all_ids.push(b.id());
        }

        // Sub the underlying values
        fabric.new_batch_gate_op(all_ids, n /* arity */, move |args| {
            let mut result = Vec::with_capacity(n);
            for mut chunk in &args.chunks(2) {
                let a_share: ScalarShare<C> = chunk.next().unwrap().into();
                let b_share: ScalarShare<C> = chunk.next().unwrap().into();

                result.push(ResultValue::ScalarShare(a_share - b_share));
            }

            result
        })
    }

    /// Subtract a batch of `ScalarResult`s from a batch of
    /// `AuthenticatedScalarResult`s
    pub fn batch_sub_public(
        a: &[AuthenticatedScalarResult<C>],
        b: &[ScalarResult<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Cannot add batches of different sizes");

        let n = a.len();
        let fabric = a[0].fabric();

        let mut all_ids = Vec::with_capacity(n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.push(a.id());
            all_ids.push(b.id());
        }

        // Add the underlying values
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();

        fabric.new_batch_gate_op(
            all_ids,
            n, // output_arity
            move |args| {
                // Split the args
                let mut result = Vec::with_capacity(n);
                for mut chunk in &args.chunks(2) {
                    let share: ScalarShare<C> = chunk.next().unwrap().into();
                    let public_value: Scalar<C> = chunk.next().unwrap().into();

                    let new_share = share.sub_public(public_value, mac_key, party_id);
                    result.push(ResultValue::ScalarShare(new_share));
                }

                result
            },
        )
    }
}

// === Negation === //

impl<C: CurveGroup> Neg for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn neg(self) -> Self::Output {
        self.fabric.new_gate_op(self.ids(), |mut args| {
            let share: ScalarShare<C> = args.next().unwrap().into();
            ResultValue::ScalarShare(-share)
        })
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Neg, neg, -, C: CurveGroup);

impl<C: CurveGroup> AuthenticatedScalarResult<C> {
    /// Negate a batch of `AuthenticatedScalarResult`s
    pub fn batch_neg(a: &[AuthenticatedScalarResult<C>]) -> Vec<AuthenticatedScalarResult<C>> {
        if a.is_empty() {
            return vec![];
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().map(|v| v.id()).collect_vec();

        fabric.new_batch_gate_op(
            all_ids,
            n, // output_arity
            |args| {
                args.into_iter()
                    .map(|arg| ResultValue::ScalarShare(-ScalarShare::from(arg)))
                    .collect()
            },
        )
    }
}

// === Multiplication === //

impl<C: CurveGroup> Mul<&Scalar<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        self.fabric().new_gate_op(self.ids(), move |mut args| {
            let share: ScalarShare<C> = args.next().unwrap().into();
            ResultValue::ScalarShare(share * rhs)
        })
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Mul, mul, *, Scalar<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedScalarResult<C>, Mul, mul, *, Scalar<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&ScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn mul(self, rhs: &ScalarResult<C>) -> Self::Output {
        self.fabric().new_gate_op(vec![self.id(), rhs.id()], |mut args| {
            let lhs: ScalarShare<C> = args.next().unwrap().into();
            let rhs: Scalar<C> = args.next().unwrap().into();

            ResultValue::ScalarShare(lhs * rhs)
        })
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Mul, mul, *, ScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedScalarResult<C>, Mul, mul, *, ScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&AuthenticatedScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    // Use the Beaver trick
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        // Sample a beaver triplet
        let (a, b, c) = self.fabric().next_triple();

        // Mask the left and right hand sides and open them
        let masked_lhs_rhs = AuthenticatedScalarResult::batch_sub(
            &[self.clone(), rhs.clone()],
            &[a.clone(), b.clone()],
        );
        let mut opened_values = AuthenticatedScalarResult::open_batch(&masked_lhs_rhs);

        let e = opened_values.pop().unwrap();
        let d = opened_values.pop().unwrap();

        // Use the same beaver identify as in the `MpcScalarResult<C>` case, but now the
        // public multiplications are applied to the MACs and the public
        // modifiers as well Identity: [x * y] = de + d[b] + e[a] + [c]
        let fabric = self.fabric();
        let party_id = fabric.party_id();
        let mac_key = fabric.mac_key();
        let ids = vec![a.id(), b.id(), c.id(), d.id(), e.id()];

        fabric.new_gate_op(ids, move |mut args| {
            // Destructure the args iter
            let a_share: ScalarShare<C> = args.next().unwrap().into();
            let b_share: ScalarShare<C> = args.next().unwrap().into();
            let c_share: ScalarShare<C> = args.next().unwrap().into();

            let d: Scalar<C> = args.next().unwrap().into();
            let e: Scalar<C> = args.next().unwrap().into();

            // Compute the beaver identity: [x * y] = de + d[b] + e[a] + [c]
            let de = d * e;
            let res = d * b_share + e * a_share + c_share;
            let res = res.add_public(de, mac_key, party_id);

            ResultValue::ScalarShare(res)
        })
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Mul, mul, *, AuthenticatedScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> AuthenticatedScalarResult<C> {
    /// Multiply a batch of values using the Beaver trick
    pub fn batch_mul(
        a: &[AuthenticatedScalarResult<C>],
        b: &[AuthenticatedScalarResult<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Cannot multiply batches of different sizes");

        if a.is_empty() {
            return vec![];
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let (beaver_a, beaver_b, beaver_c) = fabric.next_triple_batch(n);

        // Open the values d = [lhs - a] and e = [rhs - b]
        let masked_lhs = AuthenticatedScalarResult::batch_sub(a, &beaver_a);
        let masked_rhs = AuthenticatedScalarResult::batch_sub(b, &beaver_b);

        let all_masks = [masked_lhs, masked_rhs].concat();
        let opened_values = AuthenticatedScalarResult::open_batch(&all_masks);
        let (d_open, e_open) = opened_values.split_at(n);

        // Identity: [x * y] = de + d[b] + e[a] + [c]
        let de = ScalarResult::batch_mul(d_open, e_open);
        let db = AuthenticatedScalarResult::batch_mul_public(&beaver_b, d_open);
        let ea = AuthenticatedScalarResult::batch_mul_public(&beaver_a, e_open);

        // Add the terms
        let de_plus_db = AuthenticatedScalarResult::batch_add_public(&db, &de);
        let ea_plus_c = AuthenticatedScalarResult::batch_add(&ea, &beaver_c);
        AuthenticatedScalarResult::batch_add(&de_plus_db, &ea_plus_c)
    }

    /// Multiply a batch of `AuthenticatedScalarResult`s by a batch of
    /// `ScalarResult`s
    pub fn batch_mul_public(
        a: &[AuthenticatedScalarResult<C>],
        b: &[ScalarResult<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Cannot multiply batches of different sizes");
        if a.is_empty() {
            return vec![];
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
                let mut result = Vec::with_capacity(n);
                for mut chunk in &args.chunks(2) {
                    let a_share: ScalarShare<C> = chunk.next().unwrap().into();
                    let public_value: Scalar<C> = chunk.next().unwrap().into();

                    result.push(ResultValue::ScalarShare(a_share * public_value));
                }

                result
            },
        )
    }

    /// Multiply a batch of `AuthenticatedScalarResult`s by a batch of `Scalar`s
    pub fn batch_mul_constant(
        a: &[AuthenticatedScalarResult<C>],
        b: &[Scalar<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Cannot multiply batches of different sizes");
        if a.is_empty() {
            return vec![];
        }

        let n = a.len();
        let fabric = a[0].fabric();

        let b = b.to_vec();
        let ids = a.iter().map(|a| a.id()).collect_vec();

        fabric.new_batch_gate_op(
            ids,
            n, // output_arity
            move |args| {
                let mut result = Vec::with_capacity(n);
                for (a_val, b_val) in args.into_iter().zip(b.into_iter()) {
                    let a_share: ScalarShare<C> = a_val.into();

                    result.push(ResultValue::ScalarShare(a_share * b_val));
                }

                result
            },
        )
    }
}

// === Division === //
#[allow(clippy::suspicious_arithmetic_impl)]
impl<C: CurveGroup> Div<&ScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;
    fn div(self, rhs: &ScalarResult<C>) -> Self::Output {
        let rhs_inv = rhs.inverse();
        self * rhs_inv
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Div, div, /, ScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

#[allow(clippy::suspicious_arithmetic_impl)]
impl<C: CurveGroup> Div<&AuthenticatedScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;
    fn div(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        let rhs_inv = rhs.inverse();
        self * rhs_inv
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Div, div, /, AuthenticatedScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> AuthenticatedScalarResult<C> {
    /// Divide two batches of values
    pub fn batch_div(a: &[Self], b: &[Self]) -> Vec<Self> {
        let b_inv = Self::batch_inverse(b);
        Self::batch_mul(a, &b_inv)
    }
}

// === Curve Scalar Multiplication === //

impl<C: CurveGroup> Mul<&AuthenticatedScalarResult<C>> for &CurvePoint<C> {
    type Output = AuthenticatedPointResult<C>;

    fn mul(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        let lhs = *self;
        rhs.fabric().new_gate_op(vec![rhs.id()], move |mut args| {
            let scalar: ScalarShare<C> = args.next().unwrap().into();
            ResultValue::PointShare(lhs * scalar)
        })
    }
}
impl_commutative!(CurvePoint<C>, Mul, mul, *, AuthenticatedScalarResult<C>, Output=AuthenticatedPointResult<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&AuthenticatedScalarResult<C>> for &CurvePointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn mul(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        self.fabric().new_gate_op(vec![self.id(), rhs.id()], |mut args| {
            let point: CurvePoint<C> = args.next().unwrap().into();
            let scalar: ScalarShare<C> = args.next().unwrap().into();

            ResultValue::PointShare(point * scalar)
        })
    }
}
impl_borrow_variants!(CurvePointResult<C>, Mul, mul, *, AuthenticatedScalarResult<C>, Output=AuthenticatedPointResult<C>, C: CurveGroup);
impl_commutative!(CurvePointResult<C>, Mul, mul, *, AuthenticatedScalarResult<C>, Output=AuthenticatedPointResult<C>, C: CurveGroup);

// === FFT and IFFT === //
impl<C: CurveGroup> AuthenticatedScalarResult<C>
where
    C::ScalarField: FftField,
{
    /// Compute the FFT of a vector of `AuthenticatedScalarResult`s
    pub fn fft<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[AuthenticatedScalarResult<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        Self::fft_with_domain::<D>(x, D::new(x.len()).unwrap())
    }

    /// Compute the FFT of a vector of `AuthenticatedScalarResult`s with a given
    /// domain
    pub fn fft_with_domain<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[AuthenticatedScalarResult<C>],
        domain: D,
    ) -> Vec<AuthenticatedScalarResult<C>> {
        Self::fft_helper::<D>(x, true /* is_forward */, domain)
    }

    /// Compute the inverse FFT of a vector of `AuthenticatedScalarResult`s
    pub fn ifft<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[AuthenticatedScalarResult<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        Self::fft_helper::<D>(x, false /* is_forward */, D::new(x.len()).unwrap())
    }

    /// Compute the inverse FFT of a vector of `AuthenticatedScalarResult`s with
    /// a given domain
    pub fn ifft_with_domain<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[AuthenticatedScalarResult<C>],
        domain: D,
    ) -> Vec<AuthenticatedScalarResult<C>> {
        Self::fft_helper::<D>(x, false /* is_forward */, domain)
    }

    /// An FFT/IFFT helper that encapsulates the setup and restructuring of an
    /// FFT regardless of direction
    ///
    /// If `is_forward` is set, an FFT is performed. Otherwise, an IFFT is
    /// performed
    fn fft_helper<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[AuthenticatedScalarResult<C>],
        is_forward: bool,
        domain: D,
    ) -> Vec<AuthenticatedScalarResult<C>> {
        assert!(!x.is_empty(), "Cannot compute FFT of empty vector");
        let n = domain.size();

        let fabric = x[0].fabric();
        let ids = x.iter().map(|v| v.id()).collect_vec();

        fabric.new_batch_gate_op(ids, n, move |args| {
            let shares: Vec<ScalarShare<C>> = args.map(ScalarShare::from).collect();
            let res = ScalarShare::fft_helper(&shares, is_forward, domain);

            res.into_iter().map(|x| ResultValue::ScalarShare(x)).collect()
        })
    }
}

// ----------------
// | Test Helpers |
// ----------------

/// Contains unsafe helpers for modifying values, methods in this module should
/// *only* be used for testing
#[cfg(feature = "test_helpers")]
pub mod test_helpers {
    use ark_ec::CurveGroup;

    use crate::{
        algebra::{scalar::Scalar, ScalarShare},
        ResultValue,
    };

    use super::AuthenticatedScalarResult;

    /// Modify the MAC of an `AuthenticatedScalarResult`
    pub fn modify_mac<C: CurveGroup>(val: &mut AuthenticatedScalarResult<C>, new_value: Scalar<C>) {
        *val = val.fabric().new_gate_op(val.ids(), move |mut args| {
            let mut share: ScalarShare<C> = args.next().unwrap().into();
            share.mac = new_value;

            ResultValue::ScalarShare(share)
        });
    }

    /// Modify the underlying secret share of an `AuthenticatedScalarResult`
    pub fn modify_share<C: CurveGroup>(
        val: &mut AuthenticatedScalarResult<C>,
        new_value: Scalar<C>,
    ) {
        *val = val.fabric().new_gate_op(val.ids(), move |mut args| {
            let mut share: ScalarShare<C> = args.next().unwrap().into();
            share.share = new_value;

            ResultValue::ScalarShare(share)
        });
    }
}

#[cfg(test)]
mod tests {
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use futures::future;
    use itertools::Itertools;
    use rand::{thread_rng, Rng, RngCore};

    use crate::{
        algebra::{poly_test_helpers::TestPolyField, scalar::Scalar, AuthenticatedScalarResult},
        test_helpers::{execute_mock_mpc, open_await_all, TestCurve},
        PARTY0, PARTY1,
    };

    // ------------
    // | Addition |
    // ------------

    /// Tests addition with a constant value
    #[tokio::test]
    async fn test_add_constant() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_scalar(a, PARTY0);
            let res = &a_shared + b;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), a + b)
    }

    /// Tests batch addition with constant values
    #[tokio::test]
    async fn test_batch_add_constant() {
        const N: usize = 100;
        let mut rng = thread_rng();

        let a = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a + b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();

            async move {
                let a_shared = fabric.batch_share_scalar(a, PARTY0 /* sender */);
                let res = AuthenticatedScalarResult::batch_add_constant(&a_shared, &b);
                open_await_all(&res).await
            }
        })
        .await;

        assert_eq!(res, expected_res)
    }

    /// Tests addition with a public value    
    #[tokio::test]
    async fn test_add_public() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_scalar(a, PARTY0);
            let b = fabric.allocate_scalar(b);
            let res = &a_shared + b;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), a + b)
    }

    /// Tests batch addition with public values
    #[tokio::test]
    async fn test_batch_add_public() {
        const N: usize = 100;
        let mut rng = thread_rng();

        let a = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();

            async move {
                let a_shared = fabric.batch_share_scalar(a, PARTY0);
                let b = fabric.allocate_scalars(b);

                let res = AuthenticatedScalarResult::batch_add_public(&a_shared, &b);
                open_await_all(&res).await
            }
        })
        .await;

        let expected = a.iter().zip(b.iter()).map(|(a, b)| a + b).collect_vec();
        assert_eq!(res, expected)
    }

    /// Tests adding two shared values
    #[tokio::test]
    async fn test_add() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_scalar(a, PARTY0);
            let b_shared = fabric.share_scalar(b, PARTY1);

            (a_shared + b_shared).open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), a + b)
    }

    /// Tests adding two batches of shared values
    #[tokio::test]
    async fn test_batch_add() {
        const N: usize = 100;
        let mut rng = thread_rng();

        let a = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let expected = a.iter().zip(b.iter()).map(|(a, b)| a + b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();

            async move {
                let a_shared = fabric.batch_share_scalar(a, PARTY0);
                let b_shared = fabric.batch_share_scalar(b, PARTY1);

                let res = AuthenticatedScalarResult::batch_add(&a_shared, &b_shared);
                open_await_all(&res).await
            }
        })
        .await;

        assert_eq!(res, expected)
    }

    /// Tests summing values
    #[tokio::test]
    async fn test_sum() {
        const N: usize = 100;
        let mut rng = thread_rng();

        let values = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let expected_res = values.iter().cloned().sum();

        let (res, _) = execute_mock_mpc(|fabric| {
            let values = values.clone();
            async move {
                let values_shared = fabric.batch_share_scalar(values, PARTY0);

                let res: AuthenticatedScalarResult<TestCurve> = values_shared.into_iter().sum();
                res.open_authenticated().await
            }
        })
        .await;

        assert_eq!(res.unwrap(), expected_res)
    }

    // ---------------
    // | Subtraction |
    // ---------------

    /// Test subtraction with a constant value
    #[tokio::test]
    async fn test_sub_constant() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_scalar(a, PARTY0);
            let res = &a_shared - b;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), a - b)
    }

    /// Tests subtraction with a public value
    #[tokio::test]
    async fn test_sub_public() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_scalar(a, PARTY0);
            let b = fabric.allocate_scalar(b);
            let res = &a_shared - b;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), a - b)
    }

    /// Tests batch subtraction with a public value
    #[tokio::test]
    async fn test_batch_sub_public() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let a = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a - b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let shared_values = fabric.batch_share_scalar(a, PARTY0 /* sender */);
                let b = fabric.allocate_scalars(b);
                let res = AuthenticatedScalarResult::batch_sub_public(&shared_values, &b);

                open_await_all(&res).await
            }
        })
        .await;

        assert_eq!(res, expected_res)
    }

    /// Test subtraction across non-commutative types
    #[tokio::test]
    async fn test_sub() {
        let mut rng = thread_rng();
        let value1 = Scalar::random(&mut rng);
        let value2 = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            // Allocate the first value as a shared scalar and the second as a public scalar
            let party0_value = fabric.share_scalar(value1, PARTY0);
            let public_value = fabric.allocate_scalar(value2);

            // Subtract the public value from the shared value
            let res1 = &party0_value - &public_value;
            let res_open1 = res1.open_authenticated().await.unwrap();
            let expected1 = value1 - value2;

            // Subtract the shared value from the public value
            let res2 = &public_value - &party0_value;
            let res_open2 = res2.open_authenticated().await.unwrap();
            let expected2 = value2 - value1;

            (res_open1 == expected1, res_open2 == expected2)
        })
        .await;

        assert!(res.0);
        assert!(res.1)
    }

    /// Tests batch subtraction between two sets of shared values
    #[tokio::test]
    async fn test_batch_sub() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let a = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a - b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let shared_values_a = fabric.batch_share_scalar(a, PARTY0 /* sender */);
                let shared_values_b = fabric.batch_share_scalar(b, PARTY1 /* sender */);
                let res = AuthenticatedScalarResult::batch_sub(&shared_values_a, &shared_values_b);

                open_await_all(&res).await
            }
        })
        .await;

        assert_eq!(res, expected_res)
    }

    // ------------
    // | Negation |
    // ------------

    /// Tests negation of a shared value
    #[tokio::test]
    async fn test_negation() {
        let mut rng = thread_rng();
        let value = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let shared_value = fabric.share_scalar(value, PARTY0);
            let negated_value = -shared_value;

            negated_value.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), -value)
    }

    /// Tests batch negation of shared values
    #[tokio::test]
    async fn test_batch_negation() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let values = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        let expected_res = values.iter().map(|v| -v).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let values = values.clone();
            async move {
                let shared_values = fabric.batch_share_scalar(values, PARTY0);
                let negated_values = AuthenticatedScalarResult::batch_neg(&shared_values);

                open_await_all(&negated_values).await
            }
        })
        .await;

        assert_eq!(res, expected_res)
    }

    // ------------------
    // | Multiplication |
    // ------------------

    /// Tests multiplication between a constant and a shared value
    #[tokio::test]
    async fn test_mul_constant() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_scalar(a, PARTY0);
            let res = &a_shared * b;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), a * b)
    }

    /// Tests multiplication between a public and a shared value
    #[tokio::test]
    async fn test_mul_public() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_scalar(a, PARTY0);
            let b = fabric.allocate_scalar(b);
            let res = &a_shared * b;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), a * b)
    }

    /// Tests multiplication between two shared values
    #[tokio::test]
    async fn test_mul() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a_shared = fabric.share_scalar(a, PARTY0);
            let b_shared = fabric.share_scalar(b, PARTY1);

            (a_shared * b_shared).open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), a * b)
    }

    /// Tests the `batch_mul_constant` method
    #[tokio::test]
    async fn test_batch_mul_constant() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let a = (0..N).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();

        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a * b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let shared_values = fabric.batch_share_scalar(a, PARTY0 /* sender */);
                let res = AuthenticatedScalarResult::batch_mul_constant(&shared_values, &b);

                let opening = AuthenticatedScalarResult::open_authenticated_batch(&res);
                future::join_all(opening.into_iter())
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
            }
        })
        .await;

        assert_eq!(res.unwrap(), expected_res)
    }

    /// Tests batch multiplication between a shared and public scalar
    #[tokio::test]
    async fn test_batch_mul_public() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let a = (0..N).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();

        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a * b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let shared_values = fabric.batch_share_scalar(a, PARTY0 /* sender */);
                let public_values = fabric.allocate_scalars(b);

                let res =
                    AuthenticatedScalarResult::batch_mul_public(&shared_values, &public_values);
                open_await_all(&res).await
            }
        })
        .await;

        assert_eq!(res, expected_res)
    }

    /// Tests batch multiplication between two shared value batches
    #[tokio::test]
    async fn test_batch_mul() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let a = (0..N).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();

        let expected_res = a.iter().zip(b.iter()).map(|(a, b)| a * b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let shared_values1 = fabric.batch_share_scalar(a, PARTY0 /* sender */);
                let shared_values2 = fabric.batch_share_scalar(b, PARTY1 /* sender */);

                let res = AuthenticatedScalarResult::batch_mul(&shared_values1, &shared_values2);
                open_await_all(&res).await
            }
        })
        .await;

        assert_eq!(res, expected_res)
    }

    // ------------
    // | Division |
    // ------------

    /// Tests division between a shared and public scalar
    #[tokio::test]
    async fn test_public_division() {
        let mut rng = thread_rng();
        let value1 = Scalar::random(&mut rng);
        let value2 = Scalar::random(&mut rng);

        let expected_res = value1 * value2.inverse();

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let shared_value = fabric.share_scalar(value1, PARTY0);
            let public_value = fabric.allocate_scalar(value2);

            (shared_value / public_value).open().await
        })
        .await;

        assert_eq!(res, expected_res)
    }

    /// Tests division between two authenticated values
    #[tokio::test]
    async fn test_division() {
        let mut rng = thread_rng();
        let value1 = Scalar::random(&mut rng);
        let value2 = Scalar::random(&mut rng);

        let expected_res = value1 / value2;

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let shared_value1 = fabric.share_scalar(value1, PARTY0 /* sender */);
            let shared_value2 = fabric.share_scalar(value2, PARTY1 /* sender */);

            (shared_value1 / shared_value2).open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), expected_res)
    }

    /// Tests batch division between authenticated values
    #[tokio::test]
    async fn test_batch_div() {
        const N: usize = 100;
        let mut rng = thread_rng();

        let a_values = (0..N).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();
        let b_values = (0..N).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();

        let expected_res = a_values.iter().zip(b_values.iter()).map(|(a, b)| a / b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a_values.clone();
            let b = b_values.clone();
            async move {
                let shared_a = fabric.batch_share_scalar(a, PARTY0 /* sender */);
                let shared_b = fabric.batch_share_scalar(b, PARTY1 /* sender */);

                let res = AuthenticatedScalarResult::batch_div(&shared_a, &shared_b);
                let opening = AuthenticatedScalarResult::open_authenticated_batch(&res);
                future::join_all(opening.into_iter())
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
            }
        })
        .await;

        assert_eq!(res.unwrap(), expected_res)
    }

    // ------------
    // | Circuits |
    // ------------

    /// Test a simple `XOR` circuit
    #[tokio::test]
    async fn test_xor_circuit() {
        let (res, _) = execute_mock_mpc(|fabric| async move {
            let a = &fabric.zero_authenticated();
            let b = &fabric.zero_authenticated();
            let res = a + b - Scalar::from(2u64) * a * b;

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), 0u8.into());
    }

    /// Tests computing the inverse of a scalar
    #[tokio::test]
    async fn test_batch_inverse() {
        const N: usize = 10;

        let mut rng = thread_rng();
        let values = (0..N).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();
        let expected_res = values.iter().map(|v| v.inverse()).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let values = values.clone();
            async move {
                let shared_values = fabric.batch_share_scalar(values, PARTY0 /* sender */);
                let inverses = AuthenticatedScalarResult::batch_inverse(&shared_values);

                let opening = AuthenticatedScalarResult::open_authenticated_batch(&inverses);
                future::join_all(opening.into_iter())
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
            }
        })
        .await;

        assert_eq!(res.unwrap(), expected_res)
    }

    // ------------------------------
    // | Misc Arithmetic Operations |
    // ------------------------------

    /// Tests exponentiation
    #[tokio::test]
    async fn test_pow() {
        let mut rng = thread_rng();
        let exp = rng.next_u64();
        let value = Scalar::<TestCurve>::random(&mut rng);

        let expected_res = value.pow(exp);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            let shared_value = fabric.share_scalar(value, PARTY0 /* sender */);
            let res = shared_value.pow(exp);

            res.open().await
        })
        .await;

        assert_eq!(res, expected_res)
    }

    #[tokio::test]
    async fn test_fft() {
        let mut rng = thread_rng();
        let n: usize = rng.gen_range(0..100);
        let domain_size = rng.gen_range(n..10 * n);

        let values = (0..n).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();

        let domain = Radix2EvaluationDomain::<TestPolyField>::new(domain_size).unwrap();
        let fft_res = domain.fft(&values
                .iter()
                // Add one to test public modifiers
                .map(|v| (v + Scalar::one()).inner())
                .collect_vec());
        let expected_res = fft_res.into_iter().map(Scalar::new).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let values = values.clone();
            async move {
                let shared_values = fabric
                    .batch_share_scalar(values, PARTY0 /* sender */)
                    .into_iter()
                    .map(|v| v + Scalar::one())
                    .collect_vec();
                let fft = AuthenticatedScalarResult::fft_with_domain::<
                    Radix2EvaluationDomain<TestPolyField>,
                >(&shared_values, domain);

                let opening = AuthenticatedScalarResult::open_authenticated_batch(&fft);
                future::join_all(opening.into_iter())
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
            }
        })
        .await;

        let res = res.unwrap();
        assert_eq!(res.len(), expected_res.len());
        assert_eq!(res, expected_res[..res.len()])
    }

    #[tokio::test]
    async fn test_ifft() {
        let mut rng = thread_rng();
        let n: usize = rng.gen_range(0..100);
        let domain_size = rng.gen_range(n..10 * n);

        let values = (0..n).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();

        let domain = Radix2EvaluationDomain::<TestPolyField>::new(domain_size).unwrap();
        let ifft_res =
            domain.ifft(&values
                .iter()
                // Add one to test public modifiers
                .map(|v| (v + Scalar::one()).inner())
                .collect_vec());
        let expected_res = ifft_res.into_iter().map(Scalar::new).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let values = values.clone();
            async move {
                let shared_values = fabric.batch_share_scalar(values, PARTY0 /* sender */);
                let shared_values =
                    shared_values.into_iter().map(|v| v + Scalar::one()).collect_vec();

                let ifft = AuthenticatedScalarResult::ifft_with_domain::<
                    Radix2EvaluationDomain<TestPolyField>,
                >(&shared_values, domain);

                let opening = AuthenticatedScalarResult::open_authenticated_batch(&ifft);
                future::join_all(opening.into_iter())
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
            }
        })
        .await;

        assert_eq!(res.unwrap(), expected_res)
    }
}
