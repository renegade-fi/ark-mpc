//! Defines the authenticated (malicious secure) variant of the MPC scalar type

use std::{
    fmt::Debug,
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
    fabric::{MpcFabric, ResultId, ResultValue},
    PARTY0,
};

use super::{
    mpc_scalar::MpcScalarResult,
    scalar::{BatchScalarResult, Scalar, ScalarResult},
};

/// The number of results wrapped by an `AuthenticatedScalarResult<C>`
pub const AUTHENTICATED_SCALAR_RESULT_LEN: usize = 3;

/// A maliciously secure wrapper around an `MpcScalarResult`, includes a MAC as
/// per the SPDZ protocol: https://eprint.iacr.org/2011/535.pdf
/// that ensures security against a malicious adversary
#[derive(Clone)]
pub struct AuthenticatedScalarResult<C: CurveGroup> {
    /// The secret shares of the underlying value
    pub(crate) share: MpcScalarResult<C>,
    /// The SPDZ style, unconditionally secure MAC of the value
    ///
    /// If the value is `x`, parties hold secret shares of the value
    /// \delta * x for the global MAC key `\delta`. The parties individually
    /// hold secret shares of this MAC key [\delta], so we can very naturally
    /// extend the secret share arithmetic of the underlying `MpcScalarResult`
    /// to the MAC updates as well
    pub(crate) mac: MpcScalarResult<C>,
    /// The public modifier tracks additions and subtractions of public values
    /// to the underlying value. This is necessary because in the case of a
    /// public addition, only the first party adds the public value to their
    /// share, so the second party must track this up until the point that
    /// the value is opened and the MAC is checked
    pub(crate) public_modifier: ScalarResult<C>,
}

impl<C: CurveGroup> Debug for AuthenticatedScalarResult<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedScalarResult<C>")
            .field("value", &self.share.id())
            .field("mac", &self.mac.id())
            .field("public_modifier", &self.public_modifier.id)
            .finish()
    }
}

impl<C: CurveGroup> AuthenticatedScalarResult<C> {
    /// Create a new result from the given shared value
    pub fn new_shared(value: ScalarResult<C>) -> Self {
        // Create an `MpcScalarResult` to represent the fact that this is a shared value
        let fabric = value.fabric.clone();

        let mpc_value = MpcScalarResult::new_shared(value);
        let mac = fabric.borrow_mac_key() * mpc_value.clone();

        // Allocate a zero for the public modifier
        let public_modifier = fabric.zero();

        Self { share: mpc_value, mac, public_modifier }
    }

    /// Create a new batch of shared values
    pub fn new_shared_batch(values: &[ScalarResult<C>]) -> Vec<Self> {
        if values.is_empty() {
            return vec![];
        }

        let n = values.len();
        let fabric = values[0].fabric();
        let mpc_values =
            values.iter().map(|v| MpcScalarResult::new_shared(v.clone())).collect_vec();

        let mac_keys = (0..n).map(|_| fabric.borrow_mac_key().clone()).collect_vec();
        let values_macs = MpcScalarResult::batch_mul(&mpc_values, &mac_keys);

        mpc_values
            .into_iter()
            .zip(values_macs)
            .map(|(value, mac)| Self { share: value, mac, public_modifier: fabric.zero() })
            .collect_vec()
    }

    /// Create a nwe shared batch of values from a batch network result
    ///
    /// The batch result combines the batch into one result, so it must be split
    /// out first before creating the `AuthenticatedScalarResult`s
    pub fn new_shared_from_batch_result(
        values: BatchScalarResult<C>,
        n: usize,
    ) -> Vec<AuthenticatedScalarResult<C>> {
        // Convert to a set of scalar results
        let scalar_results: Vec<ScalarResult<C>> =
            values.fabric().new_batch_gate_op(vec![values.id()], n, |mut args| {
                let scalars: Vec<Scalar<C>> = args.next().unwrap().into();
                scalars.into_iter().map(ResultValue::Scalar).collect()
            });

        Self::new_shared_batch(&scalar_results)
    }

    /// Get the raw share as an `MpcScalarResult`
    #[cfg(feature = "test_helpers")]
    pub fn mpc_share(&self) -> MpcScalarResult<C> {
        self.share.clone()
    }

    /// Get the raw share as a `ScalarResult`
    pub fn share(&self) -> ScalarResult<C> {
        self.share.to_scalar()
    }

    /// Get the raw share of the MAC as a `ScalarResult`
    pub fn mac_share(&self) -> ScalarResult<C> {
        self.mac.to_scalar()
    }

    /// Get a reference to the underlying MPC fabric
    pub fn fabric(&self) -> &MpcFabric<C> {
        self.share.fabric()
    }

    /// Get the ids of the results that must be awaited
    /// before the value is ready
    pub fn ids(&self) -> Vec<ResultId> {
        vec![self.share.id(), self.mac.id(), self.public_modifier.id]
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
        let shared_scalars = fabric.random_shared_scalars_authenticated(n);

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
        self.share.open()
    }

    /// Open a batch of values without checking their MACs
    pub fn open_batch(values: &[Self]) -> Vec<ScalarResult<C>> {
        MpcScalarResult::open_batch(&values.iter().map(|val| val.share.clone()).collect_vec())
    }

    /// Convert a flattened iterator into a batch of
    /// `AuthenticatedScalarResult`s
    ///
    /// We assume that the iterator has been flattened in the same way order
    /// that `Self::id`s returns the `AuthenticatedScalar<C>`'s values:
    /// `[share, mac, public_modifier]`
    pub fn from_flattened_iterator<I>(iter: I) -> Vec<Self>
    where
        I: Iterator<Item = ScalarResult<C>>,
    {
        iter.chunks(AUTHENTICATED_SCALAR_RESULT_LEN)
            .into_iter()
            .map(|mut chunk| Self {
                share: chunk.next().unwrap().into(),
                mac: chunk.next().unwrap().into(),
                public_modifier: chunk.next().unwrap(),
            })
            .collect_vec()
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
        let recovered_value = self.share.open();

        // Add a gate to compute the MAC check value: `key_share * opened_value -
        // mac_share`
        let mac_check_value: ScalarResult<C> = self.fabric().new_gate_op(
            vec![
                self.fabric().borrow_mac_key().id(),
                recovered_value.id,
                self.public_modifier.id,
                self.mac.id(),
            ],
            move |mut args| {
                let mac_key_share: Scalar<C> = args.next().unwrap().into();
                let value: Scalar<C> = args.next().unwrap().into();
                let modifier: Scalar<C> = args.next().unwrap().into();
                let mac_share: Scalar<C> = args.next().unwrap().into();

                ResultValue::Scalar(mac_key_share * (value + modifier) - mac_share)
            },
        );

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

        // Both parties open the underlying values
        let values_open = Self::open_batch(values);

        // --- Mac Checks --- //

        // Compute the shares of the MAC check in batch
        let mut mac_check_deps = Vec::with_capacity(1 + 3 * n);
        mac_check_deps.push(fabric.borrow_mac_key().id());
        for i in 0..n {
            mac_check_deps.push(values_open[i].id());
            mac_check_deps.push(values[i].public_modifier.id());
            mac_check_deps.push(values[i].mac.id());
        }

        let mac_checks: Vec<ScalarResult<C>> =
            fabric.new_batch_gate_op(mac_check_deps, n /* output_arity */, move |mut args| {
                let mac_key_share: Scalar<C> = args.next().unwrap().into();
                let mut check_result = Vec::with_capacity(n);

                for _ in 0..n {
                    let value: Scalar<C> = args.next().unwrap().into();
                    let modifier: Scalar<C> = args.next().unwrap().into();
                    let mac_share: Scalar<C> = args.next().unwrap().into();

                    check_result.push(mac_key_share * (value + modifier) - mac_share);
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
        let new_share = if self.fabric().party_id() == PARTY0 {
            &self.share + rhs
        } else {
            &self.share + Scalar::zero()
        };

        // Both parties add the public value to their modifier, and the MACs do not
        // change when adding a public value
        let new_modifier = &self.public_modifier - rhs;
        AuthenticatedScalarResult {
            share: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Add, add, +, Scalar<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedScalarResult<C>, Add, add, +, Scalar<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&ScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn add(self, rhs: &ScalarResult<C>) -> Self::Output {
        // As above, only party 0 adds the public value to their share, but both parties
        // track this with the modifier
        //
        // Party 1 adds a zero value to their share to allocate a new ID for the result
        let new_share = if self.fabric().party_id() == PARTY0 {
            &self.share + rhs
        } else {
            &self.share + Scalar::zero()
        };

        let new_modifier = &self.public_modifier - rhs;
        AuthenticatedScalarResult {
            share: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Add, add, +, ScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedScalarResult<C>, Add, add, +, ScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&AuthenticatedScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn add(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        AuthenticatedScalarResult {
            share: &self.share + &rhs.share,
            mac: &self.mac + &rhs.mac,
            public_modifier: self.public_modifier.clone() + rhs.public_modifier.clone(),
        }
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
        let chunk_size = AUTHENTICATED_SCALAR_RESULT_LEN * 2;
        let mut all_ids = Vec::with_capacity(chunk_size * n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.extend(a.ids());
            all_ids.extend(b.ids());
        }

        // Add the underlying values
        let gate_results: Vec<ScalarResult<C>> = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_SCALAR_RESULT_LEN * n, // output_arity
            move |args| {
                let mut result = Vec::with_capacity(AUTHENTICATED_SCALAR_RESULT_LEN * n);
                for mut chunk in &args.chunks(chunk_size) {
                    let a_share: Scalar<C> = chunk.next().unwrap().into();
                    let a_mac_share: Scalar<C> = chunk.next().unwrap().into();
                    let a_modifier: Scalar<C> = chunk.next().unwrap().into();

                    let b_share: Scalar<C> = chunk.next().unwrap().into();
                    let b_mac_share: Scalar<C> = chunk.next().unwrap().into();
                    let b_modifier: Scalar<C> = chunk.next().unwrap().into();

                    result.push(ResultValue::Scalar(a_share + b_share));
                    result.push(ResultValue::Scalar(a_mac_share + b_mac_share));
                    result.push(ResultValue::Scalar(a_modifier + b_modifier));
                }

                result
            },
        );

        // Collect the gate results into a series of `AuthenticatedScalarResult`s
        AuthenticatedScalarResult::from_flattened_iterator(gate_results.into_iter())
    }

    /// Add a batch of `AuthenticatedScalarResult`s to a batch of
    /// `ScalarResult`s
    pub fn batch_add_public(
        a: &[AuthenticatedScalarResult<C>],
        b: &[ScalarResult<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Cannot add batches of different sizes");

        let n = a.len();
        let results_per_value = 3;
        let fabric = a[0].fabric();

        let chunk_size = AUTHENTICATED_SCALAR_RESULT_LEN + 1;
        let mut all_ids = Vec::with_capacity(chunk_size * n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.extend(a.ids());
            all_ids.push(b.id());
        }

        // Add the underlying values
        let party_id = fabric.party_id();
        let gate_results: Vec<ScalarResult<C>> = fabric.new_batch_gate_op(
            all_ids,
            results_per_value * n, // output_arity
            move |args| {
                // Split the args
                let mut result = Vec::with_capacity(results_per_value * n);
                for mut chunk in &args.chunks(chunk_size) {
                    let a_share: Scalar<C> = chunk.next().unwrap().into();
                    let a_mac_share: Scalar<C> = chunk.next().unwrap().into();
                    let a_modifier: Scalar<C> = chunk.next().unwrap().into();

                    let public_value: Scalar<C> = chunk.next().unwrap().into();

                    // Only the first party adds the public value to their share
                    if party_id == PARTY0 {
                        result.push(ResultValue::Scalar(a_share + public_value));
                    } else {
                        result.push(ResultValue::Scalar(a_share));
                    }

                    result.push(ResultValue::Scalar(a_mac_share));
                    result.push(ResultValue::Scalar(a_modifier - public_value));
                }

                result
            },
        );

        // Collect the gate results into a series of `AuthenticatedScalarResult<C>`s
        AuthenticatedScalarResult::from_flattened_iterator(gate_results.into_iter())
    }

    /// Add a batch of `Scalar`s to a batch of  `AuthenticatedScalarResult`s
    pub fn batch_add_constant(
        a: &[AuthenticatedScalarResult<C>],
        b: &[Scalar<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Cannot add batches of different sizes");

        let n = a.len();
        let results_per_value = 3;
        let fabric = a[0].fabric();
        let all_ids = a.iter().flat_map(|v| v.ids()).collect_vec();

        // Add the underlying values
        let b = b.to_vec();
        let party_id = fabric.party_id();
        let gate_results: Vec<ScalarResult<C>> = fabric.new_batch_gate_op(
            all_ids,
            results_per_value * n, // output_arity
            move |args| {
                let mut result = Vec::with_capacity(results_per_value * n);
                for (mut a_vals, public_value) in
                    args.chunks(results_per_value).into_iter().zip(b.into_iter())
                {
                    let a_share: Scalar<C> = a_vals.next().unwrap().into();
                    let a_mac_share: Scalar<C> = a_vals.next().unwrap().into();
                    let a_modifier: Scalar<C> = a_vals.next().unwrap().into();

                    // Only the first party adds the public value to their share
                    if party_id == PARTY0 {
                        result.push(ResultValue::Scalar(a_share + public_value));
                    } else {
                        result.push(ResultValue::Scalar(a_share));
                    }

                    result.push(ResultValue::Scalar(a_mac_share));
                    result.push(ResultValue::Scalar(a_modifier - public_value));
                }

                result
            },
        );

        // Collect the gate results into a series of `AuthenticatedScalarResult<C>`s
        AuthenticatedScalarResult::from_flattened_iterator(gate_results.into_iter())
    }
}

impl<C: CurveGroup> Sum for AuthenticatedScalarResult<C> {
    /// Assumes the iterator is non-empty
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let values = iter.collect_vec();
        let n = values.len();
        let fabric = values[0].fabric();

        // Order the result ids as shares, mac, public modifier
        let mut ids = Vec::with_capacity(n * AUTHENTICATED_SCALAR_RESULT_LEN);
        ids.append(&mut values.iter().map(|v| v.share.id()).collect_vec());
        ids.append(&mut values.iter().map(|v| v.mac.id()).collect_vec());
        ids.append(&mut values.iter().map(|v| v.public_modifier.id).collect_vec());

        // Add the underlying values
        let res = fabric.new_batch_gate_op(ids, AUTHENTICATED_SCALAR_RESULT_LEN, move |args| {
            let chunked = args.map(Scalar::from).chunks(n);
            let mut chunked_iter = chunked.into_iter();
            let new_share = chunked_iter.next().unwrap().sum();
            let new_mac_share = chunked_iter.next().unwrap().sum();
            let new_modifier = chunked_iter.next().unwrap().sum();

            vec![
                ResultValue::Scalar(new_share),
                ResultValue::Scalar(new_mac_share),
                ResultValue::Scalar(new_modifier),
            ]
        });

        let share = res[0].clone().into();
        let mac = res[1].clone().into();
        let public_modifier = res[2].clone();

        Self { share, mac, public_modifier }
    }
}

// === Subtraction === //

impl<C: CurveGroup> Sub<&Scalar<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    /// As in the case for addition, only party 0 subtracts the public value
    /// from their share, but both parties track this in the public modifier
    fn sub(self, rhs: &Scalar<C>) -> Self::Output {
        // Party 1 subtracts a zero value from their share to allocate a new ID for the
        // result and stay in sync with party 0
        let new_share = &self.share - rhs;

        // Both parties add the public value to their modifier, and the MACs do not
        // change when adding a public value
        let new_modifier = &self.public_modifier + rhs;
        AuthenticatedScalarResult {
            share: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Sub, sub, -, Scalar<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&AuthenticatedScalarResult<C>> for &Scalar<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn sub(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        // Party 1 subtracts a zero value from their share to allocate a new ID for the
        // result and stay in sync with party 0
        let new_share = self - &rhs.share;

        // Both parties add the public value to their modifier, and the MACs do not
        // change when adding a public value
        let new_modifier = -self - &rhs.public_modifier;
        AuthenticatedScalarResult {
            share: new_share,
            mac: -&rhs.mac,
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(Scalar<C>, Sub, sub, -, AuthenticatedScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&ScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn sub(self, rhs: &ScalarResult<C>) -> Self::Output {
        let new_share = &self.share - rhs;

        // Both parties add the public value to their modifier, and the MACs do not
        // change when adding a public value
        let new_modifier = &self.public_modifier + rhs;
        AuthenticatedScalarResult {
            share: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Sub, sub, -, ScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&AuthenticatedScalarResult<C>> for &ScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn sub(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        // Party 1 subtracts a zero value from their share to allocate a new ID for the
        // result and stay in sync with party 0
        let new_share = self - &rhs.share;

        // Both parties add the public value to their modifier, and the MACs do not
        // change when adding a public value
        let new_modifier = -self - &rhs.public_modifier;
        AuthenticatedScalarResult {
            share: new_share,
            mac: -&rhs.mac,
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(ScalarResult<C>, Sub, sub, -, AuthenticatedScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&AuthenticatedScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn sub(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        AuthenticatedScalarResult {
            share: &self.share - &rhs.share,
            mac: &self.mac - &rhs.mac,
            public_modifier: self.public_modifier.clone() - rhs.public_modifier.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Sub, sub, -, AuthenticatedScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> AuthenticatedScalarResult<C> {
    /// Add two batches of `AuthenticatedScalarResult`s
    pub fn batch_sub(
        a: &[AuthenticatedScalarResult<C>],
        b: &[AuthenticatedScalarResult<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Cannot add batches of different sizes");

        let n = a.len();
        let fabric = &a[0].fabric();

        let chunk_size = AUTHENTICATED_SCALAR_RESULT_LEN * 2;
        let mut all_ids = Vec::with_capacity(chunk_size * n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.extend(a.ids());
            all_ids.extend(b.ids());
        }

        // Add the underlying values
        let gate_results: Vec<ScalarResult<C>> = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_SCALAR_RESULT_LEN * n, // output_arity
            move |args| {
                let mut result = Vec::with_capacity(AUTHENTICATED_SCALAR_RESULT_LEN * n);
                for mut chunk in &args.chunks(chunk_size) {
                    let a_share: Scalar<C> = chunk.next().unwrap().into();
                    let a_mac_share: Scalar<C> = chunk.next().unwrap().into();
                    let a_modifier: Scalar<C> = chunk.next().unwrap().into();

                    let b_share: Scalar<C> = chunk.next().unwrap().into();
                    let b_mac_share: Scalar<C> = chunk.next().unwrap().into();
                    let b_modifier: Scalar<C> = chunk.next().unwrap().into();

                    result.push(ResultValue::Scalar(a_share - b_share));
                    result.push(ResultValue::Scalar(a_mac_share - b_mac_share));
                    result.push(ResultValue::Scalar(a_modifier - b_modifier));
                }

                result
            },
        );

        // Collect the gate results into a series of `AuthenticatedScalarResult`s
        AuthenticatedScalarResult::from_flattened_iterator(gate_results.into_iter())
    }

    /// Subtract a batch of `ScalarResult`s from a batch of
    /// `AuthenticatedScalarResult`s
    pub fn batch_sub_public(
        a: &[AuthenticatedScalarResult<C>],
        b: &[ScalarResult<C>],
    ) -> Vec<AuthenticatedScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Cannot add batches of different sizes");

        let n = a.len();
        let results_per_value = 3;
        let fabric = a[0].fabric();

        let chunk_size = AUTHENTICATED_SCALAR_RESULT_LEN + 1;
        let mut all_ids = Vec::with_capacity(chunk_size * n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.extend(a.ids());
            all_ids.push(b.id());
        }

        // Add the underlying values
        let party_id = fabric.party_id();
        let gate_results: Vec<ScalarResult<C>> = fabric.new_batch_gate_op(
            all_ids,
            results_per_value * n, // output_arity
            move |args| {
                // Split the args
                let mut result = Vec::with_capacity(results_per_value * n);
                for mut chunk in &args.chunks(chunk_size) {
                    let a_share: Scalar<C> = chunk.next().unwrap().into();
                    let a_mac_share: Scalar<C> = chunk.next().unwrap().into();
                    let a_modifier: Scalar<C> = chunk.next().unwrap().into();

                    let public_value: Scalar<C> = chunk.next().unwrap().into();

                    // Only the first party adds the public value to their share
                    if party_id == PARTY0 {
                        result.push(ResultValue::Scalar(a_share - public_value));
                    } else {
                        result.push(ResultValue::Scalar(a_share));
                    }

                    result.push(ResultValue::Scalar(a_mac_share));
                    result.push(ResultValue::Scalar(a_modifier + public_value));
                }

                result
            },
        );

        // Collect the gate results into a series of `AuthenticatedScalarResult`s
        AuthenticatedScalarResult::from_flattened_iterator(gate_results.into_iter())
    }
}

// === Negation === //

impl<C: CurveGroup> Neg for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn neg(self) -> Self::Output {
        AuthenticatedScalarResult {
            share: -&self.share,
            mac: -&self.mac,
            public_modifier: -&self.public_modifier,
        }
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
        let all_ids = a.iter().flat_map(|v| v.ids()).collect_vec();

        let scalars = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_SCALAR_RESULT_LEN * n, // output_arity
            |args| args.into_iter().map(|arg| ResultValue::Scalar(-Scalar::from(arg))).collect(),
        );

        AuthenticatedScalarResult::from_flattened_iterator(scalars.into_iter())
    }
}

// === Multiplication === //

impl<C: CurveGroup> Mul<&Scalar<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        AuthenticatedScalarResult {
            share: &self.share * rhs,
            mac: &self.mac * rhs,
            public_modifier: &self.public_modifier * rhs,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Mul, mul, *, Scalar<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedScalarResult<C>, Mul, mul, *, Scalar<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&ScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    fn mul(self, rhs: &ScalarResult<C>) -> Self::Output {
        AuthenticatedScalarResult {
            share: &self.share * rhs,
            mac: &self.mac * rhs,
            public_modifier: &self.public_modifier * rhs,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult<C>, Mul, mul, *, ScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedScalarResult<C>, Mul, mul, *, ScalarResult<C>, Output=AuthenticatedScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&AuthenticatedScalarResult<C>> for &AuthenticatedScalarResult<C> {
    type Output = AuthenticatedScalarResult<C>;

    // Use the Beaver trick
    fn mul(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        // Sample a beaver triplet
        let (a, b, c) = self.fabric().next_authenticated_triple();

        // Mask the left and right hand sides
        let masked_lhs = self - &a;
        let masked_rhs = rhs - &b;

        // Open these values to get d = lhs - a, e = rhs - b
        let d = masked_lhs.open();
        let e = masked_rhs.open();

        // Use the same beaver identify as in the `MpcScalarResult<C>` case, but now the
        // public multiplications are applied to the MACs and the public
        // modifiers as well Identity: [x * y] = de + d[b] + e[a] + [c]
        &d * &e + d * b + e * a + c
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
        let (beaver_a, beaver_b, beaver_c) = fabric.next_authenticated_triple_batch(n);

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

        let chunk_size = AUTHENTICATED_SCALAR_RESULT_LEN + 1;
        let mut all_ids = Vec::with_capacity(chunk_size * n);
        for (a, b) in a.iter().zip(b.iter()) {
            all_ids.extend(a.ids());
            all_ids.push(b.id());
        }

        let scalars = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_SCALAR_RESULT_LEN * n, // output_arity
            move |args| {
                let mut result = Vec::with_capacity(AUTHENTICATED_SCALAR_RESULT_LEN * n);
                for mut chunk in &args.map(Scalar::from).chunks(chunk_size) {
                    let a_share = chunk.next().unwrap();
                    let a_mac_share = chunk.next().unwrap();
                    let a_modifier = chunk.next().unwrap();

                    let public_value = chunk.next().unwrap();

                    result.push(ResultValue::Scalar(a_share * public_value));
                    result.push(ResultValue::Scalar(a_mac_share * public_value));
                    result.push(ResultValue::Scalar(a_modifier * public_value));
                }

                result
            },
        );

        AuthenticatedScalarResult::from_flattened_iterator(scalars.into_iter())
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
        let all_ids = a.iter().flat_map(|a| a.ids()).collect_vec();

        let scalars = fabric.new_batch_gate_op(
            all_ids,
            AUTHENTICATED_SCALAR_RESULT_LEN * n, // output_arity
            move |args| {
                let mut result = Vec::with_capacity(AUTHENTICATED_SCALAR_RESULT_LEN * n);
                for (mut a_vals, b_val) in args
                    .map(Scalar::from)
                    .chunks(AUTHENTICATED_SCALAR_RESULT_LEN)
                    .into_iter()
                    .zip(b.into_iter())
                {
                    let a_share = a_vals.next().unwrap();
                    let a_mac_share = a_vals.next().unwrap();
                    let a_modifier = a_vals.next().unwrap();

                    result.push(ResultValue::Scalar(a_share * b_val));
                    result.push(ResultValue::Scalar(a_mac_share * b_val));
                    result.push(ResultValue::Scalar(a_modifier * b_val));
                }

                result
            },
        );

        AuthenticatedScalarResult::from_flattened_iterator(scalars.into_iter())
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
        AuthenticatedPointResult {
            share: self * &rhs.share,
            mac: self * &rhs.mac,
            public_modifier: self * &rhs.public_modifier,
        }
    }
}
impl_commutative!(CurvePoint<C>, Mul, mul, *, AuthenticatedScalarResult<C>, Output=AuthenticatedPointResult<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&AuthenticatedScalarResult<C>> for &CurvePointResult<C> {
    type Output = AuthenticatedPointResult<C>;

    fn mul(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        AuthenticatedPointResult {
            share: self * &rhs.share,
            mac: self * &rhs.mac,
            public_modifier: self * &rhs.public_modifier,
        }
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

        // Take the FFT of the shares and the macs separately
        let shares = x.iter().map(|v| v.share()).collect_vec();
        let macs = x.iter().map(|v| v.mac_share()).collect_vec();
        let modifiers = x.iter().map(|v| v.public_modifier.clone()).collect_vec();

        let (share_fft, mac_fft, modifier_fft) = if is_forward {
            (
                ScalarResult::fft_with_domain::<D>(&shares, domain),
                ScalarResult::fft_with_domain::<D>(&macs, domain),
                ScalarResult::fft_with_domain::<D>(&modifiers, domain),
            )
        } else {
            (
                ScalarResult::ifft_with_domain::<D>(&shares, domain),
                ScalarResult::ifft_with_domain::<D>(&macs, domain),
                ScalarResult::ifft_with_domain::<D>(&modifiers, domain),
            )
        };

        let mut res = Vec::with_capacity(domain.size());
        for (share, mac, modifier) in izip!(share_fft, mac_fft, modifier_fft) {
            res.push(AuthenticatedScalarResult {
                share: MpcScalarResult::new_shared(share),
                mac: MpcScalarResult::new_shared(mac),
                public_modifier: modifier,
            })
        }

        res
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

    use crate::algebra::scalar::Scalar;

    use super::AuthenticatedScalarResult;

    /// Modify the MAC of an `AuthenticatedScalarResult`
    pub fn modify_mac<C: CurveGroup>(val: &mut AuthenticatedScalarResult<C>, new_value: Scalar<C>) {
        val.mac = val.fabric().allocate_scalar(new_value).into()
    }

    /// Modify the underlying secret share of an `AuthenticatedScalarResult`
    pub fn modify_share<C: CurveGroup>(
        val: &mut AuthenticatedScalarResult<C>,
        new_value: Scalar<C>,
    ) {
        val.share = val.fabric().allocate_scalar(new_value).into()
    }

    /// Modify the public modifier of an `AuthenticatedScalarResult` by adding
    /// an offset
    pub fn modify_public_modifier<C: CurveGroup>(
        val: &mut AuthenticatedScalarResult<C>,
        new_value: Scalar<C>,
    ) {
        val.public_modifier = val.fabric().allocate_scalar(new_value)
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
        test_helpers::{execute_mock_mpc, TestCurve},
        PARTY0, PARTY1,
    };

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

    /// Tests subtraction with a constant value outside of the fabric
    #[tokio::test]
    async fn test_sub_constant() {
        let mut rng = thread_rng();
        let value1 = Scalar::random(&mut rng);
        let value2 = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            // Allocate the first value as a shared scalar and the second as a public scalar
            let party0_value = fabric.share_scalar(value1, PARTY0);

            // Subtract the public value from the shared value
            let res1 = &party0_value - value2;
            let res_open1 = res1.open_authenticated().await.unwrap();
            let expected1 = value1 - value2;

            // Subtract the shared value from the public value
            let res2 = value2 - &party0_value;
            let res_open2 = res2.open_authenticated().await.unwrap();
            let expected2 = value2 - value1;

            (res_open1 == expected1, res_open2 == expected2)
        })
        .await;

        assert!(res.0);
        assert!(res.1)
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

        assert_eq!(res.unwrap(), expected_res)
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
