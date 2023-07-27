//! Defines the authenticated (malicious secure) variant of the MPC scalar type

use std::{
    fmt::Debug,
    iter::Sum,
    ops::{Add, Mul, Neg, Sub},
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Future, FutureExt};
use itertools::{izip, Itertools};

use crate::{
    commitment::{PedersenCommitment, PedersenCommitmentResult},
    error::MpcError,
    fabric::{MpcFabric, ResultId, ResultValue},
    PARTY0,
};

use super::{
    authenticated_stark_point::AuthenticatedStarkPointResult,
    macros::{impl_borrow_variants, impl_commutative},
    mpc_scalar::MpcScalarResult,
    scalar::{Scalar, ScalarResult},
    stark_curve::{StarkPoint, StarkPointResult},
};

/// A maliciously secure wrapper around an `MpcScalarResult`, includes a MAC as per the
/// SPDZ protocol: https://eprint.iacr.org/2011/535.pdf
/// that ensures security against a malicious adversary
#[derive(Clone)]
pub struct AuthenticatedScalarResult {
    /// The secret shares of the underlying value
    pub(crate) share: MpcScalarResult,
    /// The SPDZ style, unconditionally secure MAC of the value
    ///
    /// If the value is `x`, parties hold secret shares of the value
    /// \delta * x for the global MAC key `\delta`. The parties individually
    /// hold secret shares of this MAC key [\delta], so we can very naturally
    /// extend the secret share arithmetic of the underlying `MpcScalarResult` to
    /// the MAC updates as well
    pub(crate) mac: MpcScalarResult,
    /// The public modifier tracks additions and subtractions of public values to the
    /// underlying value. This is necessary because in the case of a public addition, only the first
    /// party adds the public value to their share, so the second party must track this up
    /// until the point that the value is opened and the MAC is checked
    pub(crate) public_modifier: ScalarResult,
}

impl Debug for AuthenticatedScalarResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedScalarResult")
            .field("value", &self.share.id())
            .field("mac", &self.mac.id())
            .field("public_modifier", &self.public_modifier.id)
            .finish()
    }
}

impl AuthenticatedScalarResult {
    /// Create a new result from the given shared value
    pub fn new_shared(value: ScalarResult) -> Self {
        // Create an `MpcScalarResult` to represent the fact that this is a shared value
        let fabric = value.fabric.clone();

        let mpc_value = MpcScalarResult::new_shared(value);
        let mac = fabric.borrow_mac_key() * mpc_value.clone();

        // Allocate a zero for the public modifier
        let public_modifier = fabric.zero();

        Self {
            share: mpc_value,
            mac,
            public_modifier,
        }
    }

    /// Get the raw share as an `MpcScalarResult`
    #[cfg(feature = "test_helpers")]
    pub fn mpc_share(&self) -> MpcScalarResult {
        self.share.clone()
    }

    /// Get the raw share as a `ScalarResult`
    pub fn share(&self) -> ScalarResult {
        self.share.to_scalar()
    }

    /// Get a reference to the underlying MPC fabric
    pub fn fabric(&self) -> &MpcFabric {
        self.share.fabric()
    }

    /// Get the ids of the results that must be awaited
    /// before the value is ready
    pub fn ids(&self) -> Vec<ResultId> {
        vec![self.share.id(), self.mac.id(), self.public_modifier.id]
    }

    /// Open the value without checking its MAC
    pub fn open(&self) -> ScalarResult {
        self.share.open()
    }

    /// Open a batch of values without checking their MACs
    pub fn open_batch(values: &[Self]) -> Vec<ScalarResult> {
        MpcScalarResult::open_batch(&values.iter().map(|val| val.share.clone()).collect_vec())
    }

    /// Check the commitment to a MAC check and that the MAC checks sum to zero
    pub fn verify_mac_check(
        my_mac_share: Scalar,
        peer_mac_share: Scalar,
        peer_mac_commitment: StarkPoint,
        peer_commitment_blinder: Scalar,
    ) -> bool {
        let their_comm = PedersenCommitment {
            value: peer_mac_share,
            blinder: peer_commitment_blinder,
            commitment: peer_mac_commitment,
        };

        // Verify that the commitment to the MAC check opens correctly
        if !their_comm.verify() {
            return false;
        }

        // Sum of the commitments should be zero
        if peer_mac_share + my_mac_share != Scalar::from(0) {
            return false;
        }

        true
    }

    /// Open the value and check its MAC
    ///
    /// This follows the protocol detailed in:
    ///     https://securecomputation.org/docs/pragmaticmpc.pdf
    /// Section 6.6.2
    pub fn open_authenticated(&self) -> AuthenticatedScalarOpenResult {
        // Both parties open the underlying value
        let recovered_value = self.share.open();

        // Add a gate to compute the MAC check value: `key_share * opened_value - mac_share`
        let mac_check_value: ScalarResult = self.fabric().new_gate_op(
            vec![
                self.fabric().borrow_mac_key().id(),
                recovered_value.id,
                self.public_modifier.id,
                self.mac.id(),
            ],
            move |mut args| {
                let mac_key_share: Scalar = args.remove(0).into();
                let value: Scalar = args.remove(0).into();
                let modifier: Scalar = args.remove(0).into();
                let mac_share: Scalar = args.remove(0).into();

                ResultValue::Scalar(mac_key_share * (value + modifier) - mac_share)
            },
        );

        // Compute a commitment to this value and share it with the peer
        let my_comm = PedersenCommitmentResult::commit(mac_check_value);
        let peer_commit = self.fabric().exchange_value(my_comm.commitment);

        // Once the parties have exchanged their commitments, they can open them, they have already exchanged
        // the underlying values and their commitments so all that is left is the blinder
        let peer_mac_check = self.fabric().exchange_value(my_comm.value.clone());

        let blinder_result: ScalarResult = self.fabric().allocate_scalar(my_comm.blinder);
        let peer_blinder = self.fabric().exchange_value(blinder_result);

        // Check the commitment and the MAC result
        let commitment_check: ScalarResult = self.fabric().new_gate_op(
            vec![
                my_comm.value.id,
                peer_mac_check.id,
                peer_blinder.id,
                peer_commit.id,
            ],
            |mut args| {
                let my_comm_value: Scalar = args.remove(0).into();
                let peer_value: Scalar = args.remove(0).into();
                let blinder: Scalar = args.remove(0).into();
                let commitment: StarkPoint = args.remove(0).into();

                // Build a commitment from the gate inputs
                ResultValue::Scalar(Scalar::from(Self::verify_mac_check(
                    my_comm_value,
                    peer_value,
                    commitment,
                    blinder,
                )))
            },
        );

        AuthenticatedScalarOpenResult {
            value: recovered_value,
            mac_check: commitment_check,
        }
    }

    /// Open a batch of values and check their MACs
    pub fn open_authenticated_batch(values: &[Self]) -> Vec<AuthenticatedScalarOpenResult> {
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

        let mac_checks: Vec<ScalarResult> =
            fabric.new_batch_gate_op(mac_check_deps, n /* output_arity */, move |mut args| {
                let mac_key_share: Scalar = args.remove(0).into();
                let mut check_result = Vec::with_capacity(n);

                for _ in 0..n {
                    let value: Scalar = args.remove(0).into();
                    let modifier: Scalar = args.remove(0).into();
                    let mac_share: Scalar = args.remove(0).into();

                    check_result.push(mac_key_share * (value + modifier) - mac_share);
                }

                check_result.into_iter().map(ResultValue::Scalar).collect()
            });

        // --- Commit to MAC Checks --- //

        let my_comms = mac_checks
            .iter()
            .cloned()
            .map(PedersenCommitmentResult::commit)
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

        let commitment_checks: Vec<ScalarResult> = fabric.new_batch_gate_op(
            mac_check_gate_deps,
            n, /* output_arity */
            move |mut args| {
                let my_comms: Vec<Scalar> = args.drain(..n).map(|comm| comm.into()).collect();
                let peer_mac_checks: Vec<Scalar> = args.remove(0).into();
                let peer_blinders: Vec<Scalar> = args.remove(0).into();
                let peer_comms: Vec<StarkPoint> = args.remove(0).into();

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

        values_open
            .into_iter()
            .zip(commitment_checks.into_iter())
            .map(|(value, check)| AuthenticatedScalarOpenResult {
                value,
                mac_check: check,
            })
            .collect_vec()
    }
}

/// The value that results from opening an `AuthenticatedScalarResult` and checking its
/// MAC. This encapsulates both the underlying value and the result of the MAC check
#[derive(Clone)]
pub struct AuthenticatedScalarOpenResult {
    /// The underlying value
    pub value: ScalarResult,
    /// The result of the MAC check
    pub mac_check: ScalarResult,
}

impl Future for AuthenticatedScalarOpenResult {
    type Output = Result<Scalar, MpcError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Await both of the underlying values
        let value = futures::ready!(self.as_mut().value.poll_unpin(cx));
        let mac_check = futures::ready!(self.as_mut().mac_check.poll_unpin(cx));

        if mac_check == Scalar::from(1) {
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

impl Add<&Scalar> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn add(self, rhs: &Scalar) -> Self::Output {
        let new_share = if self.fabric().party_id() == PARTY0 {
            &self.share + rhs
        } else {
            &self.share + Scalar::from(0)
        };

        // Both parties add the public value to their modifier, and the MACs do not change
        // when adding a public value
        let new_modifier = &self.public_modifier - rhs;
        AuthenticatedScalarResult {
            share: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Add, add, +, Scalar, Output=AuthenticatedScalarResult);
impl_commutative!(AuthenticatedScalarResult, Add, add, +, Scalar, Output=AuthenticatedScalarResult);

impl Add<&ScalarResult> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn add(self, rhs: &ScalarResult) -> Self::Output {
        // As above, only party 0 adds the public value to their share, but both parties
        // track this with the modifier
        //
        // Party 1 adds a zero value to their share to allocate a new ID for the result
        let new_share = if self.fabric().party_id() == PARTY0 {
            &self.share + rhs
        } else {
            &self.share + Scalar::from(0)
        };

        let new_modifier = &self.public_modifier - rhs;
        AuthenticatedScalarResult {
            share: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Add, add, +, ScalarResult, Output=AuthenticatedScalarResult);
impl_commutative!(AuthenticatedScalarResult, Add, add, +, ScalarResult, Output=AuthenticatedScalarResult);

impl Add<&AuthenticatedScalarResult> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn add(self, rhs: &AuthenticatedScalarResult) -> Self::Output {
        AuthenticatedScalarResult {
            share: &self.share + &rhs.share,
            mac: &self.mac + &rhs.mac,
            public_modifier: self.public_modifier.clone() + rhs.public_modifier.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Add, add, +, AuthenticatedScalarResult, Output=AuthenticatedScalarResult);

impl AuthenticatedScalarResult {
    /// Add two batches of `AuthenticatedScalarResult`s
    pub fn batch_add(
        a: Vec<AuthenticatedScalarResult>,
        b: Vec<AuthenticatedScalarResult>,
    ) -> Vec<AuthenticatedScalarResult> {
        assert_eq!(a.len(), b.len(), "Cannot add batches of different sizes");

        let n = a.len();
        let results_per_value = 3;
        let fabric = &a[0].fabric();
        let all_ids = a.iter().chain(b.iter()).flat_map(|v| v.ids()).collect_vec();

        // Add the underlying values
        let gate_results: Vec<ScalarResult> = fabric.new_batch_gate_op(
            all_ids,
            results_per_value * n, /* output_arity */
            move |mut args| {
                let arg_len = args.len();
                let a_vals = args.drain(..arg_len / 2).collect_vec();
                let b_vals = args;

                let mut result = Vec::with_capacity(results_per_value * n);
                for (mut a_vals, mut b_vals) in a_vals
                    .into_iter()
                    .chunks(results_per_value)
                    .into_iter()
                    .zip(b_vals.into_iter().chunks(results_per_value).into_iter())
                {
                    let a_share: Scalar = a_vals.next().unwrap().into();
                    let a_mac_share: Scalar = a_vals.next().unwrap().into();
                    let a_modifier: Scalar = a_vals.next().unwrap().into();

                    let b_share: Scalar = b_vals.next().unwrap().into();
                    let b_mac_share: Scalar = b_vals.next().unwrap().into();
                    let b_modifier: Scalar = b_vals.next().unwrap().into();

                    result.push(ResultValue::Scalar(a_share + b_share));
                    result.push(ResultValue::Scalar(a_mac_share + b_mac_share));
                    result.push(ResultValue::Scalar(a_modifier + b_modifier));
                }

                result
            },
        );

        // Collect the gate results into a series of `AuthenticatedScalarResult`s
        gate_results
            .into_iter()
            .chunks(results_per_value)
            .into_iter()
            .map(|mut chunk| AuthenticatedScalarResult {
                share: chunk.next().unwrap().into(),
                mac: chunk.next().unwrap().into(),
                public_modifier: chunk.next().unwrap(),
            })
            .collect_vec()
    }
}

/// TODO: Maybe use a batch gate for this; performance depends on whether materializing the
/// iterator is burdensome
impl Sum for AuthenticatedScalarResult {
    /// Assumes the iterator is non-empty
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        let seed = iter.next().expect("Cannot sum empty iterator");
        iter.fold(seed, |acc, val| acc + &val)
    }
}

// === Subtraction === //

impl Sub<&Scalar> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    /// As in the case for addition, only party 0 subtracts the public value from their share,
    /// but both parties track this in the public modifier
    fn sub(self, rhs: &Scalar) -> Self::Output {
        // Party 1 subtracts a zero value from their share to allocate a new ID for the result
        // and stay in sync with party 0
        let new_share = if self.fabric().party_id() == PARTY0 {
            &self.share - rhs
        } else {
            &self.share - Scalar::from(0)
        };

        // Both parties add the public value to their modifier, and the MACs do not change
        // when adding a public value
        let new_modifier = &self.public_modifier + rhs;
        AuthenticatedScalarResult {
            share: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Sub, sub, -, Scalar, Output=AuthenticatedScalarResult);
impl_commutative!(AuthenticatedScalarResult, Sub, sub, -, Scalar, Output=AuthenticatedScalarResult);

impl Sub<&ScalarResult> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn sub(self, rhs: &ScalarResult) -> Self::Output {
        // Party 1 subtracts a zero value from their share to allocate a new ID for the result
        // and stay in sync with party 0
        let new_share = if self.fabric().party_id() == PARTY0 {
            &self.share - rhs
        } else {
            &self.share - Scalar::from(0)
        };

        // Both parties add the public value to their modifier, and the MACs do not change
        // when adding a public value
        let new_modifier = &self.public_modifier + rhs;
        AuthenticatedScalarResult {
            share: new_share,
            mac: self.mac.clone(),
            public_modifier: new_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Sub, sub, -, ScalarResult, Output=AuthenticatedScalarResult);
impl_commutative!(AuthenticatedScalarResult, Sub, sub, -, ScalarResult, Output=AuthenticatedScalarResult);

impl Sub<&AuthenticatedScalarResult> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn sub(self, rhs: &AuthenticatedScalarResult) -> Self::Output {
        AuthenticatedScalarResult {
            share: &self.share - &rhs.share,
            mac: &self.mac - &rhs.mac,
            public_modifier: self.public_modifier.clone(),
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Sub, sub, -, AuthenticatedScalarResult, Output=AuthenticatedScalarResult);

// === Negation === //

impl Neg for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn neg(self) -> Self::Output {
        AuthenticatedScalarResult {
            share: -&self.share,
            mac: -&self.mac,
            public_modifier: -&self.public_modifier,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Neg, neg, -);

// === Multiplication === //

impl Mul<&Scalar> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        AuthenticatedScalarResult {
            share: &self.share * rhs,
            mac: &self.mac * rhs,
            public_modifier: &self.public_modifier * rhs,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Mul, mul, *, Scalar, Output=AuthenticatedScalarResult);
impl_commutative!(AuthenticatedScalarResult, Mul, mul, *, Scalar, Output=AuthenticatedScalarResult);

impl Mul<&ScalarResult> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    fn mul(self, rhs: &ScalarResult) -> Self::Output {
        AuthenticatedScalarResult {
            share: &self.share * rhs,
            mac: &self.mac * rhs,
            public_modifier: &self.public_modifier * rhs,
        }
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Mul, mul, *, ScalarResult, Output=AuthenticatedScalarResult);
impl_commutative!(AuthenticatedScalarResult, Mul, mul, *, ScalarResult, Output=AuthenticatedScalarResult);

impl Mul<&AuthenticatedScalarResult> for &AuthenticatedScalarResult {
    type Output = AuthenticatedScalarResult;

    // Use the Beaver trick
    fn mul(self, rhs: &AuthenticatedScalarResult) -> Self::Output {
        // Sample a beaver triplet
        let (a, b, c) = self.fabric().next_authenticated_beaver_triple();

        // Mask the left and right hand sides
        let masked_lhs = self - &a;
        let masked_rhs = rhs - &b;

        // Open these values to get d = lhs - a, e = rhs - b
        let d = masked_lhs.open();
        let e = masked_rhs.open();

        // Use the same beaver identify as in the `MpcScalarResult` case, but now the public
        // multiplications are applied to the MACs and the public modifiers as well
        // Identity: [x * y] = de + d[b] + e[a] + [c]
        &d * &e + d * b + e * a + c
    }
}
impl_borrow_variants!(AuthenticatedScalarResult, Mul, mul, *, AuthenticatedScalarResult, Output=AuthenticatedScalarResult);

impl AuthenticatedScalarResult {
    /// Multiply a batch of values using the Beaver trick
    ///
    /// TODO: Optimize this to use a network message
    pub fn batch_mul(
        a: &[AuthenticatedScalarResult],
        b: &[AuthenticatedScalarResult],
    ) -> Vec<AuthenticatedScalarResult> {
        a.iter().zip(b.iter()).map(|(a, b)| a * b).collect()
    }
}

// === Curve Scalar Multiplication === //

impl Mul<&AuthenticatedScalarResult> for &StarkPoint {
    type Output = AuthenticatedStarkPointResult;

    fn mul(self, rhs: &AuthenticatedScalarResult) -> Self::Output {
        AuthenticatedStarkPointResult {
            share: self * &rhs.share,
            mac: self * &rhs.mac,
            public_modifier: self * &rhs.public_modifier,
        }
    }
}
impl_commutative!(StarkPoint, Mul, mul, *, AuthenticatedScalarResult, Output=AuthenticatedStarkPointResult);

impl Mul<&AuthenticatedScalarResult> for &StarkPointResult {
    type Output = AuthenticatedStarkPointResult;

    fn mul(self, rhs: &AuthenticatedScalarResult) -> Self::Output {
        AuthenticatedStarkPointResult {
            share: self * &rhs.share,
            mac: self * &rhs.mac,
            public_modifier: self * &rhs.public_modifier,
        }
    }
}
impl_borrow_variants!(StarkPointResult, Mul, mul, *, AuthenticatedScalarResult, Output=AuthenticatedStarkPointResult);
impl_commutative!(StarkPointResult, Mul, mul, *, AuthenticatedScalarResult, Output=AuthenticatedStarkPointResult);

// ----------------
// | Test Helpers |
// ----------------

/// Contains unsafe helpers for modifying values, methods in this module should *only* be used
/// for testing
#[cfg(feature = "test_helpers")]
pub mod test_helpers {
    use crate::algebra::scalar::Scalar;

    use super::AuthenticatedScalarResult;

    /// Modify the MAC of an `AuthenticatedScalarResult`
    pub fn modify_mac(val: &mut AuthenticatedScalarResult, new_value: Scalar) {
        val.mac = val.fabric().allocate_scalar(new_value).into()
    }

    /// Modify the underlying secret share of an `AuthenticatedScalarResult`
    pub fn modify_share(val: &mut AuthenticatedScalarResult, new_value: Scalar) {
        val.share = val.fabric().allocate_scalar(new_value).into()
    }

    /// Modify the public modifier of an `AuthenticatedScalarResult` by adding an offset
    pub fn modify_public_modifier(val: &mut AuthenticatedScalarResult, new_value: Scalar) {
        val.public_modifier = val.fabric().allocate_scalar(new_value)
    }
}
