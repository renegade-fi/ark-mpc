//! Defines an unauthenticated shared scalar type which forms the basis of the
//! authenticated scalar type

use std::ops::{Add, Mul, Neg, Sub};

use ark_ec::CurveGroup;
use itertools::Itertools;

use crate::{
    algebra::macros::*,
    algebra::BatchScalarResult,
    algebra::{CurvePoint, CurvePointResult, MpcPointResult},
    fabric::{MpcFabric, ResultValue},
    network::NetworkPayload,
    PARTY0,
};

use super::scalar::{Scalar, ScalarResult};

/// Defines a secret shared type over the `Scalar` field
#[derive(Clone, Debug)]
pub struct MpcScalarResult<C: CurveGroup> {
    /// The underlying value held by the local party
    pub(crate) share: ScalarResult<C>,
}

impl<C: CurveGroup> From<ScalarResult<C>> for MpcScalarResult<C> {
    fn from(share: ScalarResult<C>) -> Self {
        Self { share }
    }
}

/// Defines the result handle type that represents a future result of an
/// `MpcScalar`
impl<C: CurveGroup> MpcScalarResult<C> {
    /// Creates an MPC scalar from a given underlying scalar assumed to be a
    /// secret share
    pub fn new_shared(value: ScalarResult<C>) -> MpcScalarResult<C> {
        value.into()
    }

    /// Get the op-id of the underlying share
    pub fn id(&self) -> usize {
        self.share.id
    }

    /// Borrow the fabric that the result is allocated in
    pub fn fabric(&self) -> &MpcFabric<C> {
        self.share.fabric()
    }

    /// Open the value; both parties send their shares to the counterparty
    pub fn open(&self) -> ScalarResult<C> {
        // Party zero sends first then receives
        let (val0, val1) = if self.fabric().party_id() == PARTY0 {
            let party0_value: ScalarResult<C> =
                self.fabric().new_network_op(vec![self.id()], |args| {
                    let share: Scalar<C> = args[0].to_owned().into();
                    NetworkPayload::Scalar(share)
                });
            let party1_value: ScalarResult<C> = self.fabric().receive_value();

            (party0_value, party1_value)
        } else {
            let party0_value: ScalarResult<C> = self.fabric().receive_value();
            let party1_value: ScalarResult<C> =
                self.fabric().new_network_op(vec![self.id()], |args| {
                    let share = args[0].to_owned().into();
                    NetworkPayload::Scalar(share)
                });

            (party0_value, party1_value)
        };

        // Create the new value by combining the additive shares
        &val0 + &val1
    }

    /// Open a batch of values
    pub fn open_batch(values: &[MpcScalarResult<C>]) -> Vec<ScalarResult<C>> {
        if values.is_empty() {
            return vec![];
        }

        let n = values.len();
        let fabric = &values[0].fabric();
        let my_results = values.iter().map(|v| v.id()).collect_vec();
        let send_shares_fn = |args: Vec<ResultValue<C>>| {
            let shares: Vec<Scalar<C>> = args.into_iter().map(Scalar::from).collect();
            NetworkPayload::ScalarBatch(shares)
        };

        // Party zero sends first then receives
        let (party0_vals, party1_vals) = if values[0].fabric().party_id() == PARTY0 {
            // Send the local shares
            let party0_vals: BatchScalarResult<C> =
                fabric.new_network_op(my_results, send_shares_fn);
            let party1_vals: BatchScalarResult<C> = fabric.receive_value();

            (party0_vals, party1_vals)
        } else {
            let party0_vals: BatchScalarResult<C> = fabric.receive_value();
            let party1_vals: BatchScalarResult<C> =
                fabric.new_network_op(my_results, send_shares_fn);

            (party0_vals, party1_vals)
        };

        // Create the new values by combining the additive shares
        fabric.new_batch_gate_op(vec![party0_vals.id, party1_vals.id], n, move |args| {
            let party0_vals: Vec<Scalar<C>> = args[0].to_owned().into();
            let party1_vals: Vec<Scalar<C>> = args[1].to_owned().into();

            let mut results = Vec::with_capacity(n);
            for i in 0..n {
                results.push(ResultValue::Scalar(party0_vals[i] + party1_vals[i]));
            }

            results
        })
    }

    /// Convert the underlying value to a `Scalar`
    pub fn to_scalar(&self) -> ScalarResult<C> {
        self.share.clone()
    }
}

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl<C: CurveGroup> Add<&Scalar<C>> for &MpcScalarResult<C> {
    type Output = MpcScalarResult<C>;

    // Only party 0 adds the plaintext value as we do not secret share it
    fn add(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        let party_id = self.fabric().party_id();

        self.fabric()
            .new_gate_op(vec![self.id()], move |args| {
                // Cast the args
                let lhs_share: Scalar<C> = args[0].to_owned().into();
                if party_id == PARTY0 {
                    ResultValue::Scalar(lhs_share + rhs)
                } else {
                    ResultValue::Scalar(lhs_share)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult<C>, Add, add, +, Scalar<C>, C: CurveGroup);
impl_commutative!(MpcScalarResult<C>, Add, add, +, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&ScalarResult<C>> for &MpcScalarResult<C> {
    type Output = MpcScalarResult<C>;

    // Only party 0 adds the plaintext value as we do not secret share it
    fn add(self, rhs: &ScalarResult<C>) -> Self::Output {
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id], move |mut args| {
                // Cast the args
                let lhs: Scalar<C> = args.remove(0).into();
                let rhs: Scalar<C> = args.remove(0).into();

                if party_id == PARTY0 {
                    ResultValue::Scalar(lhs + rhs)
                } else {
                    ResultValue::Scalar(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult<C>, Add, add, +, ScalarResult<C>, C: CurveGroup);
impl_commutative!(MpcScalarResult<C>, Add, add, +, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&MpcScalarResult<C>> for &MpcScalarResult<C> {
    type Output = MpcScalarResult<C>;

    fn add(self, rhs: &MpcScalarResult<C>) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |args| {
                // Cast the args
                let lhs: Scalar<C> = args[0].to_owned().into();
                let rhs: Scalar<C> = args[1].to_owned().into();

                ResultValue::Scalar(lhs + rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult<C>, Add, add, +, MpcScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> MpcScalarResult<C> {
    /// Add two batches of `MpcScalarResult`s using a single batched gate
    pub fn batch_add(
        a: &[MpcScalarResult<C>],
        b: &[MpcScalarResult<C>],
    ) -> Vec<MpcScalarResult<C>> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_add: a and b must be the same length"
        );

        let n = a.len();
        let fabric = a[0].fabric();
        let ids = a.iter().chain(b.iter()).map(|v| v.id()).collect_vec();

        let scalars = fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            // Split the args
            let scalars = args.into_iter().map(Scalar::from).collect_vec();
            let (a_res, b_res) = scalars.split_at(n);

            // Add the values
            a_res
                .iter()
                .zip(b_res.iter())
                .map(|(a, b)| ResultValue::Scalar(a + b))
                .collect_vec()
        });

        scalars.into_iter().map(|s| s.into()).collect_vec()
    }

    /// Add a batch of `MpcScalarResult`s to a batch of public `ScalarResult`s
    pub fn batch_add_public(
        a: &[MpcScalarResult<C>],
        b: &[ScalarResult<C>],
    ) -> Vec<MpcScalarResult<C>> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_add_public: a and b must be the same length"
        );

        let n = a.len();
        let fabric = a[0].fabric();
        let ids = a
            .iter()
            .map(|v| v.id())
            .chain(b.iter().map(|v| v.id()))
            .collect_vec();

        let party_id = fabric.party_id();
        let scalars: Vec<ScalarResult<C>> =
            fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
                if party_id == PARTY0 {
                    let mut res: Vec<ResultValue<C>> = Vec::with_capacity(n);

                    for i in 0..n {
                        let lhs: Scalar<C> = args[i].to_owned().into();
                        let rhs: Scalar<C> = args[i + n].to_owned().into();

                        res.push(ResultValue::Scalar(lhs + rhs));
                    }

                    res
                } else {
                    args[..n].to_vec()
                }
            });

        scalars.into_iter().map(|s| s.into()).collect_vec()
    }
}

// === Subtraction === //

impl<C: CurveGroup> Sub<&Scalar<C>> for &MpcScalarResult<C> {
    type Output = MpcScalarResult<C>;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        let party_id = self.fabric().party_id();

        if party_id == PARTY0 {
            &self.share - rhs
        } else {
            // Party 1 must perform an operation to keep the result queues in sync
            &self.share - Scalar::zero()
        }
        .into()
    }
}
impl_borrow_variants!(MpcScalarResult<C>, Sub, sub, -, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&MpcScalarResult<C>> for &Scalar<C> {
    type Output = MpcScalarResult<C>;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &MpcScalarResult<C>) -> Self::Output {
        let party_id = rhs.fabric().party_id();

        if party_id == PARTY0 {
            self - &rhs.share
        } else {
            // Party 1 must perform an operation to keep the result queues in sync
            Scalar::zero() - &rhs.share
        }
        .into()
    }
}

impl<C: CurveGroup> Sub<&ScalarResult<C>> for &MpcScalarResult<C> {
    type Output = MpcScalarResult<C>;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &ScalarResult<C>) -> Self::Output {
        let party_id = self.fabric().party_id();

        if party_id == PARTY0 {
            &self.share - rhs
        } else {
            // Party 1 must perform an operation to keep the result queues in sync
            self.share.clone() + Scalar::zero()
        }
        .into()
    }
}
impl_borrow_variants!(MpcScalarResult<C>, Sub, sub, -, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&MpcScalarResult<C>> for &ScalarResult<C> {
    type Output = MpcScalarResult<C>;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &MpcScalarResult<C>) -> Self::Output {
        let party_id = rhs.fabric().party_id();

        if party_id == PARTY0 {
            self - &rhs.share
        } else {
            // Party 1 must perform an operation to keep the result queues in sync
            Scalar::zero() - rhs.share.clone()
        }
        .into()
    }
}
impl_borrow_variants!(ScalarResult<C>, Sub, sub, -, MpcScalarResult<C>, Output=MpcScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&MpcScalarResult<C>> for &MpcScalarResult<C> {
    type Output = MpcScalarResult<C>;

    fn sub(self, rhs: &MpcScalarResult<C>) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |args| {
                // Cast the args
                let lhs: Scalar<C> = args[0].to_owned().into();
                let rhs: Scalar<C> = args[1].to_owned().into();

                ResultValue::Scalar(lhs - rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult<C>, Sub, sub, -, MpcScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> MpcScalarResult<C> {
    /// Subtract two batches of `MpcScalarResult`s using a single batched gate
    pub fn batch_sub(
        a: &[MpcScalarResult<C>],
        b: &[MpcScalarResult<C>],
    ) -> Vec<MpcScalarResult<C>> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_sub: a and b must be the same length"
        );

        let n = a.len();
        let fabric = a[0].fabric();
        let ids = a
            .iter()
            .map(|v| v.id())
            .chain(b.iter().map(|v| v.id()))
            .collect_vec();

        let scalars: Vec<ScalarResult<C>> =
            fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
                // Split the args
                let scalars = args.into_iter().map(Scalar::from).collect_vec();
                let (a_res, b_res) = scalars.split_at(n);

                // Add the values
                a_res
                    .iter()
                    .zip(b_res.iter())
                    .map(|(a, b)| ResultValue::Scalar(a - b))
                    .collect_vec()
            });

        scalars.into_iter().map(|s| s.into()).collect_vec()
    }

    /// Subtract a batch of `MpcScalarResult`s from a batch of public
    /// `ScalarResult`s
    pub fn batch_sub_public(
        a: &[MpcScalarResult<C>],
        b: &[ScalarResult<C>],
    ) -> Vec<MpcScalarResult<C>> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_sub_public: a and b must be the same length"
        );

        let n = a.len();
        let fabric = a[0].fabric();
        let ids = a
            .iter()
            .map(|v| v.id())
            .chain(b.iter().map(|v| v.id()))
            .collect_vec();

        let party_id = fabric.party_id();
        let scalars = fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            if party_id == PARTY0 {
                let mut res: Vec<ResultValue<C>> = Vec::with_capacity(n);

                for i in 0..n {
                    let lhs: Scalar<C> = args[i].to_owned().into();
                    let rhs: Scalar<C> = args[i + n].to_owned().into();

                    res.push(ResultValue::Scalar(lhs - rhs));
                }

                res
            } else {
                args[..n].to_vec()
            }
        });

        scalars.into_iter().map(|s| s.into()).collect_vec()
    }
}

// === Negation === //

impl<C: CurveGroup> Neg for &MpcScalarResult<C> {
    type Output = MpcScalarResult<C>;

    fn neg(self) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id()], |args| {
                // Cast the args
                let lhs: Scalar<C> = args[0].to_owned().into();
                ResultValue::Scalar(-lhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult<C>, Neg, neg, -, C: CurveGroup);

impl<C: CurveGroup> MpcScalarResult<C> {
    /// Negate a batch of `MpcScalarResult<C>`s using a single batched gate
    pub fn batch_neg(values: &[MpcScalarResult<C>]) -> Vec<MpcScalarResult<C>> {
        if values.is_empty() {
            return vec![];
        }

        let n = values.len();
        let fabric = values[0].fabric();
        let ids = values.iter().map(|v| v.id()).collect_vec();

        let scalars = fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            // Split the args
            let scalars = args.into_iter().map(Scalar::from).collect_vec();

            // Add the values
            scalars
                .iter()
                .map(|a| ResultValue::Scalar(-a))
                .collect_vec()
        });

        scalars.into_iter().map(|s| s.into()).collect_vec()
    }
}

// === Multiplication === //

impl<C: CurveGroup> Mul<&Scalar<C>> for &MpcScalarResult<C> {
    type Output = MpcScalarResult<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        self.fabric()
            .new_gate_op(vec![self.id()], move |args| {
                // Cast the args
                let lhs: Scalar<C> = args[0].to_owned().into();
                ResultValue::Scalar(lhs * rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
impl_commutative!(MpcScalarResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&ScalarResult<C>> for &MpcScalarResult<C> {
    type Output = MpcScalarResult<C>;

    fn mul(self, rhs: &ScalarResult<C>) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], move |mut args| {
                // Cast the args
                let lhs: Scalar<C> = args.remove(0).into();
                let rhs: Scalar<C> = args.remove(0).into();

                ResultValue::Scalar(lhs * rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);
impl_commutative!(MpcScalarResult<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);

/// Use the beaver trick if both values are shared
impl<C: CurveGroup> Mul<&MpcScalarResult<C>> for &MpcScalarResult<C> {
    type Output = MpcScalarResult<C>;

    fn mul(self, rhs: &MpcScalarResult<C>) -> Self::Output {
        // Sample a beaver triplet
        let (a, b, c) = self.fabric().next_beaver_triple();

        // Open the values d = [lhs - a] and e = [rhs - b]
        let masked_lhs = self - &a;
        let masked_rhs = rhs - &b;

        let d_open = masked_lhs.open();
        let e_open = masked_rhs.open();

        // Identity: [x * y] = de + d[b] + e[a] + [c]
        &d_open * &b + &e_open * &a + c + &d_open * &e_open
    }
}
impl_borrow_variants!(MpcScalarResult<C>, Mul, mul, *, MpcScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> MpcScalarResult<C> {
    /// Multiply a batch of `MpcScalarResult`s over a single network op
    pub fn batch_mul(
        a: &[MpcScalarResult<C>],
        b: &[MpcScalarResult<C>],
    ) -> Vec<MpcScalarResult<C>> {
        let n = a.len();
        assert_eq!(
            a.len(),
            b.len(),
            "batch_mul: a and b must be the same length"
        );

        // Sample a beaver triplet for each multiplication
        let fabric = &a[0].fabric();
        let (beaver_a, beaver_b, beaver_c) = fabric.next_beaver_triple_batch(n);

        // Open the values d = [lhs - a] and e = [rhs - b]
        let masked_lhs = MpcScalarResult::batch_sub(a, &beaver_a);
        let masked_rhs = MpcScalarResult::batch_sub(b, &beaver_b);

        let all_masks = [masked_lhs, masked_rhs].concat();
        let opened_values = MpcScalarResult::open_batch(&all_masks);
        let (d_open, e_open) = opened_values.split_at(n);

        // Identity: [x * y] = de + d[b] + e[a] + [c]
        let de = ScalarResult::batch_mul(d_open, e_open);
        let db = MpcScalarResult::batch_mul_public(&beaver_b, d_open);
        let ea = MpcScalarResult::batch_mul_public(&beaver_a, e_open);

        // Add the terms
        let de_plus_db = MpcScalarResult::batch_add_public(&db, &de);
        let ea_plus_c = MpcScalarResult::batch_add(&ea, &beaver_c);
        MpcScalarResult::batch_add(&de_plus_db, &ea_plus_c)
    }

    /// Multiply a batch of `MpcScalarResult`s by a batch of public
    /// `ScalarResult`s
    pub fn batch_mul_public(
        a: &[MpcScalarResult<C>],
        b: &[ScalarResult<C>],
    ) -> Vec<MpcScalarResult<C>> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_mul_public: a and b must be the same length"
        );

        let n = a.len();
        let fabric = a[0].fabric();
        let ids = a
            .iter()
            .map(|v| v.id())
            .chain(b.iter().map(|v| v.id))
            .collect_vec();

        let scalars: Vec<ScalarResult<C>> =
            fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
                let mut res: Vec<ResultValue<C>> = Vec::with_capacity(n);
                for i in 0..n {
                    let lhs: Scalar<C> = args[i].to_owned().into();
                    let rhs: Scalar<C> = args[i + n].to_owned().into();

                    res.push(ResultValue::Scalar(lhs * rhs));
                }

                res
            });

        scalars.into_iter().map(|s| s.into()).collect_vec()
    }
}

// === Curve Scalar Multiplication === //

impl<C: CurveGroup> Mul<&MpcScalarResult<C>> for &CurvePoint<C> {
    type Output = MpcPointResult<C>;

    fn mul(self, rhs: &MpcScalarResult<C>) -> Self::Output {
        let self_owned = *self;
        rhs.fabric()
            .new_gate_op(vec![rhs.id()], move |mut args| {
                let rhs: Scalar<C> = args.remove(0).into();

                ResultValue::Point(self_owned * rhs)
            })
            .into()
    }
}
impl_commutative!(CurvePoint<C>, Mul, mul, *, MpcScalarResult<C>, Output=MpcPointResult<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&MpcScalarResult<C>> for &CurvePointResult<C> {
    type Output = MpcPointResult<C>;

    fn mul(self, rhs: &MpcScalarResult<C>) -> Self::Output {
        self.fabric
            .new_gate_op(vec![self.id(), rhs.id()], |mut args| {
                let lhs: CurvePoint<C> = args.remove(0).into();
                let rhs: Scalar<C> = args.remove(0).into();

                ResultValue::Point(lhs * rhs)
            })
            .into()
    }
}
impl_borrow_variants!(CurvePointResult<C>, Mul, mul, *, MpcScalarResult<C>, Output=MpcPointResult<C>, C: CurveGroup);
impl_commutative!(CurvePointResult<C>, Mul, mul, *, MpcScalarResult<C>, Output=MpcPointResult<C>, C: CurveGroup);

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use crate::{algebra::scalar::Scalar, test_helpers::execute_mock_mpc, PARTY0};

    /// Test subtraction with a non-commutative pair of types
    #[tokio::test]
    async fn test_sub() {
        let mut rng = thread_rng();
        let value1 = Scalar::random(&mut rng);
        let value2 = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(|fabric| async move {
            // Allocate the first value as a shared scalar and the second as a public scalar
            let party0_value = fabric.share_scalar(value1, PARTY0).mpc_share();
            let public_value = fabric.allocate_scalar(value2);

            // Subtract the public value from the shared value
            let res1 = &party0_value - &public_value;
            let res_open1 = res1.open().await;
            let expected1 = value1 - value2;

            // Subtract the shared value from the public value
            let res2 = &public_value - &party0_value;
            let res_open2 = res2.open().await;
            let expected2 = value2 - value1;

            (res_open1 == expected1, res_open2 == expected2)
        })
        .await;

        assert!(res.0);
        assert!(res.1)
    }
}
