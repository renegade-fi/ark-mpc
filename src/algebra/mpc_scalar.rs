//! Defines an unauthenticated shared scalar type which forms the basis of the
//! authenticated scalar type

use std::ops::{Add, Mul, Neg, Sub};

use itertools::Itertools;

use crate::{
    algebra::scalar::BatchScalarResult,
    fabric::{MpcFabric, ResultHandle, ResultValue},
    network::NetworkPayload,
    PARTY0,
};

use super::{
    macros::{impl_borrow_variants, impl_commutative},
    mpc_stark_point::MpcStarkPointResult,
    scalar::{Scalar, ScalarResult},
    stark_curve::{StarkPoint, StarkPointResult},
};

/// Defines a secret shared type over the `Scalar` field
#[derive(Clone, Debug)]
pub struct MpcScalarResult {
    /// The underlying value held by the local party
    pub(crate) share: ScalarResult,
}

impl From<ScalarResult> for MpcScalarResult {
    fn from(share: ScalarResult) -> Self {
        Self { share }
    }
}

/// Defines the result handle type that represents a future result of an `MpcScalarResult`
impl MpcScalarResult {
    /// Creates an MPC scalar from a given underlying scalar assumed to be a secret share
    pub fn new_shared(value: ScalarResult) -> MpcScalarResult {
        value.into()
    }

    /// Get the op-id of the underlying share
    pub fn id(&self) -> usize {
        self.share.id
    }

    /// Borrow the fabric that the result is allocated in
    pub fn fabric(&self) -> &MpcFabric {
        self.share.fabric()
    }

    /// Open the value; both parties send their shares to the counterparty
    pub fn open(&self) -> ResultHandle<Scalar> {
        // Party zero sends first then receives
        let (val0, val1) = if self.fabric().party_id() == PARTY0 {
            let party0_value: ResultHandle<Scalar> =
                self.fabric().new_network_op(vec![self.id()], |args| {
                    let share: Scalar = args[0].to_owned().into();
                    NetworkPayload::Scalar(share)
                });
            let party1_value: ResultHandle<Scalar> = self.fabric().receive_value();

            (party0_value, party1_value)
        } else {
            let party0_value: ResultHandle<Scalar> = self.fabric().receive_value();
            let party1_value: ResultHandle<Scalar> =
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
    pub fn open_batch(values: &[MpcScalarResult]) -> Vec<ScalarResult> {
        if values.is_empty() {
            return vec![];
        }

        let n = values.len();
        let fabric = &values[0].fabric();
        let my_results = values.iter().map(|v| v.id()).collect_vec();
        let send_shares_fn = |args: Vec<ResultValue>| {
            let shares: Vec<Scalar> = args.into_iter().map(Scalar::from).collect();
            NetworkPayload::ScalarBatch(shares)
        };

        // Party zero sends first then receives
        let (party0_vals, party1_vals) = if values[0].fabric().party_id() == PARTY0 {
            // Send the local shares
            let party0_vals: BatchScalarResult = fabric.new_network_op(my_results, send_shares_fn);
            let party1_vals: BatchScalarResult = fabric.receive_value();

            (party0_vals, party1_vals)
        } else {
            let party0_vals: BatchScalarResult = fabric.receive_value();
            let party1_vals: BatchScalarResult = fabric.new_network_op(my_results, send_shares_fn);

            (party0_vals, party1_vals)
        };

        // Create the new values by combining the additive shares
        fabric.new_batch_gate_op(vec![party0_vals.id, party1_vals.id], n, move |args| {
            let party0_vals: Vec<Scalar> = args[0].to_owned().into();
            let party1_vals: Vec<Scalar> = args[1].to_owned().into();

            let mut results = Vec::with_capacity(n);
            for i in 0..n {
                results.push(ResultValue::Scalar(party0_vals[i] + party1_vals[i]));
            }

            results
        })
    }

    /// Convert the underlying value to a `Scalar`
    pub fn to_scalar(&self) -> ScalarResult {
        self.share.clone()
    }
}

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl Add<&Scalar> for &MpcScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 adds the plaintext value as we do not secret share it
    fn add(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        let party_id = self.fabric().party_id();

        self.fabric()
            .new_gate_op(vec![self.id()], move |args| {
                // Cast the args
                let lhs_share: Scalar = args[0].to_owned().into();
                if party_id == PARTY0 {
                    ResultValue::Scalar(lhs_share + rhs)
                } else {
                    ResultValue::Scalar(lhs_share)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult, Add, add, +, Scalar);
impl_commutative!(MpcScalarResult, Add, add, +, Scalar);

impl Add<&ScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 adds the plaintext value as we do not secret share it
    fn add(self, rhs: &ScalarResult) -> Self::Output {
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id], move |mut args| {
                // Cast the args
                let lhs: Scalar = args.remove(0).into();
                let rhs: Scalar = args.remove(0).into();

                if party_id == PARTY0 {
                    ResultValue::Scalar(lhs + rhs)
                } else {
                    ResultValue::Scalar(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult, Add, add, +, ScalarResult);
impl_commutative!(MpcScalarResult, Add, add, +, ScalarResult);

impl Add<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn add(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |args| {
                // Cast the args
                let lhs: Scalar = args[0].to_owned().into();
                let rhs: Scalar = args[1].to_owned().into();

                ResultValue::Scalar(lhs + rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult, Add, add, +, MpcScalarResult);

impl MpcScalarResult {
    /// Add two batches of `MpcScalarResult`s using a single batched gate
    pub fn batch_add(a: &[MpcScalarResult], b: &[MpcScalarResult]) -> Vec<MpcScalarResult> {
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
    pub fn batch_add_public(a: &[MpcScalarResult], b: &[ScalarResult]) -> Vec<MpcScalarResult> {
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
        let scalars: Vec<ScalarResult> =
            fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
                if party_id == PARTY0 {
                    let mut res: Vec<ResultValue> = Vec::with_capacity(n);

                    for i in 0..n {
                        let lhs: Scalar = args[i].to_owned().into();
                        let rhs: Scalar = args[i + n].to_owned().into();

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

impl Sub<&Scalar> for &MpcScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &Scalar) -> Self::Output {
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
impl_borrow_variants!(MpcScalarResult, Sub, sub, -, Scalar);

impl Sub<&MpcScalarResult> for &Scalar {
    type Output = MpcScalarResult;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &MpcScalarResult) -> Self::Output {
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

impl Sub<&ScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &ScalarResult) -> Self::Output {
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
impl_borrow_variants!(MpcScalarResult, Sub, sub, -, ScalarResult);

impl Sub<&MpcScalarResult> for &ScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &MpcScalarResult) -> Self::Output {
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
impl_borrow_variants!(ScalarResult, Sub, sub, -, MpcScalarResult, Output=MpcScalarResult);

impl Sub<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn sub(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |args| {
                // Cast the args
                let lhs: Scalar = args[0].to_owned().into();
                let rhs: Scalar = args[1].to_owned().into();

                ResultValue::Scalar(lhs - rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult, Sub, sub, -, MpcScalarResult);

impl MpcScalarResult {
    /// Subtract two batches of `MpcScalarResult`s using a single batched gate
    pub fn batch_sub(a: &[MpcScalarResult], b: &[MpcScalarResult]) -> Vec<MpcScalarResult> {
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

        let scalars: Vec<ScalarResult> =
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

    /// Subtract a batch of `MpcScalarResult`s from a batch of public `ScalarResult`s
    pub fn batch_sub_public(a: &[MpcScalarResult], b: &[ScalarResult]) -> Vec<MpcScalarResult> {
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
                let mut res: Vec<ResultValue> = Vec::with_capacity(n);

                for i in 0..n {
                    let lhs: Scalar = args[i].to_owned().into();
                    let rhs: Scalar = args[i + n].to_owned().into();

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

impl Neg for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn neg(self) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id()], |args| {
                // Cast the args
                let lhs: Scalar = args[0].to_owned().into();
                ResultValue::Scalar(-lhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult, Neg, neg, -);

impl MpcScalarResult {
    /// Negate a batch of `MpcScalarResult`s using a single batched gate
    pub fn batch_neg(values: &[MpcScalarResult]) -> Vec<MpcScalarResult> {
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

impl Mul<&Scalar> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric()
            .new_gate_op(vec![self.id()], move |args| {
                // Cast the args
                let lhs: Scalar = args[0].to_owned().into();
                ResultValue::Scalar(lhs * rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult, Mul, mul, *, Scalar);
impl_commutative!(MpcScalarResult, Mul, mul, *, Scalar);

impl Mul<&ScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn mul(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], move |mut args| {
                // Cast the args
                let lhs: Scalar = args.remove(0).into();
                let rhs: Scalar = args.remove(0).into();

                ResultValue::Scalar(lhs * rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcScalarResult, Mul, mul, *, ScalarResult);
impl_commutative!(MpcScalarResult, Mul, mul, *, ScalarResult);

/// Use the beaver trick if both values are shared
impl Mul<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn mul(self, rhs: &MpcScalarResult) -> Self::Output {
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
impl_borrow_variants!(MpcScalarResult, Mul, mul, *, MpcScalarResult);

impl MpcScalarResult {
    /// Multiply a batch of `MpcScalarResults` over a single network op
    pub fn batch_mul(a: &[MpcScalarResult], b: &[MpcScalarResult]) -> Vec<MpcScalarResult> {
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

    /// Multiply a batch of `MpcScalarResult`s by a batch of public `ScalarResult`s
    pub fn batch_mul_public(a: &[MpcScalarResult], b: &[ScalarResult]) -> Vec<MpcScalarResult> {
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

        let scalars: Vec<ScalarResult> =
            fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
                let mut res: Vec<ResultValue> = Vec::with_capacity(n);
                for i in 0..n {
                    let lhs: Scalar = args[i].to_owned().into();
                    let rhs: Scalar = args[i + n].to_owned().into();

                    res.push(ResultValue::Scalar(lhs * rhs));
                }

                res
            });

        scalars.into_iter().map(|s| s.into()).collect_vec()
    }
}

// === Curve Scalar Multiplication === //

impl Mul<&MpcScalarResult> for &StarkPoint {
    type Output = MpcStarkPointResult;

    fn mul(self, rhs: &MpcScalarResult) -> Self::Output {
        let self_owned = *self;
        rhs.fabric()
            .new_gate_op(vec![rhs.id()], move |mut args| {
                let rhs: Scalar = args.remove(0).into();

                ResultValue::Point(self_owned * rhs)
            })
            .into()
    }
}
impl_commutative!(StarkPoint, Mul, mul, *, MpcScalarResult, Output=MpcStarkPointResult);

impl Mul<&MpcScalarResult> for &StarkPointResult {
    type Output = MpcStarkPointResult;

    fn mul(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric
            .new_gate_op(vec![self.id(), rhs.id()], |mut args| {
                let lhs: StarkPoint = args.remove(0).into();
                let rhs: Scalar = args.remove(0).into();

                ResultValue::Point(lhs * rhs)
            })
            .into()
    }
}
impl_borrow_variants!(StarkPointResult, Mul, mul, *, MpcScalarResult, Output=MpcStarkPointResult);
impl_commutative!(StarkPointResult, Mul, mul, *, MpcScalarResult, Output=MpcStarkPointResult);

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
