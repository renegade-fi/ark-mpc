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
    mpc_stark_point::{MpcStarkPoint, MpcStarkPointResult},
    scalar::{Scalar, ScalarResult},
    stark_curve::{StarkPoint, StarkPointResult},
};

/// Defines a secret shared type over the `Scalar` field
#[derive(Clone, Debug)]
pub struct MpcScalar {
    /// The underlying value held by the local party
    pub(crate) value: Scalar,
    /// A reference to the underlying fabric that this value is allocated in
    pub(crate) fabric: MpcFabric,
}

/// Defines the result handle type that represents a future result of an `MpcScalar`
pub type MpcScalarResult = ResultHandle<MpcScalar>;
impl MpcScalarResult {
    /// Creates an MPC scalar from a given underlying scalar assumed to be a secret share
    pub fn new_shared(value: ScalarResult) -> ResultHandle<MpcScalar> {
        let fabric_clone = value.fabric.clone();
        value.fabric.new_gate_op(vec![value.id], move |args| {
            // Cast the args
            let value: Scalar = args[0].to_owned().into();
            ResultValue::MpcScalar(MpcScalar {
                value,
                fabric: fabric_clone,
            })
        })
    }

    /// Creates a batch of MPC scalars from a given underlying scalar assumed to be a secret share
    pub fn new_shared_batch(values: Vec<ScalarResult>) -> Vec<MpcScalarResult> {
        if values.is_empty() {
            return vec![];
        }

        let n = values.len();
        let fabric = &values[0].fabric;
        let result_ids = values.iter().map(|v| v.id).collect_vec();
        let fabric_clone = fabric.clone();

        let res: Vec<MpcScalarResult> = fabric.new_batch_gate_op(result_ids, n, move |args| {
            args.into_iter()
                .map(|val| MpcScalar {
                    value: val.into(),
                    fabric: fabric_clone.clone(),
                })
                .map(ResultValue::MpcScalar)
                .collect_vec()
        });

        res
    }

    /// Open the value; both parties send their shares to the counterparty
    pub fn open(&self) -> ResultHandle<Scalar> {
        // Party zero sends first then receives
        let (val0, val1) = if self.fabric.party_id() == PARTY0 {
            let party0_value: ResultHandle<Scalar> =
                self.fabric.new_network_op(vec![self.id], |args| {
                    let mpc_value: MpcScalar = args[0].to_owned().into();
                    NetworkPayload::Scalar(mpc_value.value)
                });
            let party1_value: ResultHandle<Scalar> = self.fabric.receive_value();

            (party0_value, party1_value)
        } else {
            let party0_value: ResultHandle<Scalar> = self.fabric.receive_value();
            let party1_value: ResultHandle<Scalar> =
                self.fabric.new_network_op(vec![self.id], |args| {
                    let mpc_value: MpcScalar = args[0].to_owned().into();
                    NetworkPayload::Scalar(mpc_value.value)
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
        let fabric = &values[0].fabric;
        let my_results = values.iter().map(|v| v.id).collect_vec();
        let send_shares_fn = |args: Vec<ResultValue>| {
            let shares: Vec<Scalar> = args
                .iter()
                .map(|arg| MpcScalar::from(arg.clone()).value)
                .collect();
            NetworkPayload::ScalarBatch(shares)
        };

        // Party zero sends first then receives
        let (party0_vals, party1_vals) = if values[0].fabric.party_id() == PARTY0 {
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
        self.fabric.new_gate_op(vec![self.id], |mut args| {
            let value: MpcScalar = args.remove(0).into();
            ResultValue::Scalar(value.value)
        })
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
        self.fabric.new_gate_op(vec![self.id], move |args| {
            // Cast the args
            let lhs: MpcScalar = args[0].to_owned().into();
            if lhs.fabric.party_id() == PARTY0 {
                ResultValue::MpcScalar(MpcScalar {
                    value: lhs.value + rhs,
                    fabric: lhs.fabric,
                })
            } else {
                ResultValue::MpcScalar(lhs)
            }
        })
    }
}
impl_borrow_variants!(MpcScalarResult, Add, add, +, Scalar);
impl_commutative!(MpcScalarResult, Add, add, +, Scalar);

impl Add<&ScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 adds the plaintext value as we do not secret share it
    fn add(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric
            .new_gate_op(vec![self.id, rhs.id], move |mut args| {
                // Cast the args
                let lhs: MpcScalar = args.remove(0).into();
                let rhs: Scalar = args.remove(0).into();

                if lhs.fabric.party_id() == PARTY0 {
                    ResultValue::MpcScalar(MpcScalar {
                        value: lhs.value + rhs,
                        fabric: lhs.fabric,
                    })
                } else {
                    ResultValue::MpcScalar(lhs)
                }
            })
    }
}
impl_borrow_variants!(MpcScalarResult, Add, add, +, ScalarResult);
impl_commutative!(MpcScalarResult, Add, add, +, ScalarResult);

impl Add<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn add(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            // Cast the args
            let lhs: MpcScalar = args[0].to_owned().into();
            let rhs: MpcScalar = args[1].to_owned().into();

            ResultValue::MpcScalar(MpcScalar {
                value: lhs.value + rhs.value,
                fabric: lhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcScalarResult, Add, add, +, MpcScalarResult);

impl MpcScalarResult {
    /// Add two batches of `MpcScalar`s using a single batched gate
    pub fn batch_add(a: &[MpcScalarResult], b: &[MpcScalarResult]) -> Vec<MpcScalarResult> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_add: a and b must be the same length"
        );

        let n = a.len();
        let fabric = &a[0].fabric;
        let ids = a.iter().chain(b.iter()).map(|v| v.id).collect_vec();

        let fabric_clone = fabric.clone();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            // Split the args
            let scalars = args
                .into_iter()
                .map(|res| MpcScalar::from(res).value)
                .collect_vec();
            let (a_res, b_res) = scalars.split_at(n);

            // Add the values
            a_res
                .iter()
                .zip(b_res.iter())
                .map(|(a, b)| {
                    ResultValue::MpcScalar(MpcScalar {
                        value: a + b,
                        fabric: fabric_clone.clone(),
                    })
                })
                .collect_vec()
        })
    }

    /// Add a batch of `MpcScalarResult`s to a batch of public `ScalarResult`s
    pub fn batch_add_public(a: &[MpcScalarResult], b: &[ScalarResult]) -> Vec<MpcScalarResult> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_add_public: a and b must be the same length"
        );

        let n = a.len();
        let fabric = &a[0].fabric;
        let ids = a
            .iter()
            .map(|v| v.id)
            .chain(b.iter().map(|v| v.id))
            .collect_vec();

        let party_id = fabric.party_id();
        let fabric_clone = fabric.clone();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            if party_id == PARTY0 {
                let mut res: Vec<ResultValue> = Vec::with_capacity(n);

                for i in 0..n {
                    let lhs: MpcScalar = args[i].to_owned().into();
                    let rhs: Scalar = args[i + n].to_owned().into();

                    res.push(ResultValue::MpcScalar(MpcScalar {
                        value: lhs.value + rhs,
                        fabric: fabric_clone.clone(),
                    }));
                }

                res
            } else {
                args[..n].to_vec()
            }
        })
    }
}

// === Subtraction === //

impl Sub<&Scalar> for &MpcScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            // Cast the args
            let lhs: MpcScalar = args[0].to_owned().into();

            if lhs.fabric.party_id() == PARTY0 {
                ResultValue::MpcScalar(MpcScalar {
                    value: lhs.value - rhs,
                    fabric: lhs.fabric,
                })
            } else {
                ResultValue::MpcScalar(lhs)
            }
        })
    }
}
impl_borrow_variants!(MpcScalarResult, Sub, sub, -, Scalar);

impl Sub<&ScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    // Only party 0 subtracts the plaintext value as we do not secret share it
    fn sub(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric
            .new_gate_op(vec![self.id, rhs.id], move |mut args| {
                // Cast the args
                let lhs: MpcScalar = args.remove(0).into();
                let rhs: Scalar = args.remove(0).into();

                if lhs.fabric.party_id() == PARTY0 {
                    ResultValue::MpcScalar(MpcScalar {
                        value: lhs.value - rhs,
                        fabric: lhs.fabric,
                    })
                } else {
                    ResultValue::MpcScalar(lhs)
                }
            })
    }
}
impl_borrow_variants!(MpcScalarResult, Sub, sub, -, ScalarResult);

impl Sub<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn sub(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |args| {
            // Cast the args
            let lhs: MpcScalar = args[0].to_owned().into();
            let rhs: MpcScalar = args[1].to_owned().into();
            ResultValue::MpcScalar(MpcScalar {
                value: lhs.value - rhs.value,
                fabric: lhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcScalarResult, Sub, sub, -, MpcScalarResult);

impl MpcScalarResult {
    /// Subtract two batches of `MpcScalar`s using a single batched gate
    pub fn batch_sub(a: &[MpcScalarResult], b: &[MpcScalarResult]) -> Vec<MpcScalarResult> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_sub: a and b must be the same length"
        );

        let n = a.len();
        let fabric = &a[0].fabric;
        let ids = a
            .iter()
            .map(|v| v.id)
            .chain(b.iter().map(|v| v.id))
            .collect_vec();

        let fabric_clone = fabric.clone();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            // Split the args
            let scalars = args
                .into_iter()
                .map(|res| MpcScalar::from(res).value)
                .collect_vec();
            let (a_res, b_res) = scalars.split_at(n);

            // Add the values
            a_res
                .iter()
                .zip(b_res.iter())
                .map(|(a, b)| {
                    ResultValue::MpcScalar(MpcScalar {
                        value: a - b,
                        fabric: fabric_clone.clone(),
                    })
                })
                .collect_vec()
        })
    }

    /// Subtract a batch of `MpcScalarResult`s from a batch of public `ScalarResult`s
    pub fn batch_sub_public(a: &[MpcScalarResult], b: &[ScalarResult]) -> Vec<MpcScalarResult> {
        assert_eq!(
            a.len(),
            b.len(),
            "batch_sub_public: a and b must be the same length"
        );

        let n = a.len();
        let fabric = &a[0].fabric;
        let ids = a
            .iter()
            .map(|v| v.id)
            .chain(b.iter().map(|v| v.id))
            .collect_vec();

        let party_id = fabric.party_id();
        let fabric_clone = fabric.clone();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            if party_id == PARTY0 {
                let mut res: Vec<ResultValue> = Vec::with_capacity(n);

                for i in 0..n {
                    let lhs: MpcScalar = args[i].to_owned().into();
                    let rhs: Scalar = args[i + n].to_owned().into();

                    res.push(ResultValue::MpcScalar(MpcScalar {
                        value: lhs.value - rhs,
                        fabric: fabric_clone.clone(),
                    }));
                }

                res
            } else {
                args[..n].to_vec()
            }
        })
    }
}

// === Negation === //

impl Neg for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn neg(self) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id], |args| {
            // Cast the args
            let lhs: MpcScalar = args[0].to_owned().into();
            ResultValue::MpcScalar(MpcScalar {
                value: -lhs.value,
                fabric: lhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcScalarResult, Neg, neg, -);

impl MpcScalarResult {
    /// Negate a batch of `MpcScalar`s using a single batched gate
    pub fn batch_neg(values: &[MpcScalarResult]) -> Vec<MpcScalarResult> {
        if values.is_empty() {
            return vec![];
        }

        let n = values.len();
        let fabric = &values[0].fabric;
        let ids = values.iter().map(|v| v.id).collect_vec();

        let fabric_clone = fabric.clone();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            // Split the args
            let scalars = args
                .into_iter()
                .map(|res| MpcScalar::from(res).value)
                .collect_vec();

            // Add the values
            scalars
                .iter()
                .map(|a| {
                    ResultValue::MpcScalar(MpcScalar {
                        value: -a,
                        fabric: fabric_clone.clone(),
                    })
                })
                .collect_vec()
        })
    }
}

// === Multiplication === //

impl Mul<&Scalar> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |args| {
            // Cast the args
            let lhs: MpcScalar = args[0].to_owned().into();
            ResultValue::MpcScalar(MpcScalar {
                value: lhs.value * rhs,
                fabric: lhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(MpcScalarResult, Mul, mul, *, Scalar);
impl_commutative!(MpcScalarResult, Mul, mul, *, Scalar);

impl Mul<&ScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn mul(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric
            .new_gate_op(vec![self.id, rhs.id], move |mut args| {
                // Cast the args
                let lhs: MpcScalar = args.remove(0).into();
                let rhs: Scalar = args.remove(0).into();

                ResultValue::MpcScalar(MpcScalar {
                    value: lhs.value * rhs,
                    fabric: lhs.fabric,
                })
            })
    }
}
impl_borrow_variants!(MpcScalarResult, Mul, mul, *, ScalarResult);
impl_commutative!(MpcScalarResult, Mul, mul, *, ScalarResult);

/// Use the beaver trick if both values are shared
impl Mul<&MpcScalarResult> for &MpcScalarResult {
    type Output = MpcScalarResult;

    fn mul(self, rhs: &MpcScalarResult) -> Self::Output {
        // Sample a beaver triplet
        let (a, b, c) = self.fabric.next_beaver_triple();

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
    /// Multiply a batch of `MpcScalars` over a single network op
    pub fn batch_mul(a: &[MpcScalarResult], b: &[MpcScalarResult]) -> Vec<MpcScalarResult> {
        let n = a.len();
        assert_eq!(
            a.len(),
            b.len(),
            "batch_mul: a and b must be the same length"
        );

        // Sample a beaver triplet for each multiplication
        let fabric = &a[0].fabric;
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
        let fabric = &a[0].fabric;
        let ids = a
            .iter()
            .map(|v| v.id)
            .chain(b.iter().map(|v| v.id))
            .collect_vec();

        let fabric_clone = fabric.clone();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let mut res: Vec<ResultValue> = Vec::with_capacity(n);
            for i in 0..n {
                let lhs: MpcScalar = args[i].to_owned().into();
                let rhs: Scalar = args[i + n].to_owned().into();

                res.push(ResultValue::MpcScalar(MpcScalar {
                    value: lhs.value * rhs,
                    fabric: fabric_clone.clone(),
                }));
            }

            res
        })
    }
}

// === Curve Scalar Multiplication === //

impl Mul<&MpcScalarResult> for &StarkPoint {
    type Output = MpcStarkPointResult;

    fn mul(self, rhs: &MpcScalarResult) -> Self::Output {
        let self_owned = *self;
        rhs.fabric.new_gate_op(vec![rhs.id], move |mut args| {
            let rhs: MpcScalar = args.remove(0).into();

            ResultValue::MpcStarkPoint(MpcStarkPoint {
                value: self_owned * rhs.value,
                fabric: rhs.fabric,
            })
        })
    }
}
impl_commutative!(StarkPoint, Mul, mul, *, MpcScalarResult, Output=MpcStarkPointResult);

impl Mul<&MpcScalarResult> for &StarkPointResult {
    type Output = MpcStarkPointResult;

    fn mul(self, rhs: &MpcScalarResult) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: StarkPoint = args.remove(0).into();
            let rhs: MpcScalar = args.remove(0).into();

            ResultValue::MpcStarkPoint(MpcStarkPoint {
                value: lhs * rhs.value,
                fabric: rhs.fabric,
            })
        })
    }
}
impl_borrow_variants!(StarkPointResult, Mul, mul, *, MpcScalarResult, Output=MpcStarkPointResult);
impl_commutative!(StarkPointResult, Mul, mul, *, MpcScalarResult, Output=MpcStarkPointResult);
