//! Defines an unauthenticated shared curve point type which forms the basis
//! of the authenticated curve point type

use std::ops::{Add, Mul, Neg, Sub};

use itertools::Itertools;

use crate::{
    fabric::{ResultHandle, ResultValue},
    network::NetworkPayload,
    MpcFabric, ResultId, PARTY0,
};

use super::{
    macros::{impl_borrow_variants, impl_commutative},
    mpc_scalar::MpcScalarResult,
    scalar::{Scalar, ScalarResult},
    stark_curve::{BatchStarkPointResult, StarkPoint, StarkPointResult},
};

/// Defines a secret shared type of a curve point
#[derive(Clone, Debug)]
pub struct MpcStarkPointResult {
    /// The underlying value held by the local party
    pub(crate) share: StarkPointResult,
}

impl From<StarkPointResult> for MpcStarkPointResult {
    fn from(value: StarkPointResult) -> Self {
        Self { share: value }
    }
}

/// Defines the result handle type that represents a future result of an `MpcStarkPoint`
impl MpcStarkPointResult {
    /// Creates an `MpcStarkPoint` from a given underlying point assumed to be a secret share
    pub fn new_shared(value: StarkPointResult) -> MpcStarkPointResult {
        MpcStarkPointResult { share: value }
    }

    /// Get the ID of the underlying share's result
    pub fn id(&self) -> ResultId {
        self.share.id
    }

    /// Borrow the fabric that this result is allocated in
    pub fn fabric(&self) -> &MpcFabric {
        self.share.fabric()
    }

    /// Open the value; both parties send their shares to the counterparty
    pub fn open(&self) -> ResultHandle<StarkPoint> {
        let send_my_share =
            |args: Vec<ResultValue>| NetworkPayload::Point(args[0].to_owned().into());

        // Party zero sends first then receives
        let (share0, share1): (StarkPointResult, StarkPointResult) =
            if self.fabric().party_id() == PARTY0 {
                let party0_value = self.fabric().new_network_op(vec![self.id()], send_my_share);
                let party1_value = self.fabric().receive_value();

                (party0_value, party1_value)
            } else {
                let party0_value = self.fabric().receive_value();
                let party1_value = self.fabric().new_network_op(vec![self.id()], send_my_share);

                (party0_value, party1_value)
            };

        share0 + share1
    }

    /// Open a batch of values
    pub fn open_batch(values: &[MpcStarkPointResult]) -> Vec<StarkPointResult> {
        if values.is_empty() {
            return Vec::new();
        }

        let n = values.len();
        let fabric = &values[0].fabric();
        let all_ids = values.iter().map(|v| v.id()).collect_vec();
        let send_my_shares = |args: Vec<ResultValue>| {
            NetworkPayload::PointBatch(args.into_iter().map(|arg| arg.into()).collect_vec())
        };

        // Party zero sends first then receives
        let (party0_values, party1_values): (BatchStarkPointResult, BatchStarkPointResult) =
            if fabric.party_id() == PARTY0 {
                let party0_values = fabric.new_network_op(all_ids, send_my_shares);
                let party1_values = fabric.receive_value();

                (party0_values, party1_values)
            } else {
                let party0_values = fabric.receive_value();
                let party1_values = fabric.new_network_op(all_ids, send_my_shares);

                (party0_values, party1_values)
            };

        // Create a gate to component-wise add the shares
        fabric.new_batch_gate_op(
            vec![party0_values.id(), party1_values.id()],
            n, /* output_arity */
            |mut args| {
                let party0_values: Vec<StarkPoint> = args.remove(0).into();
                let party1_values: Vec<StarkPoint> = args.remove(0).into();

                party0_values
                    .into_iter()
                    .zip(party1_values.into_iter())
                    .map(|(x, y)| x + y)
                    .map(ResultValue::Point)
                    .collect_vec()
            },
        )
    }
}

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl Add<&StarkPoint> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    // Only party 0 adds the plaintext value to its share
    fn add(self, rhs: &StarkPoint) -> Self::Output {
        let rhs = *rhs;
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id()], move |args| {
                let lhs: StarkPoint = args[0].to_owned().into();

                if party_id == PARTY0 {
                    ResultValue::Point(lhs + rhs)
                } else {
                    ResultValue::Point(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Add, add, +, StarkPoint);
impl_commutative!(MpcStarkPointResult, Add, add, +, StarkPoint);

impl Add<&StarkPointResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    // Only party 0 adds the plaintext value to its share
    fn add(self, rhs: &StarkPointResult) -> Self::Output {
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], move |mut args| {
                let lhs: StarkPoint = args.remove(0).into();
                let rhs: StarkPoint = args.remove(0).into();

                if party_id == PARTY0 {
                    ResultValue::Point(lhs + rhs)
                } else {
                    ResultValue::Point(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Add, add, +, StarkPointResult);
impl_commutative!(MpcStarkPointResult, Add, add, +, StarkPointResult);

impl Add<&MpcStarkPointResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn add(self, rhs: &MpcStarkPointResult) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |args| {
                let lhs: StarkPoint = args[0].to_owned().into();
                let rhs: StarkPoint = args[1].to_owned().into();

                ResultValue::Point(lhs + rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Add, add, +, MpcStarkPointResult);

impl MpcStarkPointResult {
    /// Add two batches of values
    pub fn batch_add(
        a: &[MpcStarkPointResult],
        b: &[MpcStarkPointResult],
    ) -> Vec<MpcStarkPointResult> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().chain(b.iter()).map(|v| v.id()).collect_vec();

        // Create a gate to component-wise add the shares
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
                let points = args.into_iter().map(StarkPoint::from).collect_vec();
                let (a, b) = points.split_at(n);

                a.iter()
                    .zip(b.iter())
                    .map(|(x, y)| x + y)
                    .map(ResultValue::Point)
                    .collect_vec()
            })
            .into_iter()
            .map(MpcStarkPointResult::from)
            .collect_vec()
    }

    /// Add a batch of `MpcStarkPointResults` to a batch of `StarkPointResult`s
    pub fn batch_add_public(
        a: &[MpcStarkPointResult],
        b: &[StarkPointResult],
    ) -> Vec<MpcStarkPointResult> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a
            .iter()
            .map(|v| v.id())
            .chain(b.iter().map(|b| b.id))
            .collect_vec();

        // Add the shares in a batch gate
        let party_id = fabric.party_id();
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |mut args| {
                let lhs_points = args.drain(..n).map(StarkPoint::from).collect_vec();
                let rhs_points = args.into_iter().map(StarkPoint::from).collect_vec();

                lhs_points
                    .into_iter()
                    .zip(rhs_points.into_iter())
                    .map(|(x, y)| if party_id == PARTY0 { x + y } else { x })
                    .map(ResultValue::Point)
                    .collect_vec()
            })
            .into_iter()
            .map(MpcStarkPointResult::from)
            .collect_vec()
    }
}

// === Subtraction === //

impl Sub<&StarkPoint> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    // Only party 0 subtracts the plaintext value
    fn sub(self, rhs: &StarkPoint) -> Self::Output {
        let rhs = *rhs;
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id()], move |args| {
                let lhs: StarkPoint = args[0].to_owned().into();

                if party_id == PARTY0 {
                    ResultValue::Point(lhs - rhs)
                } else {
                    ResultValue::Point(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Sub, sub, -, StarkPoint);

impl Sub<&StarkPointResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn sub(self, rhs: &StarkPointResult) -> Self::Output {
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], move |mut args| {
                let lhs: StarkPoint = args.remove(0).into();
                let rhs: StarkPoint = args.remove(0).into();

                if party_id == PARTY0 {
                    ResultValue::Point(lhs - rhs)
                } else {
                    ResultValue::Point(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Sub, sub, -, StarkPointResult);

impl Sub<&MpcStarkPointResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn sub(self, rhs: &MpcStarkPointResult) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |args| {
                let lhs: StarkPoint = args[0].to_owned().into();
                let rhs: StarkPoint = args[1].to_owned().into();

                ResultValue::Point(lhs - rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Sub, sub, -, MpcStarkPointResult);

impl MpcStarkPointResult {
    /// Subtract two batches of values
    pub fn batch_sub(
        a: &[MpcStarkPointResult],
        b: &[MpcStarkPointResult],
    ) -> Vec<MpcStarkPointResult> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().chain(b.iter()).map(|v| v.id()).collect_vec();

        // Create a gate to component-wise add the shares
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
                let points = args.into_iter().map(StarkPoint::from).collect_vec();
                let (a, b) = points.split_at(n);

                a.iter()
                    .zip(b.iter())
                    .map(|(x, y)| x - y)
                    .map(ResultValue::Point)
                    .collect_vec()
            })
            .into_iter()
            .map(MpcStarkPointResult::from)
            .collect_vec()
    }

    /// Subtract a batch of `MpcStarkPointResults` to a batch of `StarkPointResult`s
    pub fn batch_sub_public(
        a: &[MpcStarkPointResult],
        b: &[StarkPointResult],
    ) -> Vec<MpcStarkPointResult> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a
            .iter()
            .map(|v| v.id())
            .chain(b.iter().map(|b| b.id))
            .collect_vec();

        // Add the shares in a batch gate
        let party_id = fabric.party_id();
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |mut args| {
                let lhs_points = args.drain(..n).map(StarkPoint::from).collect_vec();
                let rhs_points = args.into_iter().map(StarkPoint::from).collect_vec();

                lhs_points
                    .into_iter()
                    .zip(rhs_points.into_iter())
                    .map(|(x, y)| if party_id == PARTY0 { x - y } else { x })
                    .map(ResultValue::Point)
                    .collect_vec()
            })
            .into_iter()
            .map(MpcStarkPointResult::from)
            .collect_vec()
    }
}

// === Negation === //

impl Neg for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn neg(self) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id()], |mut args| {
                let mpc_val: StarkPoint = args.remove(0).into();
                ResultValue::Point(-mpc_val)
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Neg, neg, -);

impl MpcStarkPointResult {
    /// Negate a batch of values
    pub fn batch_neg(values: &[MpcStarkPointResult]) -> Vec<MpcStarkPointResult> {
        if values.is_empty() {
            return Vec::new();
        }

        let n = values.len();
        let fabric = values[0].fabric();
        let all_ids = values.iter().map(|v| v.id()).collect_vec();

        // Create a gate to component-wise add the shares
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
                let points = args.into_iter().map(StarkPoint::from).collect_vec();

                points
                    .into_iter()
                    .map(|x| -x)
                    .map(ResultValue::Point)
                    .collect_vec()
            })
            .into_iter()
            .map(MpcStarkPointResult::from)
            .collect_vec()
    }
}

// === Scalar Multiplication === //

impl Mul<&Scalar> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        let rhs = *rhs;
        self.fabric()
            .new_gate_op(vec![self.id()], move |args| {
                let lhs: StarkPoint = args[0].to_owned().into();
                ResultValue::Point(lhs * rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Mul, mul, *, Scalar);
impl_commutative!(MpcStarkPointResult, Mul, mul, *, Scalar);

impl Mul<&ScalarResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    fn mul(self, rhs: &ScalarResult) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |mut args| {
                let lhs: StarkPoint = args.remove(0).into();
                let rhs: Scalar = args.remove(0).into();

                ResultValue::Point(lhs * rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcStarkPointResult, Mul, mul, *, ScalarResult);
impl_commutative!(MpcStarkPointResult, Mul, mul, *, ScalarResult);

impl Mul<&MpcScalarResult> for &MpcStarkPointResult {
    type Output = MpcStarkPointResult;

    // Use the beaver trick as in the scalar case
    fn mul(self, rhs: &MpcScalarResult) -> Self::Output {
        let generator = StarkPoint::generator();
        let (a, b, c) = self.fabric().next_beaver_triple();

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
impl_borrow_variants!(MpcStarkPointResult, Mul, mul, *, MpcScalarResult);
impl_commutative!(MpcStarkPointResult, Mul, mul, *, MpcScalarResult);

impl MpcStarkPointResult {
    /// Multiply a batch of `MpcStarkPointResult`s with a batch of `MpcScalarResult`s
    #[allow(non_snake_case)]
    pub fn batch_mul(a: &[MpcScalarResult], b: &[MpcStarkPointResult]) -> Vec<MpcStarkPointResult> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();

        // Sample a set of beaver triples for the multiplications
        let (beaver_a, beaver_b, beaver_c) = fabric.next_beaver_triple_batch(n);
        let beaver_b_gen = MpcStarkPointResult::batch_mul_generator(&beaver_b);

        let masked_rhs = MpcScalarResult::batch_sub(a, &beaver_a);
        let masked_lhs = MpcStarkPointResult::batch_sub(b, &beaver_b_gen);

        let eG_open = MpcStarkPointResult::open_batch(&masked_lhs);
        let d_open = MpcScalarResult::open_batch(&masked_rhs);

        // Identity [x * yG] = deG + d[bG] + [a]eG + [c]G
        let deG = StarkPointResult::batch_mul(&d_open, &eG_open);
        let dbG = MpcStarkPointResult::batch_mul_public(&d_open, &beaver_b_gen);
        let aeG = StarkPointResult::batch_mul_shared(&beaver_a, &eG_open);
        let cG = MpcStarkPointResult::batch_mul_generator(&beaver_c);

        let de_db_G = MpcStarkPointResult::batch_add_public(&dbG, &deG);
        let ae_c_G = MpcStarkPointResult::batch_add(&aeG, &cG);

        MpcStarkPointResult::batch_add(&de_db_G, &ae_c_G)
    }

    /// Multiply a batch of `MpcStarkPointResult`s with a batch of `ScalarResult`s
    pub fn batch_mul_public(
        a: &[ScalarResult],
        b: &[MpcStarkPointResult],
    ) -> Vec<MpcStarkPointResult> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a
            .iter()
            .map(|v| v.id())
            .chain(b.iter().map(|b| b.id()))
            .collect_vec();

        // Multiply the shares in a batch gate
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |mut args| {
                let scalars = args.drain(..n).map(Scalar::from).collect_vec();
                let points = args.into_iter().map(StarkPoint::from).collect_vec();

                scalars
                    .into_iter()
                    .zip(points.into_iter())
                    .map(|(x, y)| x * y)
                    .map(ResultValue::Point)
                    .collect_vec()
            })
            .into_iter()
            .map(MpcStarkPointResult::from)
            .collect_vec()
    }

    /// Multiply a batch of `MpcScalarResult`s by the generator
    pub fn batch_mul_generator(a: &[MpcScalarResult]) -> Vec<MpcStarkPointResult> {
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let all_ids = a.iter().map(|v| v.id()).collect_vec();

        // Multiply the shares in a batch gate
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
                let scalars = args.into_iter().map(Scalar::from).collect_vec();
                let generator = StarkPoint::generator();

                scalars
                    .into_iter()
                    .map(|x| x * generator)
                    .map(ResultValue::Point)
                    .collect_vec()
            })
            .into_iter()
            .map(MpcStarkPointResult::from)
            .collect_vec()
    }
}
