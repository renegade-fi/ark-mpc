//! Defines an unauthenticated shared curve point type which forms the basis
//! of the authenticated curve point type

use std::ops::{Add, Mul, Neg, Sub};

use ark_ec::CurveGroup;
use itertools::Itertools;

use crate::{
    algebra::macros::*, algebra::scalar::*, fabric::ResultValue, network::NetworkPayload,
    MpcFabric, ResultId, PARTY0,
};

use super::curve::{BatchCurvePointResult, CurvePoint, CurvePointResult};

/// Defines a secret shared type of a curve point
#[derive(Clone, Debug)]
pub struct MpcPointResult<C: CurveGroup> {
    /// The underlying value held by the local party
    pub(crate) share: CurvePointResult<C>,
}

impl<C: CurveGroup> From<CurvePointResult<C>> for MpcPointResult<C> {
    fn from(value: CurvePointResult<C>) -> Self {
        Self { share: value }
    }
}

/// Defines the result handle type that represents a future result of an
/// `MpcPoint`
impl<C: CurveGroup> MpcPointResult<C> {
    /// Creates an `MpcPoint` from a given underlying point assumed to be a
    /// secret share
    pub fn new_shared(value: CurvePointResult<C>) -> MpcPointResult<C> {
        MpcPointResult { share: value }
    }

    /// Get the ID of the underlying share's result
    pub fn id(&self) -> ResultId {
        self.share.id
    }

    /// Borrow the fabric that this result is allocated in
    pub fn fabric(&self) -> &MpcFabric<C> {
        self.share.fabric()
    }

    /// Open the value; both parties send their shares to the counterparty
    pub fn open(&self) -> CurvePointResult<C> {
        // Party zero sends first then receives
        let (share0, share1): (CurvePointResult<C>, CurvePointResult<C>) =
            if self.fabric().party_id() == PARTY0 {
                let party0_value = self.fabric().new_network_op(vec![self.id()], |mut args| {
                    let share: CurvePoint<C> = args.next().unwrap().into();
                    NetworkPayload::Point(share)
                });
                let party1_value = self.fabric().receive_value();

                (party0_value, party1_value)
            } else {
                let party0_value = self.fabric().receive_value();
                let party1_value = self.fabric().new_network_op(vec![self.id()], |mut args| {
                    let share: CurvePoint<C> = args.next().unwrap().into();
                    NetworkPayload::Point(share)
                });

                (party0_value, party1_value)
            };

        share0 + share1
    }

    /// Open a batch of values
    pub fn open_batch(values: &[MpcPointResult<C>]) -> Vec<CurvePointResult<C>> {
        if values.is_empty() {
            return Vec::new();
        }

        let n = values.len();
        let fabric = &values[0].fabric();
        let all_ids = values.iter().map(|v| v.id()).collect_vec();
        // let send_my_shares = |args: Box<dyn Iterator<Item = ResultValue<C>>>| {
        //     NetworkPayload::PointBatch(args.into_iter().map(|arg|
        // arg.into()).collect_vec()) };

        // Party zero sends first then receives
        let (party0_values, party1_values): (BatchCurvePointResult<C>, BatchCurvePointResult<C>) =
            if fabric.party_id() == PARTY0 {
                let party0_values = fabric.new_network_op(all_ids, |args| {
                    let shares = args.map(CurvePoint::from).collect_vec();
                    NetworkPayload::PointBatch(shares)
                });
                let party1_values = fabric.receive_value();

                (party0_values, party1_values)
            } else {
                let party0_values = fabric.receive_value();
                let party1_values = fabric.new_network_op(all_ids, |args| {
                    let shares = args.map(CurvePoint::from).collect_vec();
                    NetworkPayload::PointBatch(shares)
                });

                (party0_values, party1_values)
            };

        // Create a gate to component-wise add the shares
        fabric.new_batch_gate_op(
            vec![party0_values.id(), party1_values.id()],
            n, // output_arity
            |mut args| {
                let party0_values: Vec<CurvePoint<C>> = args.next().unwrap().into();
                let party1_values: Vec<CurvePoint<C>> = args.next().unwrap().into();

                party0_values
                    .into_iter()
                    .zip(party1_values)
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

impl<C: CurveGroup> Add<&CurvePoint<C>> for &MpcPointResult<C> {
    type Output = MpcPointResult<C>;

    // Only party 0 adds the plaintext value to its share
    fn add(self, rhs: &CurvePoint<C>) -> Self::Output {
        let rhs = *rhs;
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id()], move |mut args| {
                let lhs: CurvePoint<C> = args.next().unwrap().into();

                if party_id == PARTY0 {
                    ResultValue::Point(lhs + rhs)
                } else {
                    ResultValue::Point(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcPointResult<C>, Add, add, +, CurvePoint<C>, C: CurveGroup);
impl_commutative!(MpcPointResult<C>, Add, add, +, CurvePoint<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&CurvePointResult<C>> for &MpcPointResult<C> {
    type Output = MpcPointResult<C>;

    // Only party 0 adds the plaintext value to its share
    fn add(self, rhs: &CurvePointResult<C>) -> Self::Output {
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], move |mut args| {
                let lhs: CurvePoint<C> = args.next().unwrap().into();
                let rhs: CurvePoint<C> = args.next().unwrap().into();

                if party_id == PARTY0 {
                    ResultValue::Point(lhs + rhs)
                } else {
                    ResultValue::Point(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcPointResult<C>, Add, add, +, CurvePointResult<C>, C: CurveGroup);
impl_commutative!(MpcPointResult<C>, Add, add, +, CurvePointResult<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&MpcPointResult<C>> for &MpcPointResult<C> {
    type Output = MpcPointResult<C>;

    fn add(self, rhs: &MpcPointResult<C>) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |mut args| {
                let lhs: CurvePoint<C> = args.next().unwrap().into();
                let rhs: CurvePoint<C> = args.next().unwrap().into();

                ResultValue::Point(lhs + rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcPointResult<C>, Add, add, +, MpcPointResult<C>, C: CurveGroup);

impl<C: CurveGroup> MpcPointResult<C> {
    /// Add two batches of values
    pub fn batch_add(a: &[MpcPointResult<C>], b: &[MpcPointResult<C>]) -> Vec<MpcPointResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();

        let lhs = a.iter().map(|v| v.share.id());
        let rhs = b.iter().map(|v| v.share.id());
        let all_ids = lhs.interleave(rhs).collect_vec();
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
                let mut res = Vec::with_capacity(n);
                for mut chunk in &args.map(CurvePoint::from).chunks(2) {
                    let lhs = chunk.next().unwrap();
                    let rhs = chunk.next().unwrap();

                    res.push(ResultValue::Point(lhs + rhs));
                }

                res
            })
            .into_iter()
            .map(MpcPointResult::from)
            .collect_vec()
    }

    /// Add a batch of `MpcPointResults` to a batch of `CurvePointResult`s
    pub fn batch_add_public(
        a: &[MpcPointResult<C>],
        b: &[CurvePointResult<C>],
    ) -> Vec<MpcPointResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();

        let lhs = a.iter().map(|v| v.share.id());
        let rhs = b.iter().map(|v| v.id());
        let all_ids = lhs.interleave(rhs).collect_vec();
        let party_id = fabric.party_id();
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
                let mut res = Vec::with_capacity(n);
                for mut chunk in &args.map(CurvePoint::from).chunks(2) {
                    let lhs = chunk.next().unwrap();
                    let rhs = chunk.next().unwrap();

                    let val = if party_id == PARTY0 { lhs + rhs } else { lhs };
                    res.push(ResultValue::Point(val));
                }

                res
            })
            .into_iter()
            .map(MpcPointResult::from)
            .collect_vec()
    }
}

// === Subtraction === //

impl<C: CurveGroup> Sub<&CurvePoint<C>> for &MpcPointResult<C> {
    type Output = MpcPointResult<C>;

    // Only party 0 subtracts the plaintext value
    fn sub(self, rhs: &CurvePoint<C>) -> Self::Output {
        let rhs = *rhs;
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id()], move |mut args| {
                let lhs: CurvePoint<C> = args.next().unwrap().into();

                if party_id == PARTY0 {
                    ResultValue::Point(lhs - rhs)
                } else {
                    ResultValue::Point(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcPointResult<C>, Sub, sub, -, CurvePoint<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&CurvePointResult<C>> for &MpcPointResult<C> {
    type Output = MpcPointResult<C>;

    fn sub(self, rhs: &CurvePointResult<C>) -> Self::Output {
        let party_id = self.fabric().party_id();
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], move |mut args| {
                let lhs: CurvePoint<C> = args.next().unwrap().into();
                let rhs: CurvePoint<C> = args.next().unwrap().into();

                if party_id == PARTY0 {
                    ResultValue::Point(lhs - rhs)
                } else {
                    ResultValue::Point(lhs)
                }
            })
            .into()
    }
}
impl_borrow_variants!(MpcPointResult<C>, Sub, sub, -, CurvePointResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&MpcPointResult<C>> for &MpcPointResult<C> {
    type Output = MpcPointResult<C>;

    fn sub(self, rhs: &MpcPointResult<C>) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |mut args| {
                let lhs: CurvePoint<C> = args.next().unwrap().into();
                let rhs: CurvePoint<C> = args.next().unwrap().into();

                ResultValue::Point(lhs - rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcPointResult<C>, Sub, sub, -, MpcPointResult<C>, C: CurveGroup);

impl<C: CurveGroup> MpcPointResult<C> {
    /// Subtract two batches of values
    pub fn batch_sub(a: &[MpcPointResult<C>], b: &[MpcPointResult<C>]) -> Vec<MpcPointResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();

        let lhs = a.iter().map(|v| v.share.id());
        let rhs = b.iter().map(|v| v.share.id());
        let all_ids = lhs.interleave(rhs).collect_vec();
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
                let mut res = Vec::with_capacity(n);
                for mut chunk in &args.map(CurvePoint::from).chunks(2) {
                    let lhs = chunk.next().unwrap();
                    let rhs = chunk.next().unwrap();

                    res.push(ResultValue::Point(lhs - rhs));
                }

                res
            })
            .into_iter()
            .map(MpcPointResult::from)
            .collect_vec()
    }

    /// Subtract a batch of `MpcPointResults` to a batch of `CurvePointResult`s
    pub fn batch_sub_public(
        a: &[MpcPointResult<C>],
        b: &[CurvePointResult<C>],
    ) -> Vec<MpcPointResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();
        let party_id = fabric.party_id();

        let lhs = a.iter().map(|v| v.share.id());
        let rhs = b.iter().map(|v| v.id());
        let all_ids = lhs.interleave(rhs).collect_vec();
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
                let mut res = Vec::with_capacity(n);

                for mut chunk in &args.map(CurvePoint::from).chunks(2) {
                    let lhs = chunk.next().unwrap();
                    let rhs = chunk.next().unwrap();

                    let val = if party_id == PARTY0 { lhs - rhs } else { lhs };
                    res.push(ResultValue::Point(val));
                }

                res
            })
            .into_iter()
            .map(MpcPointResult::from)
            .collect_vec()
    }
}

// === Negation === //

impl<C: CurveGroup> Neg for &MpcPointResult<C> {
    type Output = MpcPointResult<C>;

    fn neg(self) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id()], |mut args| {
                let mpc_val: CurvePoint<C> = args.next().unwrap().into();
                ResultValue::Point(-mpc_val)
            })
            .into()
    }
}
impl_borrow_variants!(MpcPointResult<C>, Neg, neg, -, C: CurveGroup);

impl<C: CurveGroup> MpcPointResult<C> {
    /// Negate a batch of values
    pub fn batch_neg(values: &[MpcPointResult<C>]) -> Vec<MpcPointResult<C>> {
        if values.is_empty() {
            return Vec::new();
        }

        let n = values.len();
        let fabric = values[0].fabric();
        let all_ids = values.iter().map(|v| v.id()).collect_vec();

        // Create a gate to component-wise add the shares
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
                args.map(CurvePoint::from).map(Neg::neg).map(ResultValue::Point).collect_vec()
            })
            .into_iter()
            .map(MpcPointResult::from)
            .collect_vec()
    }
}

// === Scalar Multiplication === //

impl<C: CurveGroup> Mul<&Scalar<C>> for &MpcPointResult<C> {
    type Output = MpcPointResult<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        self.fabric()
            .new_gate_op(vec![self.id()], move |mut args| {
                let lhs: CurvePoint<C> = args.next().unwrap().into();
                ResultValue::Point(lhs * rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcPointResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
impl_commutative!(MpcPointResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&ScalarResult<C>> for &MpcPointResult<C> {
    type Output = MpcPointResult<C>;

    fn mul(self, rhs: &ScalarResult<C>) -> Self::Output {
        self.fabric()
            .new_gate_op(vec![self.id(), rhs.id()], |mut args| {
                let lhs: CurvePoint<C> = args.next().unwrap().into();
                let rhs: Scalar<C> = args.next().unwrap().into();

                ResultValue::Point(lhs * rhs)
            })
            .into()
    }
}
impl_borrow_variants!(MpcPointResult<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);
impl_commutative!(MpcPointResult<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&MpcScalarResult<C>> for &MpcPointResult<C> {
    type Output = MpcPointResult<C>;

    // Use the beaver trick as in the scalar case
    fn mul(self, rhs: &MpcScalarResult<C>) -> Self::Output {
        let generator = CurvePoint::generator();
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
impl_borrow_variants!(MpcPointResult<C>, Mul, mul, *, MpcScalarResult<C>, C: CurveGroup);
impl_commutative!(MpcPointResult<C>, Mul, mul, *, MpcScalarResult<C>, C:CurveGroup);

impl<C: CurveGroup> MpcPointResult<C> {
    /// Multiply a batch of `MpcPointResult`s with a batch of `MpcScalarResult`s
    #[allow(non_snake_case)]
    pub fn batch_mul(a: &[MpcScalarResult<C>], b: &[MpcPointResult<C>]) -> Vec<MpcPointResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();

        // Sample a set of beaver triples for the multiplications
        let (beaver_a, beaver_b, beaver_c) = fabric.next_beaver_triple_batch(n);
        let beaver_b_gen = MpcPointResult::batch_mul_generator(&beaver_b);

        let masked_rhs = MpcScalarResult::batch_sub(a, &beaver_a);
        let masked_lhs = MpcPointResult::batch_sub(b, &beaver_b_gen);

        let eG_open = MpcPointResult::open_batch(&masked_lhs);
        let d_open = MpcScalarResult::open_batch(&masked_rhs);

        // Identity [x * yG] = deG + d[bG] + [a]eG + [c]G
        let deG = CurvePointResult::batch_mul(&d_open, &eG_open);
        let dbG = MpcPointResult::batch_mul_public(&d_open, &beaver_b_gen);
        let aeG = CurvePointResult::batch_mul_shared(&beaver_a, &eG_open);
        let cG = MpcPointResult::batch_mul_generator(&beaver_c);

        let de_db_G = MpcPointResult::batch_add_public(&dbG, &deG);
        let ae_c_G = MpcPointResult::batch_add(&aeG, &cG);

        MpcPointResult::batch_add(&de_db_G, &ae_c_G)
    }

    /// Multiply a batch of `MpcPointResult`s with a batch of `ScalarResult`s
    pub fn batch_mul_public(
        a: &[ScalarResult<C>],
        b: &[MpcPointResult<C>],
    ) -> Vec<MpcPointResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");
        if a.is_empty() {
            return Vec::new();
        }

        let n = a.len();
        let fabric = a[0].fabric();

        let lhs = a.iter().map(|v| v.id());
        let rhs = b.iter().map(|v| v.id());
        let all_ids = lhs.interleave(rhs).collect_vec();
        fabric
            .new_batch_gate_op(all_ids, n /* output_arity */, move |args| {
                let mut res = Vec::with_capacity(n);
                for mut chunk in &args.chunks(2) {
                    let lhs: Scalar<C> = chunk.next().unwrap().into();
                    let rhs: CurvePoint<C> = chunk.next().unwrap().into();

                    res.push(ResultValue::Point(lhs * rhs));
                }

                res
            })
            .into_iter()
            .map(MpcPointResult::from)
            .collect_vec()
    }

    /// Multiply a batch of `MpcScalarResult`s by the generator
    pub fn batch_mul_generator(a: &[MpcScalarResult<C>]) -> Vec<MpcPointResult<C>> {
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
                let generator = CurvePoint::generator();

                scalars.into_iter().map(|x| x * generator).map(ResultValue::Point).collect_vec()
            })
            .into_iter()
            .map(MpcPointResult::from)
            .collect_vec()
    }
}
