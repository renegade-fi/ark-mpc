//! Defines the `ScalarResult` type, which is a result that resolves to a
//! `Scalar`

use std::{
    iter::Product,
    ops::{Add, Mul, Neg, Sub},
};

use ark_ec::CurveGroup;
use ark_ff::{FftField, Field};
use ark_poly::EvaluationDomain;
use itertools::Itertools;

use crate::algebra::macros::*;
use crate::fabric::{ResultHandle, ResultValue};

use super::Scalar;

/// A type alias for a result that resolves to a `Scalar`
pub type ScalarResult<C> = ResultHandle<C, Scalar<C>>;
/// A type alias for a result that resolves to a batch of `Scalar`s
pub type BatchScalarResult<C> = ResultHandle<C, Vec<Scalar<C>>>;

impl<C: CurveGroup> ScalarResult<C> {
    /// Exponentiation
    pub fn pow(&self, exp: u64) -> Self {
        self.fabric().new_gate_op(vec![self.id()], move |mut args| {
            let base: Scalar<C> = args.next().unwrap().into();
            let res = base.inner().pow([exp]);

            ResultValue::Scalar(Scalar::new(res))
        })
    }
}

// --------------
// | Arithmetic |
// --------------

impl<C: CurveGroup> ScalarResult<C> {
    /// Compute the multiplicative inverse of the scalar in its field
    pub fn inverse(&self) -> ScalarResult<C> {
        self.fabric.new_gate_op(vec![self.id], |mut args| {
            let val: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(val.0.inverse().unwrap()))
        })
    }

    /// Compute the inverse of a batch of values
    pub fn batch_inverse(values: &[ScalarResult<C>]) -> Vec<ScalarResult<C>> {
        let n = values.len();
        let fabric = &values[0].fabric;
        let ids = values.iter().map(|v| v.id).collect_vec();

        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let mut scalars: Vec<Scalar<C>> = args.into_iter().map(Into::into).collect_vec();
            Scalar::batch_inverse(&mut scalars);

            scalars.into_iter().map(ResultValue::Scalar).collect_vec()
        })
    }
}

// === Addition === //

impl<C: CurveGroup> Add<&Scalar<C>> for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn add(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(lhs.0 + rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Add, add, +, Scalar<C>, C: CurveGroup);
impl_commutative!(ScalarResult<C>, Add, add, +, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Add<&ScalarResult<C>> for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn add(self, rhs: &ScalarResult<C>) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            let rhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(lhs.0 + rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Add, add, +, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> ScalarResult<C> {
    /// Add two batches of `ScalarResult<C>`s
    pub fn batch_add(a: &[ScalarResult<C>], b: &[ScalarResult<C>]) -> Vec<ScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add requires equal length inputs");

        let n = a.len();
        let fabric = &a[0].fabric;

        let lhs = a.iter().map(|v| v.id);
        let rhs = b.iter().map(|v| v.id);
        let ids = lhs.interleave(rhs).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let mut res = Vec::with_capacity(n);

            for mut chunk in &args.map(Scalar::from).chunks(2) {
                let lhs = chunk.next().unwrap();
                let rhs = chunk.next().unwrap();

                res.push(ResultValue::Scalar(Scalar(lhs.0 + rhs.0)));
            }

            res
        })
    }

    /// Add a batch of `ScalarResult`s to a batch of `Scalar`s
    pub fn batch_add_constant(a: &[ScalarResult<C>], b: &[Scalar<C>]) -> Vec<ScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add constant requires equal length inputs");

        let n = a.len();
        let fabric = &a[0].fabric;
        let b = b.to_vec();

        let ids = a.iter().map(|v| v.id).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let a_vals = args.into_iter().map(Scalar::from).collect_vec();
            a_vals
                .into_iter()
                .zip(b.iter())
                .map(|(a, b)| a + b)
                .map(ResultValue::Scalar)
                .collect_vec()
        })
    }
}

// === Subtraction === //

impl<C: CurveGroup> Sub<&Scalar<C>> for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn sub(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(lhs.0 - rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Sub, sub, -, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&ScalarResult<C>> for &Scalar<C> {
    type Output = ScalarResult<C>;

    fn sub(self, rhs: &ScalarResult<C>) -> Self::Output {
        let lhs = *self;
        rhs.fabric.new_gate_op(vec![rhs.id], move |mut args| {
            let rhs: Scalar<C> = args.next().unwrap().to_owned().into();
            ResultValue::Scalar(lhs - rhs)
        })
    }
}
impl_borrow_variants!(Scalar<C>, Sub, sub, -, ScalarResult<C>, Output=ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Sub<&ScalarResult<C>> for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn sub(self, rhs: &ScalarResult<C>) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            let rhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(lhs.0 - rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Sub, sub, -, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> ScalarResult<C> {
    /// Subtract two batches of `ScalarResult`s
    pub fn batch_sub(a: &[ScalarResult<C>], b: &[ScalarResult<C>]) -> Vec<ScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch sub requires equal length inputs");

        let n = a.len();
        let fabric = &a[0].fabric;

        let lhs = a.iter().map(|v| v.id);
        let rhs = b.iter().map(|v| v.id);
        let ids = lhs.interleave(rhs).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let mut res = Vec::with_capacity(n);
            for mut chunk in &args.map(Scalar::from).chunks(2) {
                let lhs = chunk.next().unwrap();
                let rhs = chunk.next().unwrap();

                res.push(ResultValue::Scalar(Scalar(lhs.0 - rhs.0)));
            }

            res
        })
    }

    /// Subtract a batch of `Scalar`s from a batch of `ScalarResult`s
    pub fn batch_sub_constant(a: &[ScalarResult<C>], b: &[Scalar<C>]) -> Vec<ScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch add constant requires equal length inputs");

        let n = a.len();
        let fabric = &a[0].fabric;
        let b = b.to_vec();

        let ids = a.iter().map(|v| v.id).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let a_vals = args.into_iter().map(Scalar::from).collect_vec();
            a_vals
                .into_iter()
                .zip(b.iter())
                .map(|(a, b)| a - b)
                .map(ResultValue::Scalar)
                .collect_vec()
        })
    }
}

// === Multiplication === //

impl<C: CurveGroup> Mul<&Scalar<C>> for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        let rhs = *rhs;
        self.fabric.new_gate_op(vec![self.id], move |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(lhs.0 * rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
impl_commutative!(ScalarResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&ScalarResult<C>> for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn mul(self, rhs: &ScalarResult<C>) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id, rhs.id], |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            let rhs: Scalar<C> = args.next().unwrap().into();

            ResultValue::Scalar(Scalar(lhs.0 * rhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> ScalarResult<C> {
    /// Multiply two batches of `ScalarResult`s
    pub fn batch_mul(a: &[ScalarResult<C>], b: &[ScalarResult<C>]) -> Vec<ScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch mul requires equal length inputs");

        let n = a.len();
        let fabric = &a[0].fabric;

        let lhs = a.iter().map(|v| v.id);
        let rhs = b.iter().map(|v| v.id);
        let ids = lhs.interleave(rhs).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let mut res = Vec::with_capacity(n);

            for mut chunk in &args.map(Scalar::from).chunks(2) {
                let lhs = chunk.next().unwrap();
                let rhs = chunk.next().unwrap();

                res.push(ResultValue::Scalar(Scalar(lhs.0 * rhs.0)));
            }

            res
        })
    }

    /// Multiply a batch of `ScalarResult`s by a batch of `Scalar`s
    pub fn batch_mul_constant(a: &[ScalarResult<C>], b: &[Scalar<C>]) -> Vec<ScalarResult<C>> {
        assert_eq!(a.len(), b.len(), "Batch mul constant requires equal length inputs");

        let n = a.len();
        let fabric = &a[0].fabric;
        let b = b.to_vec();

        let ids = a.iter().map(|v| v.id).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let a_vals = args.into_iter().map(Scalar::from).collect_vec();
            a_vals
                .into_iter()
                .zip(b.iter())
                .map(|(a, b)| a * b)
                .map(ResultValue::Scalar)
                .collect_vec()
        })
    }
}

impl<C: CurveGroup> Neg for &ScalarResult<C> {
    type Output = ScalarResult<C>;

    fn neg(self) -> Self::Output {
        self.fabric.new_gate_op(vec![self.id], |mut args| {
            let lhs: Scalar<C> = args.next().unwrap().into();
            ResultValue::Scalar(Scalar(-lhs.0))
        })
    }
}
impl_borrow_variants!(ScalarResult<C>, Neg, neg, -, C: CurveGroup);

impl<C: CurveGroup> ScalarResult<C> {
    /// Negate a batch of `ScalarResult`s
    pub fn batch_neg(a: &[ScalarResult<C>]) -> Vec<ScalarResult<C>> {
        let n = a.len();
        let fabric = &a[0].fabric;
        let ids = a.iter().map(|v| v.id).collect_vec();
        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            args.into_iter().map(Scalar::from).map(|x| -x).map(ResultValue::Scalar).collect_vec()
        })
    }
}

impl<C: CurveGroup> Product for ScalarResult<C> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let values: Vec<Self> = iter.collect_vec();
        assert!(!values.is_empty(), "Cannot compute product of empty iterator");

        let ids = values.iter().map(|v| v.id()).collect_vec();
        let fabric = values[0].fabric();

        fabric.new_gate_op(ids, move |args| {
            let res = args.map(Scalar::from).product();
            ResultValue::Scalar(res)
        })
    }
}

// === FFT and IFFT === //

impl<C: CurveGroup> ScalarResult<C>
where
    C::ScalarField: FftField,
{
    /// Compute the fft of a sequence of `ScalarResult`s
    pub fn fft<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[ScalarResult<C>],
    ) -> Vec<ScalarResult<C>> {
        Self::fft_with_domain(x, D::new(x.len()).unwrap())
    }

    /// Compute the fft of a sequence of `ScalarResult`s with the given domain
    pub fn fft_with_domain<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[ScalarResult<C>],
        domain: D,
    ) -> Vec<ScalarResult<C>> {
        assert!(!x.is_empty(), "Cannot compute fft of empty sequence");
        let n = domain.size();

        let fabric = x[0].fabric();
        let ids = x.iter().map(|v| v.id).collect_vec();

        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let scalars = args.into_iter().map(Scalar::from).map(|x| x.0).collect_vec();

            domain
                .fft(&scalars)
                .into_iter()
                .map(|x| ResultValue::Scalar(Scalar::new(x)))
                .collect_vec()
        })
    }

    /// Compute the ifft of a sequence of `ScalarResult`s
    pub fn ifft<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[ScalarResult<C>],
    ) -> Vec<ScalarResult<C>> {
        Self::ifft_with_domain(x, D::new(x.len()).unwrap())
    }

    /// Compute the ifft of a sequence of `ScalarResult`s with the given domain
    pub fn ifft_with_domain<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[ScalarResult<C>],
        domain: D,
    ) -> Vec<ScalarResult<C>> {
        assert!(!x.is_empty(), "Cannot compute fft of empty sequence");
        let n = domain.size();

        let fabric = x[0].fabric();
        let ids = x.iter().map(|v| v.id).collect_vec();

        fabric.new_batch_gate_op(ids, n /* output_arity */, move |args| {
            let scalars = args.into_iter().map(Scalar::from).map(|x| x.0).collect_vec();

            domain
                .ifft(&scalars)
                .into_iter()
                .map(|x| ResultValue::Scalar(Scalar::new(x)))
                .collect_vec()
        })
    }
}
