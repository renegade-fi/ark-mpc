//! Defines the base polynomial representation, modeled after the `ark_poly::DensePolynomial` type

use std::{
    cmp, iter,
    ops::{Add, Div, Mul, Neg, Sub},
    pin::Pin,
    task::{Context, Poll},
};

use ark_ec::CurveGroup;
use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial,
};
use futures::FutureExt;
use futures::{ready, Future};
use itertools::Itertools;

use crate::{
    algebra::{
        macros::{impl_borrow_variants, impl_commutative},
        AuthenticatedScalarResult, Scalar, ScalarResult,
    },
    MpcFabric, ResultValue,
};

use super::AuthenticatedDensePoly;

// -----------
// | Helpers |
// -----------

/// Return a representation of x^t as a `DensePolynomial`
fn x_to_t<C: CurveGroup>(t: usize) -> DensePolynomial<C::ScalarField> {
    let mut coeffs = vec![C::ScalarField::zero(); t];
    coeffs.push(C::ScalarField::one());
    DensePolynomial::from_coefficients_vec(coeffs)
}

// ------------------
// | Implementation |
// ------------------

/// A dense polynomial representation allocated in an MPC circuit
#[derive(Clone)]
pub struct DensePolynomialResult<C: CurveGroup> {
    /// The coefficients of the polynomial, the `i`th coefficient is the coefficient of `x^i`
    pub coeffs: Vec<ScalarResult<C>>,
}

impl<C: CurveGroup> DensePolynomialResult<C> {
    /// Constructor
    pub fn from_coeffs(coeffs: Vec<ScalarResult<C>>) -> Self {
        assert!(!coeffs.is_empty(), "cannot construct an empty polynomial");
        Self { coeffs }
    }

    /// Construct the zero polynomial (additive identity)
    pub fn zero(fabric: &MpcFabric<C>) -> Self {
        Self::from_coeffs(vec![fabric.zero()])
    }

    /// Construct the one polynomial (multiplicative identity)
    pub fn one(fabric: &MpcFabric<C>) -> Self {
        Self::from_coeffs(vec![fabric.one()])
    }

    /// Returns the degree of the polynomial
    pub fn degree(&self) -> usize {
        self.coeffs.len() - 1
    }

    /// Get a reference to the fabric that the polynomial is allocated within
    pub(crate) fn fabric(&self) -> &MpcFabric<C> {
        self.coeffs[0].fabric()
    }

    /// Evaluate the polynomial at a given point
    pub fn eval(&self, point: ScalarResult<C>) -> ScalarResult<C> {
        let fabric = self.fabric();
        let mut deps = self.coeffs.iter().map(|coeff| coeff.id()).collect_vec();
        deps.push(point.id());

        let n_coeffs = self.coeffs.len();
        fabric.new_gate_op(deps, move |mut args| {
            let coeffs: Vec<Scalar<C>> = args.drain(..n_coeffs).map(|res| res.into()).collect_vec();
            let point: Scalar<C> = args.pop().unwrap().into();

            let mut res = Scalar::zero();
            for coeff in coeffs.iter().rev() {
                res = res * point + coeff;
            }

            ResultValue::Scalar(res)
        })
    }
}

/// Modular inversion implementation
impl<C: CurveGroup> DensePolynomialResult<C> {
    /// Compute the multiplicative inverse of the polynomial mod x^t
    ///
    /// Done using the extended Euclidean algorithm
    pub fn mul_inverse_mod_t(&self, t: usize) -> Self {
        let ids = self.coeffs.iter().map(|c| c.id()).collect_vec();
        let n_result_coeffs = t;

        let res_coeffs = self.fabric().new_batch_gate_op(
            ids,
            n_result_coeffs, /* output_arity */
            move |args| {
                let x_to_t = x_to_t::<C>(t);

                let self_coeffs = args
                    .into_iter()
                    .map(|res| Scalar::<C>::from(res).inner())
                    .collect_vec();
                let self_poly = DensePolynomial::from_coefficients_vec(self_coeffs);

                // Compute the bezout coefficients of the two polynomials
                let (inverse_poly, _) = Self::compute_bezout_polynomials(&self_poly, &x_to_t);

                // In a polynomial ring, gcd is defined only up to scalar multiplication, so we multiply the result
                // by the inverse of the resultant first coefficient to uniquely define the inverse as f^{-1}(x) such that
                // f * f^{-1}(x) = 1 \in F[x] / (x^t)
                let self_constant_coeff = self_poly.coeffs[0];
                let inverse_constant_coeff = inverse_poly.coeffs[0];
                let leading_coeff_inv = (self_constant_coeff * inverse_constant_coeff)
                    .inverse()
                    .unwrap();

                inverse_poly
                    .coeffs
                    .into_iter()
                    .take(n_result_coeffs)
                    .map(|c| c * leading_coeff_inv)
                    .map(Scalar::new)
                    .map(ResultValue::Scalar)
                    .collect_vec()
            },
        );

        Self::from_coeffs(res_coeffs)
    }

    /// A helper to compute the Bezout coefficients of the two given polynomials
    ///
    /// I.e. for a(x), b(x) as input, we compute f(x), g(x) such that:
    ///     f(x) * a(x) + g(x) * b(x) = gcd(a, b)
    fn compute_bezout_polynomials(
        a: &DensePolynomial<C::ScalarField>,
        b: &DensePolynomial<C::ScalarField>,
    ) -> (
        DensePolynomial<C::ScalarField>,
        DensePolynomial<C::ScalarField>,
    ) {
        if b.is_zero() {
            return (
                DensePolynomial::from_coefficients_vec(vec![C::ScalarField::one()]), // f(x) = 1
                DensePolynomial::zero(),                                             // f(x) = 0
            );
        }

        let a_transformed = DenseOrSparsePolynomial::from(a);
        let b_transformed = DenseOrSparsePolynomial::from(b);
        let (quotient, remainder) = a_transformed.divide_with_q_and_r(&b_transformed).unwrap();

        let (f, g) = Self::compute_bezout_polynomials(b, &remainder);
        let next_g = &f - &(&quotient * &g);

        (g, next_g)
    }
}

impl<C: CurveGroup> Future for DensePolynomialResult<C>
where
    C::ScalarField: Unpin,
{
    type Output = DensePolynomial<C::ScalarField>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut coeffs = Vec::with_capacity(self.coeffs.len());
        for coeff in self.coeffs.iter_mut() {
            let ready_coeff = ready!(coeff.poll_unpin(cx));
            coeffs.push(ready_coeff.inner());
        }

        Poll::Ready(DensePolynomial::from_coefficients_vec(coeffs))
    }
}

// --------------
// | Arithmetic |
// --------------

// --- Addition --- //

impl<C: CurveGroup> Add<&DensePolynomial<C::ScalarField>> for &DensePolynomialResult<C> {
    type Output = DensePolynomialResult<C>;
    fn add(self, rhs: &DensePolynomial<C::ScalarField>) -> Self::Output {
        assert!(!self.coeffs.is_empty(), "cannot add an empty polynomial");
        let fabric = self.coeffs[0].fabric();

        let mut coeffs = Vec::new();
        let max_degree = cmp::max(self.coeffs.len(), rhs.coeffs.len());

        // Pad the coefficients to be of the same length
        let padded_coeffs0 = self
            .coeffs
            .iter()
            .cloned()
            .chain(iter::repeat(fabric.zero()));
        let padded_coeffs1 = rhs
            .coeffs
            .iter()
            .copied()
            .map(Scalar::<C>::new)
            .chain(iter::repeat(Scalar::zero()));

        // Add component-wise
        for (lhs_coeff, rhs_coeff) in padded_coeffs0.zip(padded_coeffs1).take(max_degree) {
            coeffs.push(lhs_coeff + rhs_coeff);
        }

        DensePolynomialResult::from_coeffs(coeffs)
    }
}
impl_borrow_variants!(DensePolynomialResult<C>, Add, add, +, DensePolynomial<C::ScalarField>, C: CurveGroup);
impl_commutative!(DensePolynomialResult<C>, Add, add, +, DensePolynomial<C::ScalarField>, C: CurveGroup);

impl<C: CurveGroup> Add<&DensePolynomialResult<C>> for &DensePolynomialResult<C> {
    type Output = DensePolynomialResult<C>;
    fn add(self, rhs: &DensePolynomialResult<C>) -> Self::Output {
        // We do not pad the coefficients here, it requires fewer gates if we avoid padding
        let mut coeffs = Vec::new();
        let (shorter, longer) = if self.coeffs.len() < rhs.coeffs.len() {
            (&self.coeffs, &rhs.coeffs)
        } else {
            (&rhs.coeffs, &self.coeffs)
        };

        for (i, longer_coeff) in longer.iter().enumerate() {
            let new_coeff = if i < shorter.len() {
                &shorter[i] + longer_coeff
            } else {
                longer_coeff.clone()
            };

            coeffs.push(new_coeff);
        }

        DensePolynomialResult::from_coeffs(coeffs)
    }
}
impl_borrow_variants!(DensePolynomialResult<C>, Add, add, +, DensePolynomialResult<C>, C: CurveGroup);

// --- Negation --- //
impl<C: CurveGroup> Neg for &DensePolynomialResult<C> {
    type Output = DensePolynomialResult<C>;
    fn neg(self) -> Self::Output {
        let mut coeffs = Vec::with_capacity(self.coeffs.len());
        for coeff in self.coeffs.iter() {
            coeffs.push(-coeff);
        }

        DensePolynomialResult::from_coeffs(coeffs)
    }
}
impl_borrow_variants!(DensePolynomialResult<C>, Neg, neg, -, C: CurveGroup);

// --- Subtraction --- //
#[allow(clippy::suspicious_arithmetic_impl)]
impl<C: CurveGroup> Sub<&DensePolynomial<C::ScalarField>> for &DensePolynomialResult<C> {
    type Output = DensePolynomialResult<C>;
    fn sub(self, rhs: &DensePolynomial<C::ScalarField>) -> Self::Output {
        let negated_rhs_coeffs = rhs.coeffs.iter().map(|coeff| -(*coeff)).collect();
        let negated_rhs = DensePolynomial::from_coefficients_vec(negated_rhs_coeffs);

        self + negated_rhs
    }
}
impl_borrow_variants!(DensePolynomialResult<C>, Sub, sub, -, DensePolynomial<C::ScalarField>, C: CurveGroup);

#[allow(clippy::suspicious_arithmetic_impl)]
impl<C: CurveGroup> Sub<&DensePolynomialResult<C>> for &DensePolynomialResult<C> {
    type Output = DensePolynomialResult<C>;
    fn sub(self, rhs: &DensePolynomialResult<C>) -> Self::Output {
        // Negate the rhs then use the `Add` impl
        self + (-rhs)
    }
}

// --- Multiplication --- //

// TODO: For each of the following implementations, we can await all coefficients to be available
// and then perform an FFT-based polynomial multiplication. This is left as an optimization
impl<C: CurveGroup> Mul<&DensePolynomial<C::ScalarField>> for &DensePolynomialResult<C> {
    type Output = DensePolynomialResult<C>;

    fn mul(self, rhs: &DensePolynomial<C::ScalarField>) -> Self::Output {
        let fabric = self.coeffs[0].fabric();

        let mut coeffs = Vec::with_capacity(self.coeffs.len() + rhs.coeffs.len() - 1);
        for _ in 0..self.coeffs.len() + rhs.coeffs.len() - 1 {
            coeffs.push(fabric.zero());
        }

        for (i, lhs_coeff) in self.coeffs.iter().enumerate() {
            for (j, rhs_coeff) in rhs.coeffs.iter().copied().map(Scalar::new).enumerate() {
                coeffs[i + j] = &coeffs[i + j] + lhs_coeff * rhs_coeff;
            }
        }

        DensePolynomialResult::from_coeffs(coeffs)
    }
}
impl_borrow_variants!(DensePolynomialResult<C>, Mul, mul, *, DensePolynomial<C::ScalarField>, C: CurveGroup);
impl_commutative!(DensePolynomialResult<C>, Mul, mul, *, DensePolynomial<C::ScalarField>, C: CurveGroup);

impl<C: CurveGroup> Mul<&DensePolynomialResult<C>> for &DensePolynomialResult<C> {
    type Output = DensePolynomialResult<C>;

    fn mul(self, rhs: &DensePolynomialResult<C>) -> Self::Output {
        let fabric = self.coeffs[0].fabric();

        let mut coeffs = Vec::with_capacity(self.coeffs.len() + rhs.coeffs.len() - 1);
        for _ in 0..self.coeffs.len() + rhs.coeffs.len() - 1 {
            coeffs.push(fabric.zero());
        }

        for (i, lhs_coeff) in self.coeffs.iter().enumerate() {
            for (j, rhs_coeff) in rhs.coeffs.iter().enumerate() {
                coeffs[i + j] = &coeffs[i + j] + lhs_coeff * rhs_coeff;
            }
        }

        DensePolynomialResult::from_coeffs(coeffs)
    }
}
impl_borrow_variants!(DensePolynomialResult<C>, Mul, mul, *, DensePolynomialResult<C>, C: CurveGroup);

// --- Scalar Multiplication --- //

impl<C: CurveGroup> Mul<&Scalar<C>> for &DensePolynomialResult<C> {
    type Output = DensePolynomialResult<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        let new_coeffs = self.coeffs.iter().map(|coeff| coeff * rhs).collect_vec();
        DensePolynomialResult::from_coeffs(new_coeffs)
    }
}
impl_borrow_variants!(DensePolynomialResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
impl_commutative!(DensePolynomialResult<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&ScalarResult<C>> for &DensePolynomialResult<C> {
    type Output = DensePolynomialResult<C>;

    fn mul(self, rhs: &ScalarResult<C>) -> Self::Output {
        let new_coeffs = self.coeffs.iter().map(|coeff| coeff * rhs).collect_vec();
        DensePolynomialResult::from_coeffs(new_coeffs)
    }
}
impl_borrow_variants!(DensePolynomialResult<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);
impl_commutative!(DensePolynomialResult<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&AuthenticatedScalarResult<C>> for &DensePolynomialResult<C> {
    type Output = AuthenticatedDensePoly<C>;

    fn mul(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        let new_coeffs = self.coeffs.iter().map(|coeff| coeff * rhs).collect_vec();
        AuthenticatedDensePoly::from_coeffs(new_coeffs)
    }
}
impl_borrow_variants!(DensePolynomialResult<C>, Mul, mul, *, AuthenticatedScalarResult<C>, Output=AuthenticatedDensePoly<C>, C: CurveGroup);
impl_commutative!(DensePolynomialResult<C>, Mul, mul, *, AuthenticatedScalarResult<C>, Output=AuthenticatedDensePoly<C>, C: CurveGroup);

// --- Division --- //

// Floor division, i.e. truncated remainder
#[allow(clippy::suspicious_arithmetic_impl)]
impl<C: CurveGroup> Div<&DensePolynomialResult<C>> for &DensePolynomialResult<C> {
    type Output = DensePolynomialResult<C>;

    fn div(self, rhs: &DensePolynomialResult<C>) -> Self::Output {
        let fabric = self.coeffs[0].fabric();
        if self.degree() < rhs.degree() {
            return DensePolynomialResult::zero(fabric);
        }

        let n_lhs_coeffs = self.coeffs.len();
        let n_rhs_coeffs = rhs.coeffs.len();

        let mut deps = self.coeffs.iter().map(|coeff| coeff.id()).collect_vec();
        deps.extend(rhs.coeffs.iter().map(|coeff| coeff.id()));

        // Allocate a gate to return the coefficients of the quotient polynomial
        let result_degree = self.degree().saturating_sub(rhs.degree());
        let coeff_results =
            fabric.new_batch_gate_op(deps, result_degree + 1 /* arity */, move |mut args| {
                let lhs_coeffs: Vec<C::ScalarField> = args
                    .drain(..n_lhs_coeffs)
                    .map(|res| Scalar::<C>::from(res).inner())
                    .collect_vec();
                let rhs_coeffs = args
                    .drain(..n_rhs_coeffs)
                    .map(|res| Scalar::<C>::from(res).inner())
                    .collect_vec();

                let lhs_poly = DensePolynomial::from_coefficients_vec(lhs_coeffs);
                let rhs_poly = DensePolynomial::from_coefficients_vec(rhs_coeffs);

                let res = &lhs_poly / &rhs_poly;
                res.coeffs
                    .iter()
                    .map(|coeff| ResultValue::Scalar(Scalar::new(*coeff)))
                    .collect_vec()
            });

        DensePolynomialResult::from_coeffs(coeff_results)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use ark_ff::{One, Zero};
    use ark_poly::Polynomial;
    use itertools::Itertools;
    use rand::{thread_rng, Rng};

    use crate::{
        algebra::{
            poly_test_helpers::{allocate_poly, random_poly},
            Scalar,
        },
        test_helpers::execute_mock_mpc,
        PARTY0,
    };

    /// Degree bound on polynomials used for testing
    const DEGREE_BOUND: usize = 100;

    /// Test addition between a constant and result polynomial
    ///
    /// That is, we only allocate one of the polynomials
    #[tokio::test]
    async fn test_constant_poly_add() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 + &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let poly1 = allocate_poly(&poly1, &fabric);
                let res = &poly1 + &poly2;

                res.await
            }
        })
        .await;

        assert_eq!(res, expected_res);
    }

    /// Test addition between two allocated polynomials
    #[tokio::test]
    async fn test_poly_add() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 + &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let poly1 = allocate_poly(&poly1, &fabric);
                let poly2 = allocate_poly(&poly2, &fabric);
                let res = &poly1 + &poly2;

                res.await
            }
        })
        .await;

        assert_eq!(res, expected_res);
    }

    /// Test subtraction between a constant and result polynomial
    #[tokio::test]
    async fn test_poly_sub_constant() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 - &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let poly1 = allocate_poly(&poly1, &fabric);
                let res = &poly1 - &poly2;

                res.await
            }
        })
        .await;

        assert_eq!(res, expected_res);
    }

    /// Tests subtraction between two allocated polynomials
    #[tokio::test]
    async fn test_poly_sub() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 - &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let poly1 = allocate_poly(&poly1, &fabric);
                let poly2 = allocate_poly(&poly2, &fabric);
                let res = &poly1 - &poly2;

                res.await
            }
        })
        .await;

        assert_eq!(res, expected_res);
    }

    /// Tests multiplication between a constant and result polynomial
    #[tokio::test]
    async fn test_poly_mul_constant() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 * &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let poly1 = allocate_poly(&poly1, &fabric);
                let res = &poly1 * &poly2;

                res.await
            }
        })
        .await;

        assert_eq!(res, expected_res);
    }

    /// Tests multiplication between two allocated polynomials
    #[tokio::test]
    async fn test_poly_mul() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 * &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let poly1 = allocate_poly(&poly1, &fabric);
                let poly2 = allocate_poly(&poly2, &fabric);
                let res = &poly1 * &poly2;

                res.await
            }
        })
        .await;

        assert_eq!(res, expected_res);
    }

    /// Tests dividing one polynomial by another
    #[tokio::test]
    async fn test_poly_div() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 / &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let poly1 = allocate_poly(&poly1, &fabric);
                let poly2 = allocate_poly(&poly2, &fabric);
                let res = &poly1 / &poly2;

                res.await
            }
        })
        .await;

        assert_eq!(res, expected_res);
    }

    /// Tests scalar multiplication with a constant value
    #[tokio::test]
    async fn test_scalar_mul_constant() {
        let poly = random_poly(DEGREE_BOUND);

        let mut rng = thread_rng();
        let scaling_factor = Scalar::random(&mut rng);

        let expected_res = &poly * scaling_factor.inner();

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly = poly.clone();
            async move {
                let poly = allocate_poly(&poly, &fabric);

                (poly * scaling_factor).await
            }
        })
        .await;

        assert_eq!(res, expected_res);
    }

    /// Tests scalar multiplication with a public result value
    #[tokio::test]
    async fn test_scalar_mul() {
        let poly = random_poly(DEGREE_BOUND);

        let mut rng = thread_rng();
        let scaling_factor = Scalar::random(&mut rng);

        let expected_res = &poly * scaling_factor.inner();

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly = poly.clone();
            async move {
                let poly = allocate_poly(&poly, &fabric);
                let scaling_factor = fabric.allocate_scalar(scaling_factor);

                (poly * scaling_factor).await
            }
        })
        .await;

        assert_eq!(res, expected_res);
    }

    /// Tests scalar multiplication with a shared result value
    #[tokio::test]
    async fn test_scalar_mul_shared() {
        let poly = random_poly(DEGREE_BOUND);

        let mut rng = thread_rng();
        let scaling_factor = Scalar::random(&mut rng);

        let expected_res = &poly * scaling_factor.inner();

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly = poly.clone();
            async move {
                let poly = allocate_poly(&poly, &fabric);
                let scaling_factor = fabric.share_scalar(scaling_factor, PARTY0);

                (poly * scaling_factor).open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected_res);
    }

    /// Test evaluating a polynomial in the computation graph
    #[tokio::test]
    async fn test_eval() {
        let poly = random_poly(DEGREE_BOUND);

        let mut rng = thread_rng();
        let eval_point = Scalar::random(&mut rng);

        let expected_eval = poly.evaluate(&eval_point.inner());

        let (eval, _) = execute_mock_mpc(|fabric| {
            let poly = poly.clone();
            async move {
                let point_res = fabric.allocate_scalar(eval_point);
                let poly = allocate_poly(&poly, &fabric);

                poly.eval(point_res).await
            }
        })
        .await;

        assert_eq!(eval.inner(), expected_eval);
    }

    /// Tests computing the modular inverse of a polynomial
    #[tokio::test]
    async fn test_mod_inv() {
        let poly = random_poly(DEGREE_BOUND);

        let mut rng = thread_rng();
        let t = rng.gen_range(1..(DEGREE_BOUND * 2));

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly = poly.clone();
            async move {
                let poly = allocate_poly(&poly, &fabric);

                poly.mul_inverse_mod_t(t).await
            }
        })
        .await;

        // Check that the result is correct
        let inverted = &poly * &res;
        let mut first_t_coeffs = inverted.coeffs.into_iter().take(t).collect_vec();

        assert!(first_t_coeffs.remove(0).is_one());
        assert!(first_t_coeffs.into_iter().all(|coeff| coeff.is_zero()));
    }
}
