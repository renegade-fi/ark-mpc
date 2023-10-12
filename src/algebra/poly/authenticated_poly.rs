//! An authenticated polynomial over a `CurveGroup`'s scalar field
//!
//! Modeled after the `ark_poly::DensePolynomial` type, but allocated in an MPC fabric

use std::{
    cmp, iter,
    ops::{Add, Mul, Neg, Sub},
    pin::Pin,
    task::{Context, Poll},
};

use ark_ec::CurveGroup;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use futures::{ready, Future, FutureExt};
use itertools::Itertools;

use crate::{
    algebra::{
        macros::{impl_borrow_variants, impl_commutative},
        AuthenticatedScalarOpenResult, AuthenticatedScalarResult, Scalar, ScalarResult,
    },
    error::MpcError,
    MpcFabric,
};

use super::DensePolynomialResult;

/// An authenticated polynomial; i.e. a polynomial in which the coefficients are secret
/// shared between parties
///
/// This is modeled after the `ark_poly::DensePolynomial` [source](https://github.com/arkworks-rs/algebra/blob/master/poly/src/polynomial/univariate/dense.rs#L22)
#[derive(Debug, Clone)]
pub struct AuthenticatedDensePoly<C: CurveGroup> {
    /// A vector of coefficients, the coefficient for `x^i` is stored at index `i`
    pub coeffs: Vec<AuthenticatedScalarResult<C>>,
}

impl<C: CurveGroup> AuthenticatedDensePoly<C> {
    /// Constructor
    pub fn from_coeffs(coeffs: Vec<AuthenticatedScalarResult<C>>) -> Self {
        assert!(
            !coeffs.is_empty(),
            "AuthenticatedDensePoly must have at least one coefficient"
        );
        Self { coeffs }
    }

    /// Allocate the zero polynomial (additive identity) in the given fabric
    pub fn zero(fabric: &MpcFabric<C>) -> Self {
        let coeffs = vec![fabric.zero_authenticated()];
        Self::from_coeffs(coeffs)
    }

    /// Allocate the one polynomial (multiplicative identity) in the given fabric
    pub fn one(fabric: &MpcFabric<C>) -> Self {
        let coeffs = vec![fabric.one_authenticated()];
        Self::from_coeffs(coeffs)
    }

    /// Get the degree of the represented polynomial
    pub fn degree(&self) -> usize {
        self.coeffs.len() - 1
    }

    /// Evaluate the polynomial at a given point
    ///
    /// TODO: Opt for a more efficient implementation that allocates fewer gates, i.e.
    /// by awaiting all results then creating the evaluation
    pub fn eval(&self, x: &ScalarResult<C>) -> AuthenticatedScalarResult<C> {
        // Evaluate the polynomial at the given point
        let mut result = x.fabric().zero_authenticated();
        for coeff in self.coeffs.iter().rev() {
            result = result * x + coeff;
        }

        result
    }

    /// Open the polynomial to the base type `DensePolynomial`
    pub fn open(&self) -> DensePolynomialResult<C> {
        // Open the coeffs directly
        let open_coeffs = AuthenticatedScalarResult::open_batch(&self.coeffs);
        DensePolynomialResult::from_coeffs(open_coeffs)
    }

    /// Open the polynomial and authenticate the shares
    pub fn open_authenticated(&self) -> AuthenticatedDensePolyOpenResult<C> {
        // Open the coeffs directly
        let coeff_open_results = AuthenticatedScalarResult::open_authenticated_batch(&self.coeffs);
        AuthenticatedDensePolyOpenResult { coeff_open_results }
    }
}

/// The result of opening an `AuthenticatedDensePoly` to its base type
///
/// Encapsulates a potential error in opening the polynomial
pub struct AuthenticatedDensePolyOpenResult<C: CurveGroup> {
    /// The opening results of each coefficient
    pub coeff_open_results: Vec<AuthenticatedScalarOpenResult<C>>,
}

impl<C: CurveGroup> Future for AuthenticatedDensePolyOpenResult<C>
where
    C::ScalarField: Unpin,
{
    type Output = Result<DensePolynomial<C::ScalarField>, MpcError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Poll each coeff open result
        let mut coeffs = Vec::new();
        for coeff_open_result in self.coeff_open_results.iter_mut() {
            match ready!(coeff_open_result.poll_unpin(cx)) {
                Ok(coeff) => coeffs.push(coeff),
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        // Map all coefficients back into their Arkworks types
        let inner_coeffs = coeffs
            .into_iter()
            .map(|coeff| coeff.inner())
            .collect::<Vec<_>>();

        Poll::Ready(Ok(DensePolynomial::from_coefficients_vec(inner_coeffs)))
    }
}

// --------------
// | Arithmetic |
// --------------

// --- Addition --- //
impl<C: CurveGroup> Add<&DensePolynomial<C::ScalarField>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;
    fn add(self, rhs: &DensePolynomial<C::ScalarField>) -> Self::Output {
        assert!(!self.coeffs.is_empty(), "cannot add to an empty polynomial");
        let fabric = self.coeffs[0].fabric();

        let max_degree = cmp::max(self.degree(), rhs.degree());

        // Pad the coefficients to the same length
        let padded_coeffs0 = self
            .coeffs
            .iter()
            .cloned()
            .chain(iter::repeat(fabric.zero_authenticated()));
        let padded_coeffs1 = rhs
            .coeffs
            .iter()
            .copied()
            .map(Scalar::<C>::new)
            .chain(iter::repeat(Scalar::zero()));

        // Add the coefficients component-wise
        let mut coeffs = Vec::new();
        for (lhs_coeff, rhs_coeff) in padded_coeffs0.zip(padded_coeffs1).take(max_degree + 1) {
            coeffs.push(lhs_coeff + rhs_coeff);
        }

        AuthenticatedDensePoly::from_coeffs(coeffs)
    }
}
impl_borrow_variants!(AuthenticatedDensePoly<C>, Add, add, +, DensePolynomial<C::ScalarField>, C: CurveGroup);
impl_commutative!(AuthenticatedDensePoly<C>, Add, add, +, DensePolynomial<C::ScalarField>, C: CurveGroup);

impl<C: CurveGroup> Add<&AuthenticatedDensePoly<C>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;
    fn add(self, rhs: &AuthenticatedDensePoly<C>) -> Self::Output {
        // Don't pad the coefficients as it requires fewer gates when we don't have to
        let (shorter, longer) = if self.coeffs.len() < rhs.coeffs.len() {
            (&self.coeffs, &rhs.coeffs)
        } else {
            (&rhs.coeffs, &self.coeffs)
        };

        let mut coeffs = Vec::new();
        for (i, longer_coeff) in longer.iter().enumerate() {
            let new_coeff = if i < shorter.len() {
                &shorter[i] + longer_coeff
            } else {
                longer_coeff.clone()
            };
            coeffs.push(new_coeff);
        }

        AuthenticatedDensePoly::from_coeffs(coeffs)
    }
}
impl_borrow_variants!(AuthenticatedDensePoly<C>, Add, add, +, AuthenticatedDensePoly<C>, C: CurveGroup);

// --- Negation --- //
impl<C: CurveGroup> Neg for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;

    fn neg(self) -> Self::Output {
        let coeffs = self
            .coeffs
            .iter()
            .map(|coeff| coeff.neg())
            .collect::<Vec<_>>();

        AuthenticatedDensePoly::from_coeffs(coeffs)
    }
}
impl_borrow_variants!(AuthenticatedDensePoly<C>, Neg, neg, -, C: CurveGroup);

// --- Subtraction --- //
#[allow(clippy::suspicious_arithmetic_impl)]
impl<C: CurveGroup> Sub<&DensePolynomial<C::ScalarField>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;

    fn sub(self, rhs: &DensePolynomial<C::ScalarField>) -> Self::Output {
        let negated_rhs_coeffs = rhs.coeffs.iter().map(|coeff| coeff.neg()).collect_vec();
        self + DensePolynomial::from_coefficients_vec(negated_rhs_coeffs)
    }
}
impl_borrow_variants!(AuthenticatedDensePoly<C>, Sub, sub, -, DensePolynomial<C::ScalarField>, C: CurveGroup);

#[allow(clippy::suspicious_arithmetic_impl)]
impl<C: CurveGroup> Sub<&AuthenticatedDensePoly<C>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;

    fn sub(self, rhs: &AuthenticatedDensePoly<C>) -> Self::Output {
        self + (-rhs)
    }
}
impl_borrow_variants!(AuthenticatedDensePoly<C>, Sub, sub, -, AuthenticatedDensePoly<C>, C: CurveGroup);

// --- Multiplication --- //
// TODO: We can use an FFT-based approach here, it takes a bit more care because evaluations needed
// are more expensive, but it could provide a performance boost
//
// For now we leave this as an optimization, the current implementation can be executed in one round,
// although with many gates
impl<C: CurveGroup> Mul<&DensePolynomial<C::ScalarField>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;

    fn mul(self, rhs: &DensePolynomial<C::ScalarField>) -> Self::Output {
        assert!(
            !self.coeffs.is_empty(),
            "cannot multiply an empty polynomial"
        );
        let fabric = self.coeffs[0].fabric();

        // Setup the zero coefficients
        let result_degree = self.degree() + rhs.degree();
        let mut coeffs = Vec::with_capacity(result_degree + 1);
        for _ in 0..(result_degree + 1) {
            coeffs.push(fabric.zero_authenticated());
        }

        // Multiply the coefficients component-wise
        for (i, lhs_coeff) in self.coeffs.iter().enumerate() {
            for (j, rhs_coeff) in rhs.coeffs.iter().enumerate() {
                coeffs[i + j] = &coeffs[i + j] + (lhs_coeff * Scalar::<C>::new(*rhs_coeff));
            }
        }

        AuthenticatedDensePoly::from_coeffs(coeffs)
    }
}

impl<C: CurveGroup> Mul<&AuthenticatedDensePoly<C>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;

    fn mul(self, rhs: &AuthenticatedDensePoly<C>) -> Self::Output {
        assert!(
            !self.coeffs.is_empty(),
            "cannot multiply an empty polynomial"
        );
        let fabric = self.coeffs[0].fabric();

        // Setup the zero coefficients
        let result_degree = self.degree() + rhs.degree();
        let mut coeffs = Vec::with_capacity(result_degree + 1);
        for _ in 0..(result_degree + 1) {
            coeffs.push(fabric.zero_authenticated());
        }

        // Multiply the coefficients component-wise
        for (i, lhs_coeff) in self.coeffs.iter().enumerate() {
            for (j, rhs_coeff) in rhs.coeffs.iter().enumerate() {
                coeffs[i + j] = &coeffs[i + j] + (lhs_coeff * rhs_coeff);
            }
        }

        AuthenticatedDensePoly::from_coeffs(coeffs)
    }
}

#[cfg(test)]
mod test {
    use ark_poly::{univariate::DensePolynomial, Polynomial};
    use itertools::Itertools;
    use rand::thread_rng;

    use crate::{
        algebra::{
            poly_test_helpers::{random_poly, TestPolyField},
            Scalar,
        },
        network::PartyId,
        test_helpers::{execute_mock_mpc, TestCurve},
        MpcFabric, PARTY0,
    };

    use super::AuthenticatedDensePoly;

    /// The degree bound used for testing
    const DEGREE_BOUND: usize = 100;

    /// Allocate an authenticated polynomial in the given fabric
    fn share_poly(
        poly: DensePolynomial<TestPolyField>,
        sender: PartyId,
        fabric: &MpcFabric<TestCurve>,
    ) -> AuthenticatedDensePoly<TestCurve> {
        let coeffs = poly.coeffs.iter().copied().map(Scalar::new).collect_vec();
        let shared_coeffs = fabric.batch_share_scalar(coeffs, sender);

        AuthenticatedDensePoly::from_coeffs(shared_coeffs)
    }

    /// Test evaluating a polynomial at a given point
    #[tokio::test]
    async fn test_eval() {
        let mut rng = thread_rng();
        let poly = random_poly(DEGREE_BOUND);
        let point = Scalar::random(&mut rng);

        let expected_res = poly.evaluate(&point.inner());

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly = poly.clone();
            async move {
                let shared_poly = share_poly(poly, PARTY0, &fabric);
                let point = fabric.allocate_scalar(point);

                shared_poly.eval(&point).open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Scalar::new(expected_res));
    }

    /// Tests adding a constant polynomial to an authenticated polynomial
    #[tokio::test]
    async fn test_add_constant_poly() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 + &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let shared_poly1 = share_poly(poly1, PARTY0, &fabric);

                let res = &shared_poly1 + &poly2;
                res.open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected_res);
    }

    /// Tests adding two authenticated polynomials
    #[tokio::test]
    async fn test_add_poly() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 + &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let shared_poly1 = share_poly(poly1, PARTY0, &fabric);
                let shared_poly2 = share_poly(poly2, PARTY0, &fabric);

                let res = &shared_poly1 + &shared_poly2;
                res.open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected_res);
    }

    /// Tests subtracting a constant polynomial from an authenticated polynomial
    #[tokio::test]
    async fn test_subtract_constant_poly() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 - &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let shared_poly1 = share_poly(poly1, PARTY0, &fabric);

                let res = &shared_poly1 - &poly2;
                res.open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected_res);
    }

    /// Tests subtracting two authenticated polynomials
    #[tokio::test]
    async fn test_subtract_poly() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 - &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let shared_poly1 = share_poly(poly1, PARTY0, &fabric);
                let shared_poly2 = share_poly(poly2, PARTY0, &fabric);

                let res = &shared_poly1 - &shared_poly2;
                res.open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected_res);
    }

    /// Test multiplying a constant polynomial with an authenticated polynomial
    #[tokio::test]
    async fn test_mul_constant_polynomial() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 * &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let shared_poly1 = share_poly(poly1, PARTY0, &fabric);

                let res = &shared_poly1 * &poly2;
                res.open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected_res);
    }

    /// Test multiplying two authenticated polynomials
    #[tokio::test]
    async fn test_mul_polynomial() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 * &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let shared_poly1 = share_poly(poly1, PARTY0, &fabric);
                let shared_poly2 = share_poly(poly2, PARTY0, &fabric);

                let res = &shared_poly1 * &shared_poly2;
                res.open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected_res);
    }
}
