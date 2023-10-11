//! Defines the base polynomial representation, modeled after the `ark_poly::DensePolynomial` type

use std::{
    cmp, iter,
    ops::{Add, Mul, Neg, Sub},
    pin::Pin,
    task::{Context, Poll},
};

use ark_ec::CurveGroup;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use futures::FutureExt;
use futures::{ready, Future};

use crate::{
    algebra::{
        macros::{impl_borrow_variants, impl_commutative},
        Scalar, ScalarResult,
    },
    MpcFabric,
};

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
    pub fn zero(fabric: MpcFabric<C>) -> Self {
        Self::from_coeffs(vec![fabric.zero()])
    }

    /// Construct the one polynomial (multiplicative identity)
    pub fn one(fabric: MpcFabric<C>) -> Self {
        Self::from_coeffs(vec![fabric.one()])
    }

    /// Returns the degree of the polynomial
    pub fn degree(&self) -> usize {
        self.coeffs.len() - 1
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

#[cfg(test)]
mod test {
    use ark_ec::Group;
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::UniformRand;
    use rand::{thread_rng, Rng};

    use crate::{
        algebra::Scalar,
        test_helpers::{execute_mock_mpc, TestCurve},
        MpcFabric,
    };

    use super::DensePolynomialResult;

    /// Degree bound on polynomials used for testing
    const DEGREE_BOUND: usize = 100;
    /// The scalar field testing polynomials are defined over
    type TestPolyField = <TestCurve as Group>::ScalarField;

    /// Generate a random polynomial given a degree bound
    fn random_poly(degree_bound: usize) -> DensePolynomial<TestPolyField> {
        let mut rng = thread_rng();

        // Sample a random degree below the bound
        let degree = rng.gen_range(1..degree_bound);
        let mut coeffs = Vec::with_capacity(degree + 1);
        for _ in 0..degree {
            // Sample a random coefficient
            coeffs.push(<TestCurve as Group>::ScalarField::rand(&mut rng));
        }

        DensePolynomial::from_coefficients_vec(coeffs)
    }

    /// Allocate a polynomial in an MPC fabric
    fn allocate_poly(
        poly: &DensePolynomial<TestPolyField>,
        fabric: &MpcFabric<TestCurve>,
    ) -> DensePolynomialResult<TestCurve> {
        let mut allocated_coeffs = Vec::with_capacity(poly.degree() + 1);
        for coeff in poly.coeffs().iter() {
            allocated_coeffs.push(fabric.allocate_scalar(Scalar::new(*coeff)));
        }

        DensePolynomialResult::from_coeffs(allocated_coeffs)
    }

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
}
