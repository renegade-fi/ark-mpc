//! An authenticated polynomial over a `CurveGroup`'s scalar field
//!
//! Modeled after the `ark_poly::DensePolynomial` type, but allocated in an MPC fabric

use std::{
    cmp, iter,
    ops::{Add, Div, Mul, Neg, Sub},
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
#[derive(Debug, Clone, Default)]
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

    /// Sample a random polynomial of given degree
    pub fn random(d: usize, fabric: &MpcFabric<C>) -> Self {
        let coeffs = fabric.random_shared_scalars_authenticated(d + 1);
        Self::from_coeffs(coeffs)
    }

    /// Get the fabric underlying the polynomial
    pub fn fabric(&self) -> &MpcFabric<C> {
        self.coeffs[0].fabric()
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

/// Inversion and division helpers
impl<C: CurveGroup> AuthenticatedDensePoly<C> {
    /// Reduce a given polynomial mod x^n
    ///
    /// For a modulus of this form, this is equivalent to truncating the coefficients
    pub fn mod_xn(&self, n: usize) -> Self {
        let mut coeffs = self.coeffs.clone();
        coeffs.truncate(n);

        Self::from_coeffs(coeffs)
    }

    /// Reverse the coefficients of the polynomial and return a new polynomial
    ///
    /// This is useful when implementing division between authenticated polynomials as per:
    ///     https://iacr.org/archive/pkc2006/39580045/39580045.pdf
    /// Effectively, for a given polynomial a(x), the operation rev(a) returns the polynomial:
    ///     rev(a)(x) = x^deg(a) * a(1/x)
    /// which is emulated by reversing the coefficients directly.
    ///
    /// See the division docstring below for a more detailed explanation
    pub fn rev(&self) -> Self {
        let mut coeffs = self.coeffs.clone();
        coeffs.reverse();

        Self::from_coeffs(coeffs)
    }

    /// Get a random, shared masking polynomial of degree `n`
    pub fn random_polynomial(n: usize, fabric: &MpcFabric<C>) -> Self {
        let coeffs = fabric.random_shared_scalars_authenticated(n + 1);
        Self::from_coeffs(coeffs)
    }

    /// Compute the multiplicative inverse of a polynomial in the quotient ring F[x] / (x^t)
    ///
    /// Uses an extension of the inverse method defined in:
    ///     https://dl.acm.org/doi/pdf/10.1145/72981.72995
    pub fn mul_inverse_mod_t(&self, t: usize) -> Self {
        let fabric = self.fabric();
        let masking_poly = Self::random_polynomial(t /* degree */, fabric);

        // Mask the polynomial and open the result
        let masked_poly = (&masking_poly * self).open_authenticated();

        // Invert the public, masked polynomial without interaction
        let masked_poly_res = DensePolynomialResult::from_coeffs(
            masked_poly
                .coeff_open_results
                .into_iter()
                .map(|c| c.value)
                .collect_vec(),
        );
        let inverted_masked_poly = masked_poly_res.mul_inverse_mod_t(t);

        // Multiply out this inversion with the masking polynomial to cancel the masking term
        // and reduce modulo x^t
        let res = &inverted_masked_poly * &masking_poly;
        res.mod_xn(t)
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

impl<C: CurveGroup> Add<&DensePolynomialResult<C>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;
    fn add(self, rhs: &DensePolynomialResult<C>) -> Self::Output {
        assert!(!self.coeffs.is_empty(), "cannot add to an empty polynomial");

        // Pad both polynomials to the same length
        let n_coeffs = cmp::max(self.coeffs.len(), rhs.coeffs.len());
        let zero = self.fabric().zero();
        let zero_authenticated = self.fabric().zero_authenticated();

        let padded_lhs = self
            .coeffs
            .iter()
            .chain(iter::repeat(&zero_authenticated))
            .take(n_coeffs);
        let padded_rhs = rhs.coeffs.iter().chain(iter::repeat(&zero)).take(n_coeffs);

        // Add the coefficients component-wise
        let mut coeffs = Vec::with_capacity(n_coeffs);
        for (lhs_coeff, rhs_coeff) in padded_lhs.zip(padded_rhs) {
            coeffs.push(lhs_coeff + rhs_coeff);
        }

        AuthenticatedDensePoly::from_coeffs(coeffs)
    }
}
impl_borrow_variants!(AuthenticatedDensePoly<C>, Add, add, +, DensePolynomialResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedDensePoly<C>, Add, add, +, DensePolynomialResult<C>, C: CurveGroup);

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

impl<C: CurveGroup> Mul<&DensePolynomialResult<C>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;

    fn mul(self, rhs: &DensePolynomialResult<C>) -> Self::Output {
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
impl_borrow_variants!(AuthenticatedDensePoly<C>, Mul, mul, *, DensePolynomialResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedDensePoly<C>, Mul, mul, *, DensePolynomialResult<C>, C: CurveGroup);

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

// --- Scalar Multiplication --- //

impl<C: CurveGroup> Mul<&Scalar<C>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        let new_coeffs = self.coeffs.iter().map(|coeff| coeff * rhs).collect_vec();
        AuthenticatedDensePoly::from_coeffs(new_coeffs)
    }
}
impl_borrow_variants!(AuthenticatedDensePoly<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
impl_commutative!(AuthenticatedDensePoly<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&ScalarResult<C>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;

    fn mul(self, rhs: &ScalarResult<C>) -> Self::Output {
        let new_coeffs = self.coeffs.iter().map(|coeff| coeff * rhs).collect_vec();
        AuthenticatedDensePoly::from_coeffs(new_coeffs)
    }
}
impl_borrow_variants!(AuthenticatedDensePoly<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedDensePoly<C>, Mul, mul, *, ScalarResult<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&AuthenticatedScalarResult<C>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;

    fn mul(self, rhs: &AuthenticatedScalarResult<C>) -> Self::Output {
        let new_coeffs = self.coeffs.iter().map(|coeff| coeff * rhs).collect_vec();
        AuthenticatedDensePoly::from_coeffs(new_coeffs)
    }
}
impl_borrow_variants!(AuthenticatedDensePoly<C>, Mul, mul, *, AuthenticatedScalarResult<C>, C: CurveGroup);
impl_commutative!(AuthenticatedDensePoly<C>, Mul, mul, *, AuthenticatedScalarResult<C>, C: CurveGroup);

// --- Division --- //
/// Given a public divisor b(x) and shared dividend a(x) = a_1(x) + a_2(x) for party shares a_1, a_2
/// We can divide each share locally to obtain a secret sharing of \floor{a(x) / b(x)}
///
/// To see this, consider that a_1(x) = q_1(x)b(x) + r_1(x) and a_2(x) = q_2(x)b(x) + r_2(x) where:
///     - deg(q_1) = deg(a_1) - deg(b)
///     - deg(q_2) = deg(a_2) - deg(b)
///     - deg(r_1) < deg(b)
///     - deg(r_2) < deg(b)
/// The floor division operator for a(x), b(x) returns q(x) such that there exists r(x): deg(r) < deg(b)
/// where a(x) = q(x)b(x) + r(x)
/// Note that a_1(x) + a_2(x) = (q_1(x) + q_2(x))b(x) + r_1(x) + r_2(x), where of course
/// deg(r_1 + r_2) < deg(b), so \floor{a(x) / b(x)} = q_1(x) + q_2(x); making q_1, q_2 additive
/// secret shares of the result as desired
impl<C: CurveGroup> Div<&DensePolynomialResult<C>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;

    fn div(self, rhs: &DensePolynomialResult<C>) -> Self::Output {
        // We cannot break early if the remainder is exhausted because this will cause the gate
        // sequencing to differ between parties in the MPC. Instead we execute the whole computation on
        // both ends of the MPC
        assert!(!rhs.coeffs.is_empty(), "cannot divide by zero polynomial");
        let fabric = self.coeffs[0].fabric();

        let quotient_degree = self.degree().saturating_sub(rhs.degree());
        if quotient_degree == 0 {
            return AuthenticatedDensePoly::zero(fabric);
        }

        let mut remainder = self.clone();
        let mut quotient_coeffs = fabric.zeros_authenticated(quotient_degree + 1);

        let divisor_leading_inverse = rhs.coeffs.last().unwrap().inverse();
        for deg in (0..=quotient_degree).rev() {
            // Compute the quotient coefficient for this round
            let remainder_leading_coeff = remainder.coeffs.last().unwrap();
            let next_quotient_coeff = remainder_leading_coeff * &divisor_leading_inverse;

            // Update the remainder and record the coefficient
            for (i, divisor_coeff) in rhs.coeffs.iter().enumerate() {
                let remainder_ind = deg + i;
                remainder.coeffs[remainder_ind] =
                    &remainder.coeffs[remainder_ind] - divisor_coeff * &next_quotient_coeff;
            }

            quotient_coeffs[deg] = next_quotient_coeff;

            // Pop the leading coefficient (now zero) from the remainder
            remainder.coeffs.pop();
        }

        AuthenticatedDensePoly::from_coeffs(quotient_coeffs)
    }
}
impl_borrow_variants!(AuthenticatedDensePoly<C>, Div, div, /, DensePolynomialResult<C>, C: CurveGroup);

/// Authenticated division, i.e. division in which the divisor is a secret shared polynomial
///
/// We follow the approach of: https://iacr.org/archive/pkc2006/39580045/39580045.pdf (Section 4)
///
/// To see why this method holds, consider the `rev` operation for a polynomial a(x):
///     rev(a) = x^deg(a) * a(1/x)
/// Note that this operation is equivalent to reversing the coefficients of a(x)
/// For f(x) / g(x) where deg(f) = n, deg(g) = m, the objective of a division with
/// remainder algorithm is to solve:
///     f(x) = g(x)q(x) + r(x)
/// for q(x), r(x) uniquely where deg(r) < deg(g).
///
/// We could solve for q(x) easily if:
///     1. We could "mod out" r(x) and
///     2. If g^{-1}(x) exists
/// The rev operator provides a transformation that makes both of these true:
///     rev(f) = rev(g) * rev(q) + x^{n - m + 1} * rev(r)
/// Again, we have used the `rev` operator to reverse the coefficients of each polynomial
/// so that the leading coefficients are those of r(x). Now we can "mod out" the highest
/// terms to get:
///     rev(f) = rev(g) * rev(q) mod x^{n - m + 1}
/// And now that we are working in the quotient ring F[x] / (x^{n - m + 1}), we can be sure
/// that rev(g)^{-1}(x) exists if its lowest degree coefficient (constant coefficient) is non-zero.
/// For random (blinded) polynomials, this is true with probability 1 - 1/p.
///
/// So we:
///     1. apply the `rev` transformation,
///     2. mod out rev{r} and solve for rev(q)
///     3. undo the `rev` transformation to get q(x)
///     4. solve for r(x) = f(x) - q(x)g(x), though for floor division we skip this step
impl<C: CurveGroup> Div<&AuthenticatedDensePoly<C>> for &AuthenticatedDensePoly<C> {
    type Output = AuthenticatedDensePoly<C>;

    // Let f = self, g = rhs
    fn div(self, rhs: &AuthenticatedDensePoly<C>) -> Self::Output {
        let n = self.degree();
        let m = rhs.degree();
        if n < m {
            return AuthenticatedDensePoly::zero(self.fabric());
        }

        let modulus = n - m + 1;

        // Apply the rev transformation
        let rev_f = self.rev();
        let rev_g = rhs.rev();

        // Invert `rev_g` in the quotient ring
        let rev_g_inv = rev_g.mul_inverse_mod_t(modulus);

        // Compute rev_f * rev_g_inv and "mod out" rev_r; what is left is `rev_q`
        let rev_q = (&rev_f * &rev_g_inv).mod_xn(modulus);

        // Undo the `rev` transformation
        rev_q.rev()
    }
}
impl_borrow_variants!(AuthenticatedDensePoly<C>, Div, div, /, AuthenticatedDensePoly<C>, C: CurveGroup);

#[cfg(test)]
mod test {
    use ark_poly::Polynomial;
    use rand::thread_rng;

    use crate::{
        algebra::{
            poly_test_helpers::{allocate_poly, random_poly, share_poly},
            Scalar,
        },
        test_helpers::execute_mock_mpc,
        PARTY0, PARTY1,
    };

    /// The degree bound used for testing
    const DEGREE_BOUND: usize = 100;

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

    /// Tests adding a public polynomial to an authenticated polynomial
    #[tokio::test]
    async fn test_add_public_poly() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 + &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let shared_poly1 = share_poly(poly1, PARTY0, &fabric);
                let poly2 = allocate_poly(&poly2, &fabric);

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

    /// Tests multiplying by a public polynomial result
    #[tokio::test]
    async fn test_mul_public_polynomial() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 * &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();

            async move {
                let shared_poly1 = share_poly(poly1, PARTY0, &fabric);
                let poly2 = allocate_poly(&poly2, &fabric);

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

    /// Tests multiplying by a public constant scalar
    #[tokio::test]
    async fn test_scalar_mul_constant() {
        let mut rng = thread_rng();
        let poly = random_poly(DEGREE_BOUND);
        let scaling_factor = Scalar::random(&mut rng);

        let expected_res = &poly * scaling_factor.inner();

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly = poly.clone();
            async move {
                let shared_poly = share_poly(poly, PARTY0, &fabric);
                (shared_poly * scaling_factor).open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected_res);
    }

    /// Tests multiplying by a public result
    #[tokio::test]
    async fn test_scalar_mul_public() {
        let mut rng = thread_rng();
        let poly = random_poly(DEGREE_BOUND);
        let scaling_factor = Scalar::random(&mut rng);

        let expected_res = &poly * scaling_factor.inner();

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly = poly.clone();
            async move {
                let shared_poly = share_poly(poly, PARTY0, &fabric);
                let scaling_factor = fabric.allocate_scalar(scaling_factor);

                (shared_poly * scaling_factor).open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected_res);
    }

    /// Tests multiplying by a shared scalar
    #[tokio::test]
    async fn test_scalar_mul() {
        let mut rng = thread_rng();
        let poly = random_poly(DEGREE_BOUND);
        let scaling_factor = Scalar::random(&mut rng);

        let expected_res = &poly * scaling_factor.inner();

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly = poly.clone();
            async move {
                let shared_poly = share_poly(poly, PARTY0, &fabric);
                let scaling_factor = fabric.share_scalar(scaling_factor, PARTY0);

                (shared_poly * scaling_factor).open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected_res);
    }

    /// Tests dividing a shared polynomial by a public polynomial
    #[tokio::test]
    async fn test_div_polynomial_public() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 / &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();
            async move {
                let dividend = share_poly(poly1, PARTY0, &fabric);
                let divisor = allocate_poly(&poly2, &fabric);

                let quotient = dividend / divisor;
                quotient.open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected_res);
    }

    /// Tests dividing two shared polynomial
    #[tokio::test]
    async fn test_div_polynomial() {
        let poly1 = random_poly(DEGREE_BOUND);
        let poly2 = random_poly(DEGREE_BOUND);

        let expected_res = &poly1 / &poly2;

        let (res, _) = execute_mock_mpc(|fabric| {
            let poly1 = poly1.clone();
            let poly2 = poly2.clone();
            async move {
                let dividend = share_poly(poly1, PARTY0, &fabric);
                let divisor = share_poly(poly2, PARTY1, &fabric);

                let quotient = dividend / divisor;
                quotient.open_authenticated().await
            }
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected_res);
    }
}
