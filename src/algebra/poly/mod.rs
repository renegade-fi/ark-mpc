//! Polynomial types over secret shared fields
//!
//! Modeled after the `ark_poly` implementation

#![allow(clippy::module_inception)]

mod authenticated_poly;
mod poly;

use ark_ff::{FftField, Field};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial,
};
use ark_std::Zero;
pub use authenticated_poly::*;
pub use poly::*;

/// Return a representation of x^t as a `DensePolynomial`
fn x_to_t<F: Field>(t: usize) -> DensePolynomial<F> {
    let mut coeffs = vec![F::zero(); t];
    coeffs.push(F::one());
    DensePolynomial::from_coefficients_vec(coeffs)
}

/// Reverse the coefficients of an Arkworks polynomial
pub fn rev_coeffs<F: Field>(poly: &DensePolynomial<F>) -> DensePolynomial<F> {
    let mut coeffs = poly.coeffs().to_vec();
    coeffs.reverse();

    DensePolynomial::from_coefficients_vec(coeffs)
}

/// A helper to compute the Bezout coefficients of the two given polynomials
///
/// I.e. for a(x), b(x) as input, we compute f(x), g(x) such that:
///     f(x) * a(x) + g(x) * b(x) = gcd(a, b)
/// This is done using the extended Euclidean method
fn compute_bezout_polynomials<F: FftField>(
    a: &DensePolynomial<F>,
    b: &DensePolynomial<F>,
) -> (DensePolynomial<F>, DensePolynomial<F>) {
    if b.is_zero() {
        return (
            DensePolynomial::from_coefficients_vec(vec![F::one()]), // f(x) = 1
            DensePolynomial::zero(),                                // f(x) = 0
        );
    }

    let a_transformed = DenseOrSparsePolynomial::from(a);
    let b_transformed = DenseOrSparsePolynomial::from(b);
    let (quotient, remainder) = a_transformed.divide_with_q_and_r(&b_transformed).unwrap();

    let (f, g) = compute_bezout_polynomials(b, &remainder);
    let next_g = &f - &(&quotient * &g);

    (g, next_g)
}
/// Compute the multiplicative inverse of a polynomial mod x^t
pub fn poly_inverse_mod_xt<F: FftField>(poly: &DensePolynomial<F>, t: usize) -> DensePolynomial<F> {
    // Compute the Bezout coefficients of the two polynomials
    let x_to_t = x_to_t(t);
    let (inverse_poly, _) = compute_bezout_polynomials(poly, &x_to_t);

    // In a polynomial ring, gcd is defined only up to scalar multiplication, so we
    // multiply the result by the inverse of the resultant first
    // coefficient to uniquely define the inverse as f^{-1}(x) such that
    // f * f^{-1}(x) = 1 \in F[x] / (x^t)
    let self_constant_coeff = poly.coeffs[0];
    let inverse_constant_coeff = inverse_poly.coeffs[0];
    let constant_coeff_inv = (self_constant_coeff * inverse_constant_coeff).inverse().unwrap();

    &inverse_poly * constant_coeff_inv
}

#[cfg(test)]
pub mod poly_test_helpers {
    use ark_ec::Group;
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::UniformRand;
    use itertools::Itertools;
    use rand::{thread_rng, Rng};

    use crate::{algebra::Scalar, network::PartyId, test_helpers::TestCurve, MpcFabric};

    use super::{AuthenticatedDensePoly, DensePolynomialResult};

    /// The scalar field testing polynomials are defined over
    pub type TestPolyField = <TestCurve as Group>::ScalarField;

    /// Generate a random polynomial given a degree bound
    pub fn random_poly(degree_bound: usize) -> DensePolynomial<TestPolyField> {
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
    pub fn allocate_poly(
        poly: &DensePolynomial<TestPolyField>,
        fabric: &MpcFabric<TestCurve>,
    ) -> DensePolynomialResult<TestCurve> {
        let mut allocated_coeffs = Vec::with_capacity(poly.degree() + 1);
        for coeff in poly.coeffs().iter() {
            allocated_coeffs.push(fabric.allocate_scalar(Scalar::new(*coeff)));
        }

        DensePolynomialResult::from_coeffs(allocated_coeffs)
    }

    /// Allocate an authenticated polynomial in the given fabric
    pub fn share_poly(
        poly: DensePolynomial<TestPolyField>,
        sender: PartyId,
        fabric: &MpcFabric<TestCurve>,
    ) -> AuthenticatedDensePoly<TestCurve> {
        let coeffs = poly.coeffs.iter().copied().map(Scalar::new).collect_vec();
        let shared_coeffs = fabric.batch_share_scalar(coeffs, sender);

        AuthenticatedDensePoly::from_coeffs(shared_coeffs)
    }
}
