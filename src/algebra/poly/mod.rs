//! Polynomial types over secret shared fields
//!
//! Modeled after the `ark_poly` implementation

#![allow(clippy::module_inception)]

mod authenticated_poly;
mod poly;

pub use authenticated_poly::*;
pub use poly::*;

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
