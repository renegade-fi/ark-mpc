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
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
    use ark_std::UniformRand;
    use rand::{thread_rng, Rng};

    use crate::test_helpers::TestCurve;

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
}
