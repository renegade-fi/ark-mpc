//! An authenticated polynomial over a `CurveGroup`'s scalar field
//!
//! Modeled after the `ark_poly::DensePolynomial` type, but allocated in an MPC fabric

use ark_ec::CurveGroup;

use crate::algebra::AuthenticatedScalarResult;

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
        Self { coeffs }
    }
}
