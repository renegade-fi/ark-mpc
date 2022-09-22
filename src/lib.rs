use std::{cmp::Ordering, cell::RefCell, rc::Rc};

use beaver::SharedValueSource;
use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::MpcRistrettoPoint;
use mpc_scalar::MpcScalar;
use network::MpcNetwork;

pub mod authenticated_scalar;
pub mod beaver;
pub mod error;
mod macros;
pub mod mpc_scalar;
pub mod mpc_ristretto;
pub mod network;

/// SharedNetwork wraps a network implementation in a borrow-safe container
/// while providing interior mutability
#[allow(type_alias_bounds)]
pub type SharedNetwork<N: MpcNetwork + Send> = Rc<RefCell<N>>;
#[allow(type_alias_bounds)]
pub type BeaverSource<S: SharedValueSource<Scalar>> = Rc<RefCell<S>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Visibility determines what information peers have for values allocated
/// in the network.
pub enum Visibility {
    /// The below are in increasing order of visibility
    /// A value that only one party holds, can be *shared* into Shared
    /// or *opened* into Public
    Private,
    /// Shared in which neither party knows the underlying value
    /// Can be *opened* into Public
    Shared,
    /// Public, both parties know the value
    Public
}

/// Convenience methods for comparing visibilities on various types
impl Visibility {
    /// Returns the minimum visibility between two scalars
    pub(crate) fn min_visibility_two_scalars<N, S>(a: &MpcScalar<N, S>, b: &MpcScalar<N, S>) -> Visibility where
        N: MpcNetwork + Send,
        S: SharedValueSource<Scalar>
    {
        if a.visibility.lt(&b.visibility) { a.visibility } else { b.visibility }
    }

    /// Returns the minimum visibility between two Ristretto points
    pub(crate) fn min_visibility_two_points<N, S>(a: &MpcRistrettoPoint<N, S>, b: &MpcRistrettoPoint<N, S>) -> Visibility where
        N: MpcNetwork + Send,
        S: SharedValueSource<Scalar>
    {
        if a.visibility().lt(&b.visibility()) { a.visibility() } else { b.visibility() }
    }

    /// Returns the minimum visibility between a point and a scalar
    pub(crate) fn min_visibility_point_scalar<N, S>(point: &MpcRistrettoPoint<N, S>, scalar: &MpcScalar<N, S>) -> Visibility where
        N: MpcNetwork + Send,
        S: SharedValueSource<Scalar>
    {
        if point.visibility().lt(&scalar.visibility()) { point.visibility() } else { scalar.visibility() }
    }
}

/// An implementation of Ord for Visibilities
/// Note that when two items are SharedWithOwner, but have different owners
/// they are said to be equal; we let the caller handle differences
impl Ord for Visibility {
    fn cmp(&self, other: &Self) -> Ordering {
        match self {
            Visibility::Private => match other {
                Visibility::Private => Ordering::Equal,
                _ => Ordering::Less
            }
            Visibility::Shared => match other {
                Visibility::Private => Ordering::Greater,
                Visibility::Shared => Ordering::Equal,
                _ => Ordering::Less
            },
            Visibility::Public => match other {
                Visibility::Public => Ordering::Equal,
                _ => Ordering::Greater,
            }
        }
    }
}

impl PartialOrd for Visibility {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            self.cmp(other)
        )
    }
}