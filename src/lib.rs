use std::{
    cell::RefCell,
    cmp::Ordering,
    rc::Rc,
    sync::{Arc, RwLock},
};

use algebra::stark_curve::Scalar;
use ark_ff::PrimeField;
use beaver::SharedValueSource;

use network::MpcNetwork;

pub mod algebra;
pub mod beaver;
pub mod error;
pub mod fabric;
pub mod network;

// -------------
// | Constants |
// -------------

/// The first party
pub const PARTY0: u64 = 0;
/// The second party
pub const PARTY1: u64 = 1;

// -----------
// | Helpers |
// -----------

/// Generate a random scalar
pub fn random_scalar() -> Scalar {
    let bytes: [u8; 32] = rand::random();
    Scalar::from_be_bytes_mod_order(&bytes)
}

// --------------------
// | Crate-wide Types |
// --------------------

/// A type alias for a shared locked value
type Shared<T> = Arc<RwLock<T>>;

/// SharedNetwork wraps a network implementation in a borrow-safe container
/// while providing interior mutability
#[allow(type_alias_bounds)]
pub type SharedNetwork<N: MpcNetwork + Send> = Rc<RefCell<N>>;
#[allow(type_alias_bounds)]
pub type BeaverSource<S: SharedValueSource> = Rc<RefCell<S>>;

/// A wrapper trait that allows for implementing generic comparisons
pub trait Visible {
    fn visibility(&self) -> Visibility;
}

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
    Public,
}

/// Convenience methods for comparing visibilities on various types
impl Visibility {
    /// Returns the minimum visibility between two scalars
    pub(crate) fn min_visibility_two(a: &impl Visible, b: &impl Visible) -> Visibility {
        if a.visibility().lt(&b.visibility()) {
            a.visibility()
        } else {
            b.visibility()
        }
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
                _ => Ordering::Less,
            },
            Visibility::Shared => match other {
                Visibility::Private => Ordering::Greater,
                Visibility::Shared => Ordering::Equal,
                _ => Ordering::Less,
            },
            Visibility::Public => match other {
                Visibility::Public => Ordering::Equal,
                _ => Ordering::Greater,
            },
        }
    }
}

impl PartialOrd for Visibility {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
