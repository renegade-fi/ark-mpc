#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

//! Defines an MPC implementation over the Stark curve that allows for out-of-order execution of
//! the underlying MPC circuit

use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, RwLock},
};

use algebra::{scalar::Scalar, stark_curve::StarkPoint};
use beaver::SharedValueSource;

use network::MpcNetwork;
use rand::thread_rng;

pub mod algebra;
pub mod beaver;
pub mod commitment;
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

/// Generate a random curve point by multiplying a random scalar with the
/// Stark curve group generator
pub fn random_point() -> StarkPoint {
    let mut rng = thread_rng();
    StarkPoint::generator() * Scalar::random(&mut rng)
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
/// A type alias for a shared, mutable reference to an underlying beaver source
#[allow(type_alias_bounds)]
pub type BeaverSource<S: SharedValueSource> = Rc<RefCell<S>>;
