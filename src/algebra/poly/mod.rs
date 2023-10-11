//! Polynomial types over secret shared fields
//!
//! Modeled after the `ark_poly` implementation

#![allow(clippy::module_inception)]

mod authenticated_poly;
mod poly;

pub use authenticated_poly::*;
pub use poly::*;
