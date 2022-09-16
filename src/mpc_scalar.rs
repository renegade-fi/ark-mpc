//! Groups the definitions and trait implementations for a scalar value within an MPC network
#![allow(unused_doc_comments)]
mod macros;

use std::{rc::Rc, ops::{Add, Index, MulAssign, Mul, AddAssign, SubAssign, Sub, Neg}, iter::{Product, Sum}, borrow::Borrow, cmp::Ordering};

use curve25519_dalek::scalar::Scalar;


use rand_core::{RngCore, CryptoRng};
use subtle::{ConstantTimeEq};
use zeroize::Zeroize;

use crate::{network::MpcNetwork, beaver::{SharedValueSource}};

#[allow(type_alias_bounds)]
pub type SharedNetwork<N: MpcNetwork> = Rc<N>;
#[allow(type_alias_bounds)]
pub type BeaverSource<S: SharedValueSource<Scalar>> = Rc<S>;

#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Represents a scalar value allocated in an MPC network
#[derive(Clone, Debug)]
pub struct MpcScalar<N: MpcNetwork, S: SharedValueSource<Scalar>> {
    /// the underlying value of the scalar allocated in the network
    value: Scalar,
    /// The visibility flag; what amount of information parties have
    visibility: Visibility,
    /// The underlying network that the MPC operates on
    network: SharedNetwork<N>,
    /// The source for shared values; MAC keys, beaver triples, etc
    beaver_source: BeaverSource<S>,
}

/// Static methods
impl<N: MpcNetwork, S: SharedValueSource<Scalar>> MpcScalar<N, S> {
    /// Returns the minimum visibility over a vector of scalars
    pub fn min_visibility(scalars: &[MpcScalar<N, S>]) -> Visibility {
        scalars.iter()
            .map(|scalar| scalar.visibility.clone())
            .min()
            .unwrap()  // The Ord + PartialOrd implementations never return None
    }

    /// Returns the minimum visibility between two scalars
    pub fn min_visibility_two(a: MpcScalar<N, S>, b: MpcScalar<N, S>) -> Visibility {
        Self::min_visibility(&[a, b])
    }
}

impl<N: MpcNetwork, S: SharedValueSource<Scalar>> MpcScalar<N, S> {
    /**
     * Casting methods
     */

    /// Create a scalar from a given u64, visibility assumed to be Public
    pub fn from_u64(a: u64, network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Self {
        Self::from_u64_with_visibility(a, Visibility::Public, network, beaver_source)
    }

    /// Create a scalar from a given u64 and visibility
    pub fn from_u64_with_visibility(
        a: u64, 
        visibility: Visibility,
        network: SharedNetwork<N>, 
        beaver_source: BeaverSource<S>, 
    ) -> Self {
        Self { 
            network, 
            visibility, 
            beaver_source, 
            value: Scalar::from(a),
        }
    }

    /// Allocate an existing scalar in the network
    pub fn from_scalar(value: Scalar, network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Self {
        Self::from_scalar_with_visibility(value, Visibility::Public, network, beaver_source)
    }

    /// Allocate an existing scalar in the network with given visibility
    pub fn from_scalar_with_visibility(
        value: Scalar, 
        visibility: Visibility,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>, 
    ) -> Self {
        Self {
            network,
            visibility,
            value,
            beaver_source,
        }
    }

    /// Generate a random scalar
    /// Random will always be SharedWithOwner(self); two parties cannot reliably generate the same random value
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R, network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Self {
        Self { 
            network, 
            visibility: Visibility::Private,
            beaver_source,
            value: Scalar::random(rng) 
        }
    }

    /// Default-esque implementation
    pub fn default(network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Self {
        Self::zero(network, beaver_source)
    }

    // Build a scalar from bytes
    macros::impl_delegated_wrapper!(from_bytes_mod_order, from_bytes_mod_order_with_visibility, bytes, [u8;32]);
    macros::impl_delegated_wrapper!(
        from_bytes_mod_order_wide, 
        from_bytes_mod_order_wide_with_visibility,
        input, 
        &[u8; 64]
    );

    pub fn from_canonical_bytes(bytes: [u8; 32], network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Option<MpcScalar<N, S>> {
        Self::from_canonical_bytes_with_visibility(bytes, Visibility::Public, network, beaver_source)
    }

    pub fn from_canonical_bytes_with_visibility(
        bytes: [u8; 32], 
        visibility: Visibility,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Option<MpcScalar<N, S>> {
        Some(
            MpcScalar {
                visibility,
                network,
                beaver_source,
                value: Scalar::from_canonical_bytes(bytes)?,
            }
        )
    }

    macros::impl_delegated_wrapper!(from_bits, from_bits_with_visibility, bytes, [u8; 32]);
    
    // Convert a scalar to bytes
    macros::impl_delegated!(to_bytes, self, [u8; 32]);
    macros::impl_delegated!(as_bytes, self, &[u8; 32]);
    // Compute the multiplicative inverse of the Scalar
    macros::impl_delegated_wrapper!(invert, invert_with_visibility, self);
    // Invert a batch of scalars and return the product of inverses
    pub fn batch_invert(inputs: &mut [MpcScalar<N, S>]) -> MpcScalar<N, S> {
        let mut scalars: Vec<Scalar> = inputs.iter()
            .map(|mpc_scalar| mpc_scalar.value)
            .collect();

        MpcScalar {
            visibility: MpcScalar::min_visibility(inputs),
            network: inputs[0].network.clone(),
            beaver_source: inputs[0].beaver_source.clone(),
            value: Scalar::batch_invert(&mut scalars)
        }
    }

    // Reduce the scalar mod l
    macros::impl_delegated_wrapper!(reduce, reduce_with_visibility, self);
    // Check whether the scalar is canonically represented mod l
    macros::impl_delegated!(is_canonical, self, bool);
    // Generate the additive identity
    macros::impl_delegated_wrapper!(zero, zero_with_visibility);
    // Generate the multiplicative identity
    macros::impl_delegated_wrapper!(one, one_with_visibility);
}

/**
 * Generic trait implementations
 */

impl<N: MpcNetwork, S: SharedValueSource<Scalar>> PartialEq for MpcScalar<N, S> {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq(&other.value)
    }
}

impl<N: MpcNetwork, S: SharedValueSource<Scalar>> ConstantTimeEq for MpcScalar<N, S> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value.ct_eq(&other.value)
    } 
}

impl<N: MpcNetwork, S: SharedValueSource<Scalar>> Index<usize> for MpcScalar<N, S> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        self.value.index(index)
    }
}


/**
 * Mul and variants for: borrowed, non-borrowed, and Scalar types
 */
macros::impl_arithmetic_assign_scalar!(MulAssign, mul_assign, *=, MpcScalar<N, S>);
macros::impl_arithmetic_assign_scalar!(MulAssign, mul_assign, *=, Scalar);
macros::impl_arithmetic_scalar!(Mul, mul, *, MpcScalar<N, S>);
macros::impl_arithmetic_scalar!(Mul, mul, *, Scalar);

/**
 * add and variants for: borrowed, non-borrowed, and scalar types
 */
macros::impl_arithmetic_assign_scalar!(AddAssign, add_assign, +=, MpcScalar<N, S>);
macros::impl_arithmetic_assign_scalar!(AddAssign, add_assign, +=, Scalar);
macros::impl_arithmetic_scalar!(Add, add, +, MpcScalar<N, S>);
macros::impl_arithmetic_scalar!(Add, add, +, Scalar);


/**
 * Sub and variants for: borrowed, non-borrowed, and scalar types
 */
macros::impl_arithmetic_assign_scalar!(SubAssign, sub_assign, -=, MpcScalar<N, S>);
macros::impl_arithmetic_assign_scalar!(SubAssign, sub_assign, -=, Scalar);
macros::impl_arithmetic_scalar!(Sub, sub, -, MpcScalar<N, S>);
macros::impl_arithmetic_scalar!(Sub, sub, -, Scalar);


impl<N: MpcNetwork, S: SharedValueSource<Scalar>> Neg for MpcScalar<N, S> {
    type Output = MpcScalar<N, S>; 

    fn neg(self) -> Self::Output {
        MpcScalar {
            visibility: self.visibility.clone(),
            network: self.network.clone(),
            beaver_source: self.beaver_source.clone(),
            value: self.value.neg()
        }
    }
}

impl<'a, N: MpcNetwork, S: SharedValueSource<Scalar>> Neg for &'a MpcScalar<N, S> {
    type Output = MpcScalar<N, S>;

    fn neg(self) -> Self::Output {
        MpcScalar {
            visibility: self.visibility.clone(),
            network: self.network.clone(),
            beaver_source: self.beaver_source.clone(),
            value: self.value.neg(),
        }
    }
}

/**
 * Iterator traits
 */

impl<N, S, T> Product<T> for MpcScalar<N, S> where
    N: MpcNetwork,
    S: SharedValueSource<Scalar>,
    T: Borrow<MpcScalar<N, S>>
{
    fn product<I: Iterator<Item = T>>(mut iter: I) -> Self {
        let first_elem = iter.next().unwrap();
        let network: SharedNetwork<N> = first_elem.borrow()
            .network
            .clone();
        let beaver_source: BeaverSource<S> = first_elem.borrow()
            .beaver_source
            .clone();

        iter.fold(MpcScalar::one(network, beaver_source), |acc, item| acc * item.borrow())
    }
}

impl<N, S, T> Sum<T> for MpcScalar<N, S> where
    N: MpcNetwork,
    S: SharedValueSource<Scalar>,
    T: Borrow<MpcScalar<N, S>>
{
    fn sum<I: Iterator<Item = T>>(mut iter: I) -> Self {
        // This operation is invalid on an empty iterator, unwrap is expected
        let first_elem = iter.next().unwrap();
        let network = first_elem.borrow()
            .network
            .clone();
        let beaver_source: BeaverSource<S> = first_elem.borrow()
            .beaver_source
            .clone();

        iter.fold(MpcScalar::one(network, beaver_source), |acc, item| acc + item.borrow())
    } 
}

impl<N: MpcNetwork, S: SharedValueSource<Scalar>> Zeroize for MpcScalar<N, S> {
    fn zeroize(&mut self) {
        self.value.zeroize()
    }
}

#[cfg(test)]
mod test {
    use std::rc::Rc;

    use curve25519_dalek::scalar::Scalar;

    use crate::{network::dummy_network::DummyMpcNetwork, beaver::DummySharedScalarSource};

    use super::MpcScalar;

    #[test]
    fn test_zero() {
        let network = Rc::new(DummyMpcNetwork::new());
        let beaver_source = Rc::new(DummySharedScalarSource::new());

        let expected = MpcScalar::from_scalar(
            Scalar::zero(), network.clone(), beaver_source.clone()
        );
        let zero = MpcScalar::zero(network, beaver_source);

        assert_eq!(zero, expected);
    }
}