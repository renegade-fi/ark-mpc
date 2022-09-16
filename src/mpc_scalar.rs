//! Groups the definitions and trait implementations for a scalar value within an MPC network
#![allow(unused_doc_comments)]
mod macros;

use std::{
    borrow::Borrow, 
    cell::RefCell,
    cmp::Ordering, 
    iter::{Product, Sum}, 
    rc::Rc, 
    ops::{Add, Index, MulAssign, Mul, AddAssign, SubAssign, Sub, Neg}, 
};

use curve25519_dalek::scalar::Scalar;
use futures::executor::block_on;
use rand_core::{RngCore, CryptoRng, OsRng};
use subtle::{ConstantTimeEq};
use zeroize::Zeroize;

use crate::{network::MpcNetwork, beaver::{SharedValueSource}, error::MpcNetworkError};

#[allow(type_alias_bounds)]
pub type SharedNetwork<N: MpcNetwork + Send> = Rc<RefCell<N>>;
#[allow(type_alias_bounds)]
pub type BeaverSource<S: SharedValueSource<Scalar>> = Rc<RefCell<S>>;

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
pub struct MpcScalar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// the underlying value of the scalar allocated in the network
    value: Scalar,
    /// The visibility flag; what amount of information parties have
    visibility: Visibility,
    /// The underlying network that the MPC operates on
    network: SharedNetwork<N>,
    /// The source for shared values; MAC keys, beaver triples, etc
    beaver_source: BeaverSource<S>,
}

/**
 * Static methods
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MpcScalar<N, S> {
    /// Returns the minimum visibility over a vector of scalars
    pub fn min_visibility(scalars: &[MpcScalar<N, S>]) -> Visibility {
        scalars.iter()
            .map(|scalar| scalar.visibility.clone())
            .min()
            .unwrap()  // The Ord + PartialOrd implementations never return None
    }

    /// Returns the minimum visibility between two scalars
    pub fn min_visibility_two(a: &MpcScalar<N, S>, b: &MpcScalar<N, S>) -> Visibility {
        if a.visibility.lt(&b.visibility) { a.visibility.clone() } else { b.visibility.clone() }
    }
}

/**
 * Wrapper type implementations
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MpcScalar<N, S> {
    /**
     * Helper methods
     */
    #[inline]
    fn is_shared(&self) -> bool {
        self.visibility == Visibility::Shared
    }

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
 * Secret sharing implementation
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MpcScalar<N, S> {
    /// From a privately held value, construct an additive secret share and distribute this
    /// to the counterparty. The local party samples a random value R which is given to the peer
    /// The local party then holds a - R where a is the underlying value.
    /// Returns the share held by the local party
    pub fn share_secret(self) -> Result<MpcScalar<N, S>, MpcNetworkError> {
        // Sample a random additive complement
        let mut rng = OsRng{};
        let random_share = Scalar::from(rng.next_u64());

        // Broadcast the counterparty's share
        block_on(
            self.network
                .as_ref()
                .borrow_mut()
                .send_single_scalar(random_share)
        )?;

        Ok( self - random_share )
    }

    /// From a shared value, both parties open their shares and construct the plaintext value.
    /// Note that the parties no longer hold valid additive secret shares of the value, this is used
    /// at the end of a computation
    pub fn open(self) -> Result<MpcScalar<N, S>, MpcNetworkError> {
        // Send my scalar and expect one back
        let received_scalar = block_on(
            self.network
                .as_ref()
                .borrow_mut()
                .broadcast_single_scalar(self.value)
        )?;

        // Reconstruct the plaintext from the peer's share
        Ok(
            MpcScalar::from_scalar_with_visibility(
                self.value + received_scalar, 
                Visibility::Public,
                self.network.clone(),
                self.beaver_source
            )
        )
    }

    /// Retreives the next Beaver triplet from the Beaver source and allocates the values within the network
    fn next_beaver_triplet(&self) -> (MpcScalar<N, S>, MpcScalar<N, S>, MpcScalar<N, S>) {
        let (a, b, c) = self.beaver_source
            .as_ref()
            .borrow_mut()
            .next_triplet();
        
        (
            MpcScalar::from_scalar_with_visibility(a, Visibility::Shared, self.network.clone(), self.beaver_source.clone()),
            MpcScalar::from_scalar_with_visibility(b, Visibility::Shared, self.network.clone(), self.beaver_source.clone()),
            MpcScalar::from_scalar_with_visibility(c, Visibility::Shared, self.network.clone(), self.beaver_source.clone())
        )
    }
}

/**
 * Generic trait implementations
 */

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> PartialEq for MpcScalar<N, S> {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq(&other.value)
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> ConstantTimeEq for MpcScalar<N, S> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value.ct_eq(&other.value)
    } 
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Index<usize> for MpcScalar<N, S> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        self.value.index(index)
    }
}

/**
 * Mul and variants for: borrowed, non-borrowed, and Scalar types
 */

// Multiplication with a scalar value is equivalent to a public multiplication, no Beaver
// trick needed
macros::impl_arithmetic_scalar!(Mul, mul, *, Scalar);
macros::impl_arithmetic_assign_scalar!(MulAssign, mul_assign, *=, Scalar);

/// Implementations of MulAssign must panic, there is no clean way for us to pass the error up
/// I.e. we could implement MulAssign on Result<MpcScalar<N, S>, MpcNetworkError> but this is
/// not a clean interface
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MulAssign<MpcScalar<N, S>> for MpcScalar<N, S> {
    fn mul_assign(&mut self, rhs: MpcScalar<N, S>) {
        *self = (self.borrow() * rhs).unwrap();
    }
}

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MulAssign<&'a MpcScalar<N, S>> for MpcScalar<N, S> {
    fn mul_assign(&mut self, rhs: &'a MpcScalar<N, S>) {
        *self = (self.borrow() * rhs).unwrap();
    }
}

// Implementation of mul with the beaver trick
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a MpcScalar<N, S>> for &'a MpcScalar<N, S> {
    type Output = Result<MpcScalar<N, S>, MpcNetworkError>;

    /// Multiplies two (possibly shared) values. The only case in which we need a Beaver trick
    /// is when both lhs and rhs are Shared. If only one is shared, multiplying by a public value
    /// directly leads to an additive sharing. If both are public, we do not need an additive share.
    /// TODO(@joey): What is the correct behavior when one or both of lhs and rhs are private
    /// 
    /// See https://securecomputation.org/docs/pragmaticmpc.pdf (Section 3.4) for the identities this
    /// implementation makes use of.
    fn mul(self, rhs: &'a MpcScalar<N, S>) -> Self::Output {
        if self.is_shared() && rhs.is_shared() {
            let (a, b, c) = self.next_beaver_triplet();

            // Open the value d = [lhs - a]
            let lhs_minus_a = (self - &a).open()?;
            // Open the value e = [rhs - b]
            let rhs_minus_b = (rhs - &b).open()?;

            // Identity: [a * b] = de + d[b] + e[a] + [c]
            // All multiplications here are between a public and shared value or
            // two public values, so the recursion will not hit this case
            Ok(
                (&lhs_minus_a * &rhs_minus_b)? + 
                (&lhs_minus_a * &b)? + 
                (&rhs_minus_b * &a)? + 
                c
            )
        } else {
            // Directly multiply
            Ok(
                MpcScalar {
                    visibility: MpcScalar::min_visibility_two(self, rhs),
                    network: self.network.clone(),
                    beaver_source: self.beaver_source.clone(),
                    value: self.value * rhs.value
                }
            )
        }
    }
}

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a MpcScalar<N, S>> for MpcScalar<N, S> {
    type Output = Result<MpcScalar<N, S>, MpcNetworkError>;

    fn mul(self, rhs: &'a MpcScalar<N, S>) -> Self::Output {
        &self * rhs
    }
}

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<MpcScalar<N, S>> for &'a MpcScalar<N, S> {
    type Output = Result<MpcScalar<N, S>, MpcNetworkError>;

    fn mul(self, rhs: MpcScalar<N, S>) -> Self::Output {
        self * &rhs
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<MpcScalar<N, S>> for MpcScalar<N, S> {
    type Output = Result<MpcScalar<N, S>, MpcNetworkError>;

    fn mul(self, rhs: MpcScalar<N, S>) -> Self::Output {
        &self * &rhs
    }
}

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

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Neg for MpcScalar<N, S> {
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

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Neg for &'a MpcScalar<N, S> {
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
    N: MpcNetwork + Send,
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

        iter.fold(MpcScalar::one(network, beaver_source), |acc, item| (acc * item.borrow()).unwrap())
    }
}

impl<N, S, T> Sum<T> for MpcScalar<N, S> where
    N: MpcNetwork + Send,
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

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Zeroize for MpcScalar<N, S> {
    fn zeroize(&mut self) {
        self.value.zeroize()
    }
}

#[cfg(test)]
mod test {
    use std::{rc::Rc, cell::RefCell};

    use curve25519_dalek::scalar::Scalar;

    use crate::{network::dummy_network::DummyMpcNetwork, beaver::DummySharedScalarSource};

    use super::MpcScalar;

    #[test]
    fn test_zero() {
        let network = Rc::new(RefCell::new(DummyMpcNetwork::new()));
        let beaver_source = Rc::new(RefCell::new(DummySharedScalarSource::new()));

        let expected = MpcScalar::from_scalar(
            Scalar::zero(), network.clone(), beaver_source.clone()
        );
        let zero = MpcScalar::zero(network, beaver_source);

        assert_eq!(zero, expected);
    }
}