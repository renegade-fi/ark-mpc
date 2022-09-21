//! Groups the definitions and trait implementations for a scalar value within an MPC network
#![allow(unused_doc_comments)]
use std::{
    borrow::Borrow, 
    cell::RefCell,
    cmp::Ordering, 
    iter::{Product, Sum}, 
    rc::Rc, 
    ops::{Add, Index, MulAssign, Mul, AddAssign, SubAssign, Sub, Neg}, convert::TryInto, 
};

use curve25519_dalek::{scalar::{Scalar}};
use futures::executor::block_on;
use rand_core::{RngCore, CryptoRng, OsRng};
use subtle::{ConstantTimeEq};
use zeroize::Zeroize;

use crate::{network::MpcNetwork, beaver::{SharedValueSource}, error::MpcNetworkError, macros, mpc_ristretto::MpcRistrettoPoint};

#[allow(type_alias_bounds)]
pub type SharedNetwork<N: MpcNetwork + Send> = Rc<RefCell<N>>;
#[allow(type_alias_bounds)]
pub type BeaverSource<S: SharedValueSource<Scalar>> = Rc<RefCell<S>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// Returns the minimum visibility of an array of scalars
    pub(crate) fn min_visibility_scalars<N, S>(scalars: &[MpcScalar<N, S>]) -> Visibility where
        N: MpcNetwork + Send,
        S: SharedValueSource<Scalar> 
    {
        scalars.iter()
            .map(|scalar| scalar.visibility())
            .min()
            .unwrap()  // The Ord + PartialOrd implementations never return None
    }

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

/// Represents a scalar value allocated in an MPC network
#[derive(Clone, Debug)]
pub struct MpcScalar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// the underlying value of the scalar allocated in the network
    pub(crate) value: Scalar,
    /// The visibility flag; what amount of information parties have
    pub(crate) visibility: Visibility,
    /// The underlying network that the MPC operates on
    pub(crate) network: SharedNetwork<N>,
    /// The source for shared values; MAC keys, beaver triples, etc
    pub(crate) beaver_source: BeaverSource<S>,
}

/**
 * Static and helper methods
 */

/// Converts a scalar to u64
pub fn scalar_to_u64(a: &Scalar) -> u64 {
    u64::from_le_bytes(a.to_bytes()[..8].try_into().unwrap()) as u64
}

/**
 * Wrapper type implementations
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MpcScalar<N, S> {
    /**
     * Helper methods
     */
    #[inline]
    pub(crate) fn is_shared(&self) -> bool {
        self.visibility == Visibility::Shared
    }

    #[inline]
    pub(crate) fn is_public(&self) -> bool {
        self.visibility == Visibility::Public
    }

    #[inline]
    pub fn value(&self) -> Scalar {
        self.value
    }

    #[inline]
    pub(crate) fn visibility(&self) -> Visibility {
        self.visibility
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
    macros::impl_delegated_wrapper!(Scalar, from_bytes_mod_order, from_bytes_mod_order_with_visibility, bytes, [u8;32]);
    macros::impl_delegated_wrapper!(
        Scalar,
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

    macros::impl_delegated_wrapper!(Scalar, from_bits, from_bits_with_visibility, bytes, [u8; 32]);
    
    // Convert a scalar to bytes
    macros::impl_delegated!(to_bytes, self, [u8; 32]);
    macros::impl_delegated!(as_bytes, self, &[u8; 32]);
    // Compute the multiplicative inverse of the Scalar
    macros::impl_delegated_wrapper!(Scalar, invert, invert_with_visibility, self);
    // Invert a batch of scalars and return the product of inverses
    pub fn batch_invert(inputs: &mut [MpcScalar<N, S>]) -> MpcScalar<N, S> {
        let mut scalars: Vec<Scalar> = inputs.iter()
            .map(|mpc_scalar| mpc_scalar.value)
            .collect();

        MpcScalar {
            visibility: Visibility::min_visibility_scalars(inputs),
            network: inputs[0].network.clone(),
            beaver_source: inputs[0].beaver_source.clone(),
            value: Scalar::batch_invert(&mut scalars)
        }
    }

    // Reduce the scalar mod l
    macros::impl_delegated_wrapper!(Scalar, reduce, reduce_with_visibility, self);
    // Check whether the scalar is canonically represented mod l
    macros::impl_delegated!(is_canonical, self, bool);
    // Generate the additive identity
    macros::impl_delegated_wrapper!(Scalar, zero, zero_with_visibility);
    // Generate the multiplicative identity
    macros::impl_delegated_wrapper!(Scalar, one, one_with_visibility);
}

/**
 * Secret sharing implementation
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MpcScalar<N, S> {
    /// From a privately held value, construct an additive secret share and distribute this
    /// to the counterparty. The local party samples a random value R which is given to the peer
    /// The local party then holds a - R where a is the underlying value.
    /// This method is called by both parties, only one of which transmits, the peer will simply
    /// await the sent share
    pub fn share_secret(&self, party_id: u64) -> Result<MpcScalar<N, S>, MpcNetworkError> {
        let my_party_id = self.network
            .as_ref()
            .borrow()
            .party_id();

        if my_party_id == party_id {
            // Sender party
            // Sample a random additive complement
            let mut rng = OsRng{};
            let random_share = Scalar::random(&mut rng);

            // Broadcast the counterparty's share
            block_on(
                self.network
                    .as_ref()
                    .borrow_mut()
                    .send_single_scalar(random_share)
            )?;

            // Do not subtract directly as the random scalar is not directly allocated in the network
            // subtracting directly ties it to the subtraction implementaiton in a fragile way
            Ok( 
                MpcScalar { 
                    value: self.value - random_share, 
                    visibility: Visibility::Shared,
                    network: self.network.clone(),
                    beaver_source: self.beaver_source.clone(),
                }
            )
        } else {
            Self::receive_value(self.network.clone(), self.beaver_source.clone())
        }
    }

    /// Local party receives a secret share of a value; as opposed to using share_secret, no existing value is needed
    pub fn receive_value(network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Result<MpcScalar<N, S>, MpcNetworkError> {
        let value = block_on(
            network.as_ref()
                .borrow_mut()
                .receive_single_scalar()
        )?;

        Ok(
            MpcScalar { 
                value,
                visibility: Visibility::Shared,
                network,
                beaver_source,
            }
        )
    }

    /// From a shared value, both parties open their shares and construct the plaintext value.
    /// Note that the parties no longer hold valid additive secret shares of the value, this is used
    /// at the end of a computation
    pub fn open(&self) -> Result<MpcScalar<N, S>, MpcNetworkError> {
        if self.is_public() {
            return Ok(
                MpcScalar::from_scalar(
                    self.value, self.network.clone(), self.beaver_source.clone()
                )
            )
        }

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
                self.beaver_source.clone()
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

/// Implementation of mul with the beaver trick
/// This implementation panics in the case of a network error.
/// Ideally this is done in a thread where the panic can be handled by the parent.
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a MpcScalar<N, S>> for &'a MpcScalar<N, S> {
    type Output = MpcScalar<N, S>;

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

            // Open the value d = [lhs - a].open()
            let lhs_minus_a = (self - &a).open().unwrap();
            // Open the value e = [rhs - b].open()
            let rhs_minus_b = (rhs - &b).open().unwrap();

            // Identity: [a * b] = de + d[b] + e[a] + [c]
            // All multiplications here are between a public and shared value or
            // two public values, so the recursion will not hit this case
            let mut res = &lhs_minus_a * &b + 
                &rhs_minus_b * &a + 
                c;
            
            // Split into additive shares, the king holds de + res 
            if self.network
                .as_ref()
                .borrow()
                .am_king() 
            {
                res += &lhs_minus_a * &rhs_minus_b;
            }

            res 
        } else {
            // Directly multiply
            MpcScalar {
                visibility: Visibility::min_visibility_two_scalars(self, rhs),
                network: self.network.clone(),
                beaver_source: self.beaver_source.clone(),
                value: self.value * rhs.value
            }
        }
    }
}

// Multiplication with a scalar value is equivalent to a public multiplication, no Beaver
// trick needed
macros::impl_arithmetic_assign!(MpcScalar<N, S>, MulAssign, mul_assign, *, Scalar);
macros::impl_arithmetic_assign!(MpcScalar<N, S>, MulAssign, mul_assign, *, MpcScalar<N, S>);
macros::impl_arithmetic_wrapper!(MpcScalar<N, S>, Mul, mul, *, MpcScalar<N, S>);
macros::impl_arithmetic_wrapped!(MpcScalar<N, S>, Mul, mul, *, from_scalar, Scalar);

/**
 * Add and variants for: borrowed, non-borrowed, and scalar types
 */
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Add<&'a MpcScalar<N, S>> for &'a MpcScalar<N, S> {
    type Output = MpcScalar<N, S>;

    fn add(self, rhs: &'a MpcScalar<N, S>) -> Self::Output {
        // If public + shared swap the arguments for simplicity
        if self.is_public() && rhs.is_shared() {
            return rhs + self
        }

        // If both values are public; both parties add the values together to obtain
        // a public result. 
        // If both values are shared; both parties add the shared values together to
        // obtain a shared result.
        // If only one value is public, the king adds the public valid to her share
        // I.e. if the parties hold an additive sharing of a = a_1 + a_2 and with to
        // add public b; the king now holds a_1 + b and the peer holds a_2. Effectively
        // they construct an implicit secret sharing of b where b_1 = b and b_2 = 0
        let am_king = self.network.as_ref().borrow().am_king();

        let res = {
            if 
                self.is_public() && rhs.is_public() ||  // Both public
                self.is_shared() && rhs.is_shared() ||  // Both shared
                am_king                                 // One public, but local peer is king
            {
                self.value() + rhs.value()
            } else {
                self.value()
            }
        };

        MpcScalar {
            value: res,
            visibility: Visibility::min_visibility_two_scalars(self, rhs),
            network: self.network.clone(),
            beaver_source: self.beaver_source.clone(), 
        }
    }
}

macros::impl_arithmetic_assign!(MpcScalar<N, S>, AddAssign, add_assign, +, MpcScalar<N, S>);
macros::impl_arithmetic_assign!(MpcScalar<N, S>, AddAssign, add_assign, +, Scalar);
macros::impl_arithmetic_wrapper!(MpcScalar<N, S>, Add, add, +, MpcScalar<N, S>);
macros::impl_arithmetic_wrapped!(MpcScalar<N, S>, Add, add, +, from_scalar, Scalar);

/**
 * Sub and variants for: borrowed, non-borrowed, and scalar types
 */
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Sub<&'a MpcScalar<N, S>> for &'a MpcScalar<N, S> {
    type Output = MpcScalar<N, S>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &'a MpcScalar<N, S>) -> Self::Output {
        self + rhs.neg()
    }
}

macros::impl_arithmetic_assign!(MpcScalar<N, S>, SubAssign, sub_assign, -, MpcScalar<N, S>);
macros::impl_arithmetic_assign!(MpcScalar<N, S>, SubAssign, sub_assign, -, Scalar);
macros::impl_arithmetic_wrapper!(MpcScalar<N, S>, Sub, sub, -, MpcScalar<N, S>);
macros::impl_arithmetic_wrapped!(MpcScalar<N, S>, Sub, sub, -, from_scalar, Scalar);

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Neg for MpcScalar<N, S> {
    type Output = MpcScalar<N, S>; 

    fn neg(self) -> Self::Output {
        (&self).neg()
    }
}

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Neg for &'a MpcScalar<N, S> {
    type Output = MpcScalar<N, S>;

    fn neg(self) -> Self::Output {
        MpcScalar {
            visibility: self.visibility,
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
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        let mut peekable = iter.peekable();
        let first_elem = peekable.peek().unwrap();
        let network: SharedNetwork<N> = first_elem.borrow()
            .network
            .clone();
        let beaver_source: BeaverSource<S> = first_elem.borrow()
            .beaver_source
            .clone();

        peekable.fold(
            MpcScalar::one(network, beaver_source),
            |acc, item| (acc * item.borrow())
        )
    }
}

impl<N, S, T> Sum<T> for MpcScalar<N, S> where
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
    T: Borrow<MpcScalar<N, S>>
{
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        // This operation is invalid on an empty iterator, unwrap is expected
        let mut peekable = iter.peekable();
        let first_elem = peekable.peek().unwrap();
        let network = first_elem.borrow()
            .network
            .clone();
        let beaver_source: BeaverSource<S> = first_elem.borrow()
            .beaver_source
            .clone();

        peekable.fold(
            MpcScalar::zero_with_visibility(Visibility::Shared, network, beaver_source), 
            |acc, item| acc + item.borrow()
        )
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

    use super::{MpcScalar, Visibility};

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

    #[test]
    fn test_open() {
        let network = Rc::new(RefCell::new(DummyMpcNetwork::new()));
        network.borrow_mut()
            .add_mock_scalars(vec![Scalar::from(1u8)]);
        
        let beaver_source = Rc::new(RefCell::new(DummySharedScalarSource::new()));

        let expected = MpcScalar::from_scalar(
            Scalar::from(2u8), network.clone(), beaver_source.clone()
        );
        
        // Dummy network opens to the value we send it, so the mock parties each hold Scalar(1) for a 
        // shared value of Scalar(2)
        let my_share = MpcScalar::from_u64_with_visibility(
            1u64, 
            Visibility::Shared, 
            network, 
            beaver_source
        );

        assert_eq!(my_share.open().unwrap(), expected);
    }

    #[test]
    fn test_add() {
        let network = Rc::new(RefCell::new(DummyMpcNetwork::new()));
        network.borrow_mut()
            .add_mock_scalars(vec![Scalar::from(2u8)]);

        let beaver_source = Rc::new(RefCell::new(DummySharedScalarSource::new()));

        // Assume that parties hold a secret share of [4] as individual shares of 2 each
        let shared_value1 = MpcScalar::from_u64_with_visibility(
            2u64, 
            Visibility::Shared, 
            network.clone(), 
            beaver_source.clone(),
        );
        
        // Test adding a scalar value first
        let res = &shared_value1 + Scalar::from(3u64);  // [4] + 3
        assert_eq!(res.visibility, Visibility::Shared);
        assert_eq!(
            res.open().unwrap(),
            MpcScalar::from_u64(7u64, network.clone(), beaver_source.clone())
        );

        // Test adding another shared value
        // Assume now that parties have additive shares of [5]
        // The peer holds 1, the local party holds 4
        let shared_value2 = MpcScalar::from_u64_with_visibility(
            4u64, 
            Visibility::Shared, 
            network.clone(), 
            beaver_source.clone()
        );

        network.borrow_mut()
            .add_mock_scalars(vec![Scalar::from(3u8)]);  // The peer's share of [4] + [5]

        let res = shared_value1 + shared_value2;
        assert_eq!(res.visibility, Visibility::Shared);
        assert_eq!(
            res.open().unwrap(),
            MpcScalar::from_u64(9, network, beaver_source)
        )
    }

    #[test]
    fn test_sub() {
        let network = Rc::new(RefCell::new(DummyMpcNetwork::new()));
        let beaver_source = Rc::new(RefCell::new(DummySharedScalarSource::new()));

        // Subtract a raw scalar from a shared value
        // Assume parties hold secret shares 2 and 1 of [3]
        let shared_value1 = MpcScalar::from_u64_with_visibility(
            2u64, 
            Visibility::Shared, 
            network.clone(), 
            beaver_source.clone()
        );
        network.borrow_mut()
            .add_mock_scalars(vec![Scalar::from(1u8)]);
        
        let res = &shared_value1 - Scalar::from(2u8);
        assert_eq!(res.visibility, Visibility::Shared);
        assert_eq!(
            res.open().unwrap(),
            MpcScalar::from_u64(1u64, network.clone(), beaver_source.clone())
        );

        // Subtract two shared values
        let shared_value2 = MpcScalar::from_u64_with_visibility(
            5, 
            Visibility::Shared, 
            network.clone(), 
            beaver_source.clone()
        );
        network.borrow_mut()
            .add_mock_scalars(vec![Scalar::from(2u8)]);
        
        let res = shared_value2 - shared_value1;
        assert_eq!(res.visibility, Visibility::Shared);
        assert_eq!(
            res.open().unwrap(),
            MpcScalar::from_u64(5, network, beaver_source)
        )
    }

    #[test]
    fn test_mul() {
        let network = Rc::new(RefCell::new(DummyMpcNetwork::new()));
        let beaver_source = Rc::new(RefCell::new(DummySharedScalarSource::new()));

        // Multiply a scalar with a shared value
        // Assume both parties have a sharing of [11], local party holds 6
        let shared_value1 = MpcScalar::from_u64_with_visibility(
            6u64, 
            Visibility::Shared, 
            network.clone(), 
            beaver_source.clone()
        );

        // Populate the network mock after the multiplication; this implicitly asserts that
        // no network call was used for multiplying by a scalar (assumed public)
        let res = &shared_value1 * Scalar::from(2u8);
        assert_eq!(res.visibility, Visibility::Shared);

        network.borrow_mut()
            .add_mock_scalars(vec![Scalar::from(10u8)]);
        
        assert_eq!(
            res.open().unwrap(),
            MpcScalar::from_u64(22, network.clone(), beaver_source.clone())
        );

        // Multiply a shared value with a public value
        let public_value = MpcScalar::from_u64_with_visibility(
            3u64,
            Visibility::Public,
            network.clone(),
            beaver_source.clone(),
        );

        // As above, populate the network mock after the multiplication
        let res = public_value * &shared_value1;
        assert_eq!(res.visibility, Visibility::Shared);

        network.borrow_mut()
            .add_mock_scalars(vec![Scalar::from(15u8)]);
        assert_eq!(
            res.open().unwrap(),
            MpcScalar::from_u64(33u64, network.clone(), beaver_source.clone())
        );

        // Multiply two shared values, a beaver triplet (a, b, c) will be needed
        // Populate the network mock with two openings:
        //      1. [shared1 - a]
        //      2. [shared2 - b]
        // Assume that the parties hold [shared2] = [12] where the peer holds 7 and the local holds 5
        let shared_value2 = MpcScalar::from_u64_with_visibility(
            5u64, 
            Visibility::Shared, 
            network.clone(), 
            beaver_source.clone()
        );
        network.borrow_mut()
            .add_mock_scalars(vec![Scalar::from(5u8), Scalar::from(7u8)]);
        
        // Populate the network with the peer's res share after the computation
        let res = shared_value1 * shared_value2;
        assert_eq!(res.visibility, Visibility::Shared);

        network.borrow_mut()
            .add_mock_scalars(vec![Scalar::from(0u64)]);
        
        assert_eq!(
            res.open().unwrap(),
            MpcScalar::from_u64(12 * 11, network, beaver_source)
        )


    }

}