//! Groups logic for a Ristretto Point that contains an authenticated value
use std::{
    borrow::Borrow,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::{Identity, IsIdentity, MultiscalarMul},
};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::{
    authenticated_scalar::AuthenticatedScalar,
    beaver::SharedValueSource,
    error::{MpcError, MpcNetworkError},
    macros,
    mpc_ristretto::{MpcCompressedRistretto, MpcRistrettoPoint},
    mpc_scalar::MpcScalar,
    network::MpcNetwork,
    BeaverSource, SharedNetwork, Visibility, Visible,
};

/// An authenticated Ristretto point, wrapper around an MPC-capable Ristretto point
/// that supports method to authenticate an opened result against a shared global MAC key.
/// See SPDZ (https://eprint.iacr.org/2012/642.pdf) for a detailed discussion.
#[derive(Debug)]
pub struct AuthenticatedRistretto<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// the underlying MpcRistrettoPoint that this structure authenticates
    value: MpcRistrettoPoint<N, S>,
    /// The local party's share of the value's MAC. If the value is `x`, then
    /// parties hold an additive share of \delta * x; where \delta is the
    /// shared MAC key
    mac_share: Option<MpcRistrettoPoint<N, S>>,
    /// The local party's share of the global MAC key `\delta`. No party knows
    /// the cleartext key, only an additive share of the key.
    /// TODO: replace this with Rc<RefCell<...>> or just Rc<...>
    key_share: MpcScalar<N, S>,
    /// The visibility of the value within the network
    visibility: Visibility,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone for AuthenticatedRistretto<N, S> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            mac_share: self.mac_share.clone(),
            key_share: self.key_share.clone(),
            visibility: self.visibility,
        }
    }
}

#[allow(unused_doc_comments, dead_code)]
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedRistretto<N, S> {
    #[inline]
    pub(crate) fn is_public(&self) -> bool {
        self.visibility == Visibility::Public
    }

    #[inline]
    pub(crate) fn is_shared(&self) -> bool {
        self.visibility == Visibility::Shared
    }

    #[inline]
    pub fn value(&self) -> &MpcRistrettoPoint<N, S> {
        &self.value
    }

    #[inline]
    fn mac(&self) -> Option<MpcRistrettoPoint<N, S>> {
        self.mac_share.clone()
    }

    #[inline]
    fn key_share(&self) -> MpcScalar<N, S> {
        self.key_share.clone()
    }

    #[inline]
    fn network(&self) -> SharedNetwork<N> {
        self.value().network()
    }

    #[inline]
    fn beaver_source(&self) -> BeaverSource<S> {
        self.value().beaver_source()
    }

    #[inline]
    pub fn to_ristretto(&self) -> RistrettoPoint {
        self.value().value()
    }

    /// Create a new AuthenticatedRistretto from a public/private u64 constant
    macros::impl_authenticated!(
        MpcRistrettoPoint<N, S>, from_public_u64, from_private_u64, from_u64_with_visibility, u64
    );

    macros::impl_authenticated!(
        MpcRistrettoPoint<N, S>, from_public_scalar, from_private_scalar, from_scalar_with_visibility, Scalar
    );

    macros::impl_authenticated!(
        MpcRistrettoPoint<N, S>,
        from_public_ristretto_point,
        from_private_ristretto_point,
        from_ristretto_point_with_visibility,
        RistrettoPoint
    );

    /// Create a new AuthenticatedRistretto from an existing private MpcRistrettoPoint
    pub fn from_private_mpc_ristretto(
        x: MpcRistrettoPoint<N, S>,
        key_share: MpcScalar<N, S>,
    ) -> Self {
        Self::from_mpc_ristretto_with_visibility(x, Visibility::Private, key_share)
    }

    /// Create a new AuthenticatedRistretto from an existing public MpcRistrettoPoint
    pub fn from_public_mpc_ristretto(
        x: MpcRistrettoPoint<N, S>,
        key_share: MpcScalar<N, S>,
    ) -> Self {
        Self::from_mpc_ristretto_with_visibility(x, Visibility::Public, key_share)
    }

    /// A helper method that fits the macro interface
    fn from_mpc_ristretto(
        x: MpcRistrettoPoint<N, S>,
        key_share: MpcScalar<N, S>,
        _: SharedNetwork<N>,
        _: BeaverSource<S>,
    ) -> Self {
        Self::from_public_mpc_ristretto(x, key_share)
    }

    /// Create a new AuthenticatedRistretto from an existing MpcRistrettoPoint with visiblity specified
    pub(crate) fn from_mpc_ristretto_with_visibility(
        x: MpcRistrettoPoint<N, S>,
        visibility: Visibility,
        key_share: MpcScalar<N, S>,
    ) -> Self {
        Self {
            value: x,
            visibility,
            key_share,
            mac_share: None, // Will be filled in when shared
        }
    }

    // Create a random authenticated Ristretto point, assumed private
    pub fn random<R: RngCore + CryptoRng>(
        rng: &mut R,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self {
            value: MpcRistrettoPoint::random(rng, network, beaver_source),
            visibility: Visibility::Private,
            mac_share: None, // Private values don't have MACs
            key_share,
        }
    }

    macros::impl_authenticated!(MpcRistrettoPoint<N, S>, identity);
    macros::impl_authenticated!(MpcRistrettoPoint<N, S>, default);

    pub fn compress(&self) -> AuthenticatedCompressedRistretto<N, S> {
        AuthenticatedCompressedRistretto {
            value: self.value().compress(),
            visibility: self.visibility,
            mac_share: self.mac().map(|val| val.compress()),
            key_share: self.key_share(),
        }
    }
}

/**
 * Secret sharing implementation
 */

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedRistretto<N, S> {
    /// From a private value, the <party_id>'th party distributes additive shares of
    /// their local value to the other parties. Togther they use the Beaver trick
    /// to also obtain a secret sharing of the value's MAC under the shared key
    pub fn share_secret(
        &self,
        party_id: u64,
    ) -> Result<AuthenticatedRistretto<N, S>, MpcNetworkError> {
        // Share the value and then create the mac
        let my_share = self.value().share_secret(party_id)?;
        let my_mac_share = &self.key_share() * &my_share;

        Ok(Self {
            value: my_share,
            visibility: Visibility::Shared,
            mac_share: Some(my_mac_share),
            key_share: self.key_share(),
        })
    }

    /// From a shared value, both parties distribute their shares of the underlying value
    /// The parties locally sum all shares to reconstruct the value
    pub fn open(&self) -> Result<AuthenticatedRistretto<N, S>, MpcNetworkError> {
        Ok(Self {
            value: self.value().open()?,
            visibility: Visibility::Public,
            mac_share: None, // Public values have no MAC
            key_share: self.key_share(),
        })
    }

    /// From a shared value, both parties:
    ///     1. Distribute their shares of the underlying value, compute the sum to reveal the plaintext
    ///     2. Compute and commit to their share of \key_share * value - \mac_share
    ///     3. Open their commitments to the other party, and verify that the shares sum to zero
    pub fn open_and_authenticate(&self) -> Result<AuthenticatedRistretto<N, S>, MpcError> {
        // If the value is not shard, there is nothing to open or authenticate
        if !self.is_shared() {
            return Ok(self.clone());
        }

        // 1. Open the underlying value
        let opened_value = self.value().open().map_err(MpcError::NetworkError)?;

        // 2. Commit to the value key_share * value - mac_share, then open the values and check commitments
        let mac_check_share = &self.key_share * &opened_value - self.mac().unwrap();

        // 3. Verify the authenticated mac check shares sum to zero
        if mac_check_share
            .commit_and_open()?
            .value()
            .ne(&RistrettoPoint::identity())
        {
            return Err(MpcError::AuthenticationError);
        }

        Ok(Self {
            value: opened_value,
            visibility: Visibility::Public,
            key_share: self.key_share(),
            mac_share: None, // Public value has no MAC
        })
    }
}

/**
 * Generic trait implementations
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Visible for AuthenticatedRistretto<N, S> {
    fn visibility(&self) -> Visibility {
        self.visibility
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> PartialEq
    for AuthenticatedRistretto<N, S>
{
    fn eq(&self, other: &Self) -> bool {
        self.value().eq(other.value())
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Eq for AuthenticatedRistretto<N, S> {}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> ConstantTimeEq
    for AuthenticatedRistretto<N, S>
{
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value().ct_eq(other.value())
    }
}

/**
 * Mul and variants for borrowed, non-borrowed values
 */
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a AuthenticatedScalar<N, S>>
    for &'a AuthenticatedRistretto<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    fn mul(self, rhs: &'a AuthenticatedScalar<N, S>) -> Self::Output {
        let value = self.value() * rhs.value();
        let mac = {
            // Public * public results in a public value, which has no MAC
            if self.is_public() && rhs.is_public() {
                None
            } else if self.is_shared() && rhs.is_shared() {
                Some(&value * self.key_share())
            } else if rhs.is_public() {
                Some(self.mac().unwrap() * rhs.value())
            }
            // Left hand side is public
            else {
                Some(rhs.mac().unwrap() * self.value())
            }
        };

        Self::Output {
            value,
            visibility: Visibility::min_visibility_two(self, rhs),
            mac_share: mac,
            key_share: self.key_share(),
        }
    }
}

macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, MulAssign, mul_assign, *, AuthenticatedScalar<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, MulAssign, mul_assign, *, Scalar);
macros::impl_arithmetic_wrapper!(AuthenticatedRistretto<N, S>, Mul, mul, *, AuthenticatedScalar<N, S>);

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<Scalar>
    for &'a AuthenticatedRistretto<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    fn mul(self, rhs: Scalar) -> Self::Output {
        self * AuthenticatedScalar::from_public_scalar(
            rhs,
            self.key_share(),
            self.network(),
            self.beaver_source(),
        )
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<Scalar>
    for AuthenticatedRistretto<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    fn mul(self, rhs: Scalar) -> Self::Output {
        &self * rhs
    }
}

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a MpcScalar<N, S>>
    for &'a AuthenticatedRistretto<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    fn mul(self, rhs: &'a MpcScalar<N, S>) -> Self::Output {
        self * rhs.value()
    }
}

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<MpcScalar<N, S>>
    for &'a AuthenticatedRistretto<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    fn mul(self, rhs: MpcScalar<N, S>) -> Self::Output {
        self * &rhs
    }
}

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a MpcScalar<N, S>>
    for AuthenticatedRistretto<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    fn mul(self, rhs: &'a MpcScalar<N, S>) -> Self::Output {
        &self * rhs
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<MpcScalar<N, S>>
    for AuthenticatedRistretto<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    fn mul(self, rhs: MpcScalar<N, S>) -> Self::Output {
        &self * &rhs
    }
}

/// Multiplication with AuthenticatedScalar on the LHS
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a AuthenticatedRistretto<N, S>>
    for &'a AuthenticatedScalar<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    fn mul(self, rhs: &'a AuthenticatedRistretto<N, S>) -> Self::Output {
        rhs * self
    }
}

macros::impl_arithmetic_wrapper!(
    AuthenticatedScalar<N, S>, Mul, mul, *, AuthenticatedRistretto<N, S>, Output=AuthenticatedRistretto<N, S>
);

/// Multiplication with MpcScalar on the LHS
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a AuthenticatedRistretto<N, S>>
    for &'a MpcScalar<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    fn mul(self, rhs: &'a AuthenticatedRistretto<N, S>) -> Self::Output {
        rhs * self
    }
}

macros::impl_arithmetic_wrapper!(
    MpcScalar<N, S>, Mul, mul, *, AuthenticatedRistretto<N, S>, Output=AuthenticatedRistretto<N, S>
);

/// Multiplication with Scalar on the LHS
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a AuthenticatedRistretto<N, S>>
    for Scalar
{
    type Output = AuthenticatedRistretto<N, S>;

    fn mul(self, rhs: &'a AuthenticatedRistretto<N, S>) -> Self::Output {
        rhs * self
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<AuthenticatedRistretto<N, S>>
    for Scalar
{
    type Output = AuthenticatedRistretto<N, S>;

    fn mul(self, rhs: AuthenticatedRistretto<N, S>) -> Self::Output {
        &rhs * self
    }
}

/**
 * Add and variants for borrowed, non-borrowed values
 */
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Add<&'a AuthenticatedRistretto<N, S>>
    for &'a AuthenticatedRistretto<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    fn add(self, rhs: &'a AuthenticatedRistretto<N, S>) -> Self::Output {
        // For a public value + a scalar value; always put the public value on the RHS
        if self.is_public() && rhs.is_shared() {
            return rhs + self;
        }

        let mac_share = {
            // The unwraps below are appropriately handled by this fist case, if a value
            // is shared, it will have a MAC
            if self.is_public() && rhs.is_public() {
                None
            } else if rhs.is_public() {
                Some(self.mac().unwrap() + &self.key_share() * rhs.value())
            } else {
                Some(self.mac().unwrap() + rhs.mac().unwrap())
            }
        };

        Self::Output {
            value: self.value() + rhs.value(),
            visibility: Visibility::min_visibility_two(self, rhs),
            mac_share,
            key_share: self.key_share(),
        }
    }
}

macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, AddAssign, add_assign, +, AuthenticatedRistretto<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, AddAssign, add_assign, +, RistrettoPoint);
macros::impl_arithmetic_wrapper!(AuthenticatedRistretto<N, S>, Add, add, +, AuthenticatedRistretto<N, S>);
macros::impl_arithmetic_wrapped_authenticated!(
    AuthenticatedRistretto<N, S>, Add, add, +, from_public_ristretto_point, RistrettoPoint
);
macros::impl_arithmetic_wrapped_authenticated!(
    AuthenticatedRistretto<N, S>, Add, add, +, from_mpc_ristretto, MpcRistrettoPoint<N, S>
);

/**
 * Sub and variants for borrowed, non-borrowed values
 */
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Sub<&'a AuthenticatedRistretto<N, S>>
    for &'a AuthenticatedRistretto<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &'a AuthenticatedRistretto<N, S>) -> Self::Output {
        self + rhs.neg()
    }
}

macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, SubAssign, sub_assign, -, AuthenticatedRistretto<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, SubAssign, sub_assign, -, Scalar);
macros::impl_arithmetic_wrapper!(AuthenticatedRistretto<N, S>, Sub, sub, -, AuthenticatedRistretto<N, S>);
macros::impl_arithmetic_wrapped_authenticated!(
    AuthenticatedRistretto<N, S>, Sub, sub, -, from_public_scalar, Scalar
);
macros::impl_arithmetic_wrapped_authenticated!(
    AuthenticatedRistretto<N, S>, Sub, sub, -, from_mpc_ristretto, MpcRistrettoPoint<N, S>
);

/**
 * Neg and variants for borrowed, non-borrowed values
 */
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Neg
    for &'a AuthenticatedRistretto<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    fn neg(self) -> Self::Output {
        Self::Output {
            value: self.value().neg(),
            visibility: self.visibility(),
            mac_share: self.mac().map(|value| value.neg()),
            key_share: self.key_share(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Neg for AuthenticatedRistretto<N, S> {
    type Output = AuthenticatedRistretto<N, S>;

    fn neg(self) -> Self::Output {
        (&self).neg()
    }
}

/**
 * Iterator traits
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MultiscalarMul
    for AuthenticatedRistretto<N, S>
{
    type Point = Self;

    fn multiscalar_mul<I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator,
        I::Item: std::borrow::Borrow<Scalar>,
        J: IntoIterator,
        J::Item: std::borrow::Borrow<Self::Point>,
    {
        let mut peekable = points.into_iter().peekable();
        let (key_share, network, beaver_source) = {
            let first_elem: &AuthenticatedRistretto<N, S> = peekable.peek().unwrap().borrow();
            (
                first_elem.key_share(),
                first_elem.network(),
                first_elem.beaver_source(),
            )
        };

        scalars.into_iter().zip(peekable.into_iter()).fold(
            AuthenticatedRistretto::identity(key_share, network, beaver_source),
            |acc, pair| acc + *pair.0.borrow() * pair.1.borrow(),
        )
    }
}

/**
 * Compressed Representation
 */

/// An authenticated CompressedRistrettoPoint where authentication is over the decompressed version
#[derive(Clone, Debug)]
pub struct AuthenticatedCompressedRistretto<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The underlying value that this structure authenticates
    value: MpcCompressedRistretto<N, S>,
    /// The visibility of this Ristretto point to peers in the network
    visibility: Visibility,
    /// The share of the MAC for this value
    mac_share: Option<MpcCompressedRistretto<N, S>>,
    /// The share of the MAC key held by the local party
    key_share: MpcScalar<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedCompressedRistretto<N, S> {
    pub fn decompress(&self) -> Option<AuthenticatedRistretto<N, S>> {
        let new_mac = match &self.mac_share {
            None => None,
            Some(val) => Some(val.decompress()?),
        };

        Some(AuthenticatedRistretto {
            value: self.value.decompress()?,
            visibility: self.visibility,
            mac_share: new_mac,
            key_share: self.key_share.clone(),
        })
    }

    /// View this CompressedRistretto as an array of bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.value.as_bytes()
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> IsIdentity
    for AuthenticatedCompressedRistretto<N, S>
{
    fn is_identity(&self) -> bool {
        self.value.is_identity()
    }
}
