//! Groups logic for a Ristretto Point that contains an authenticated value
use std::{
    borrow::Borrow,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use clear_on_drop::clear::Clear;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};

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
    pub fn is_public(&self) -> bool {
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

    #[inline]
    /// Recompute the MAC of the given value
    pub(crate) fn recompute_mac(&mut self) {
        self.mac_share = Some(&self.key_share * &self.value)
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

    /// Create a new AuthenticatedRistretto from an existing MpcRistrettoPoint with visibility specified
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

    pub fn batch_compress(
        points: &[AuthenticatedRistretto<N, S>],
    ) -> Vec<AuthenticatedCompressedRistretto<N, S>> {
        points.iter().map(|point| point.compress()).collect()
    }
}

/**
 * Secret sharing implementation
 */

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedRistretto<N, S> {
    /// From a private value, the <party_id>'th party distributes additive shares of
    /// their local value to the other parties. Together they use the Beaver trick
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

    /// Secret share a batch of privately held `AuthenticatedRistretto`s
    pub fn batch_share_secrets(
        party_id: u64,
        secrets: &[AuthenticatedRistretto<N, S>],
    ) -> Result<Vec<AuthenticatedRistretto<N, S>>, MpcNetworkError> {
        assert!(
            !secrets.is_empty(),
            "Cannot batch share secrets of empty vector"
        );

        let key_share = secrets[0].key_share();

        // Batch secret share the underlying values
        let my_shares = MpcRistrettoPoint::batch_share_secrets(
            party_id,
            &secrets
                .iter()
                .map(|secret| secret.value().clone())
                .collect::<Vec<MpcRistrettoPoint<_, _>>>(),
        )?;

        // Compute the MACs for the newly shared values
        #[allow(clippy::needless_collect)]
        let my_mac_shares: Vec<MpcRistrettoPoint<N, S>> = my_shares
            .iter()
            .map(|share| &key_share.clone() * share)
            .collect();

        Ok(my_shares
            .into_iter()
            .zip(my_mac_shares.into_iter())
            .map(|(value, mac)| AuthenticatedRistretto {
                value,
                visibility: Visibility::Shared,
                key_share: key_share.clone(),
                mac_share: Some(mac),
            })
            .collect())
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

    /// Open a batch of shared values
    pub fn batch_open(
        values: &[AuthenticatedRistretto<N, S>],
    ) -> Result<Vec<AuthenticatedRistretto<N, S>>, MpcNetworkError> {
        assert!(!values.is_empty(), "Cannot batch open an empty vector");

        let key_share = values[0].key_share();

        // Open the values
        let opened_values = MpcRistrettoPoint::batch_open(
            &values
                .iter()
                .map(|shared_value| shared_value.value().clone())
                .collect::<Vec<MpcRistrettoPoint<_, _>>>(),
        )?;

        // Reconstruct from opened shares
        Ok(opened_values
            .into_iter()
            .map(|value| {
                AuthenticatedRistretto {
                    value,
                    visibility: Visibility::Public,
                    key_share: key_share.clone(),
                    mac_share: None, // Public values have no mac
                }
            })
            .collect())
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

    /// Open and authenticate a batch of shared values
    pub fn batch_open_and_authenticate(
        values: &[AuthenticatedRistretto<N, S>],
    ) -> Result<Vec<AuthenticatedRistretto<N, S>>, MpcError> {
        assert!(
            !values.is_empty(),
            "Cannot batch open and authenticate an empty vector"
        );

        let key_share = values[0].key_share();

        // 1. Open the underlying values
        let opened_values = MpcRistrettoPoint::batch_open(
            &values
                .iter()
                .map(|shared_value| shared_value.value().clone())
                .collect::<Vec<MpcRistrettoPoint<_, _>>>(),
        )
        .map_err(MpcError::NetworkError)?;

        // 2. Commit to the value key_share * value - mac_share, then open the values and check commitments
        let mac_check_shares = opened_values
            .iter()
            .zip(values.iter())
            .map(|(opened_value, original_value)| {
                // If the value is public (already opened) add a dummy value for the MAC
                if original_value.is_public() {
                    MpcRistrettoPoint::identity(
                        original_value.network(),
                        original_value.beaver_source(),
                    )
                } else {
                    &key_share * opened_value - &original_value.mac().unwrap()
                }
            })
            .collect::<Vec<MpcRistrettoPoint<_, _>>>();

        // 3. Verify that the MACs pass the authentication check
        MpcRistrettoPoint::batch_commit_and_open(&mac_check_shares)?
            .iter()
            .try_for_each(|commit_result| {
                if commit_result.value().ne(&RistrettoPoint::identity()) {
                    return Err(MpcError::AuthenticationError);
                }

                Ok(())
            })?;

        // Reconstruct the plaintext from the shared values
        Ok(opened_values
            .into_iter()
            .map(|value| AuthenticatedRistretto {
                value,
                visibility: Visibility::Public,
                key_share: key_share.clone(),
                mac_share: None, // Public values have no MAC
            })
            .collect::<Vec<AuthenticatedRistretto<_, _>>>())
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

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clear for AuthenticatedRistretto<N, S> {
    #[allow(clippy::needless_borrow)]
    fn clear(&mut self) {
        (&mut self.value).clear();
        (&mut self.mac_share).clear();
        (&mut self.key_share).clear();
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

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a AuthenticatedRistretto<N, S>>
    for &'a AuthenticatedScalar<N, S>
{
    type Output = AuthenticatedRistretto<N, S>;

    fn mul(self, rhs: &'a AuthenticatedRistretto<N, S>) -> Self::Output {
        rhs * self
    }
}

macros::impl_operator_variants!(AuthenticatedRistretto<N, S>, Mul, mul, *, AuthenticatedScalar<N, S>);
macros::impl_operator_variants!(AuthenticatedScalar<N, S>, Mul, mul, *, AuthenticatedRistretto<N, S>, Output=AuthenticatedRistretto<N, S>);
macros::impl_wrapper_type!(
    AuthenticatedRistretto<N, S>,
    MpcScalar<N, S>,
    AuthenticatedScalar::from_mpc_scalar,
    Mul,
    mul,
    *,
    authenticated=true
);
macros::impl_wrapper_type!(AuthenticatedRistretto<N, S>, Scalar, AuthenticatedScalar::from_public_scalar, Mul, mul, *, authenticated=true);
macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, MulAssign, mul_assign, *, AuthenticatedScalar<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, MulAssign, mul_assign, *, MpcScalar<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, MulAssign, mul_assign, *, Scalar);

// Implement multiplication between an authenticated scalar and a non-authenticated Ristretto point
macros::impl_wrapper_type!(
    AuthenticatedScalar<N, S>,
    RistrettoPoint,
    AuthenticatedRistretto::from_public_ristretto_point,
    Mul,
    mul,
    *,
    Output=AuthenticatedRistretto<N, S>,
    authenticated=true
);

macros::impl_wrapper_type!(
    AuthenticatedScalar<N, S>,
    MpcRistrettoPoint<N, S>,
    AuthenticatedRistretto::from_mpc_ristretto,
    Mul,
    mul,
    *,
    Output=AuthenticatedRistretto<N, S>,
    authenticated=true
);

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

macros::impl_operator_variants!(AuthenticatedRistretto<N, S>, Add, add, +, AuthenticatedRistretto<N, S>);
macros::impl_wrapper_type!(
    AuthenticatedRistretto<N, S>,
    MpcRistrettoPoint<N, S>,
    AuthenticatedRistretto::from_mpc_ristretto,
    Add,
    add,
    +,
    authenticated=true
);
macros::impl_wrapper_type!(
    AuthenticatedRistretto<N, S>,
    RistrettoPoint,
    AuthenticatedRistretto::from_public_ristretto_point,
    Add,
    add,
    +,
    authenticated=true
);
macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, AddAssign, add_assign, +, AuthenticatedRistretto<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, AddAssign, add_assign, +, MpcRistrettoPoint<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, AddAssign, add_assign, +, RistrettoPoint);

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

macros::impl_operator_variants!(AuthenticatedRistretto<N, S>, Sub, sub, -, AuthenticatedRistretto<N, S>);
macros::impl_wrapper_type!(
    AuthenticatedRistretto<N, S>,
    MpcRistrettoPoint<N, S>,
    AuthenticatedRistretto::from_mpc_ristretto,
    Sub,
    sub,
    -,
    authenticated=true
);
macros::impl_wrapper_type!(
    AuthenticatedRistretto<N, S>,
    RistrettoPoint,
    AuthenticatedRistretto::from_public_ristretto_point,
    Sub,
    sub,
    -,
    authenticated=true
);
macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, SubAssign, sub_assign, -, AuthenticatedRistretto<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, SubAssign, sub_assign, -, MpcRistrettoPoint<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedRistretto<N, S>, SubAssign, sub_assign, -, RistrettoPoint);

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
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedRistretto<N, S> {
    /// Multiscalar multiplication, for scalars a_1, ..., a_n and points
    /// B_1, ..., B_n; this function computes a_1 * B_1 + ... + a_n * B_n
    pub fn multiscalar_mul<I, J>(scalars: I, points: J) -> Self
    where
        I: IntoIterator,
        I::Item: std::borrow::Borrow<AuthenticatedScalar<N, S>>,
        J: IntoIterator,
        J::Item: std::borrow::Borrow<Self>,
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

        scalars.into_iter().zip(peekable).fold(
            AuthenticatedRistretto::identity(key_share, network, beaver_source),
            |acc, pair| acc + pair.0.borrow() * pair.1.borrow(),
        )
    }
}

/**
 * Compressed Representation
 */

/// An authenticated CompressedRistrettoPoint where authentication is over the decompressed version
#[derive(Debug)]
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

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone
    for AuthenticatedCompressedRistretto<N, S>
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            visibility: self.visibility,
            mac_share: self.mac_share.clone(),
            key_share: self.key_share.clone(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedCompressedRistretto<N, S> {
    /// Get the underlying CompressedRistretto point
    pub fn value(&self) -> CompressedRistretto {
        self.value.value()
    }

    /// Allocate a public AuthenticatedCompressedRistretto value from a byte buffer
    pub fn from_public_bytes(
        buf: &[u8; 32],
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_bytes_with_visibility(buf, Visibility::Public, key_share, network, beaver_source)
    }

    /// Allocate a private AuthenticatedCompressedRistretto value from a byte buffer
    pub fn from_private_bytes(
        buf: &[u8; 32],
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_bytes_with_visibility(
            buf,
            Visibility::Private,
            key_share,
            network,
            beaver_source,
        )
    }

    pub(crate) fn from_bytes_with_visibility(
        buf: &[u8; 32],
        visibility: Visibility,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self {
            value: MpcCompressedRistretto::from_bytes_with_visibility(
                buf,
                visibility,
                network,
                beaver_source,
            ),
            visibility,
            key_share,
            mac_share: None, // Filled in when value is shared
        }
    }

    /// Allocate from a public CompressedRistretto point
    pub fn from_public_compressed_ristretto(
        value: CompressedRistretto,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_compressed_ristretto_with_visibility(
            value,
            Visibility::Public,
            key_share,
            network,
            beaver_source,
        )
    }

    /// Allocate from a private CompressedRistretto point
    pub fn from_private_compressed_ristretto(
        value: CompressedRistretto,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_compressed_ristretto_with_visibility(
            value,
            Visibility::Private,
            key_share,
            network,
            beaver_source,
        )
    }

    pub(crate) fn from_compressed_ristretto_with_visibility(
        value: CompressedRistretto,
        visibility: Visibility,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self {
            value: MpcCompressedRistretto::from_compressed_ristretto_with_visibility(
                value,
                visibility,
                network,
                beaver_source,
            ),
            visibility,
            key_share,
            mac_share: None, // Filled in after sharing
        }
    }

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

    pub fn batch_decompress(
        points: &[AuthenticatedCompressedRistretto<N, S>],
    ) -> Option<Vec<AuthenticatedRistretto<N, S>>> {
        points.iter().map(|point| point.decompress()).collect()
    }

    /// View this CompressedRistretto as an array of bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.value.as_bytes()
    }

    /// Create the identity point wrapped in an AuthenticatedRistretto
    pub fn identity(
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> AuthenticatedCompressedRistretto<N, S> {
        AuthenticatedCompressedRistretto {
            value: MpcCompressedRistretto::identity(network, beaver_source),
            visibility: Visibility::Public,
            mac_share: None,
            key_share,
        }
    }
}

/// Secret sharing implementation
///
/// Roughly speaking, these methods decompress the value(s), operate on them
/// via methods on the decompressed type, then re-compress them
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedCompressedRistretto<N, S> {
    /// Open a single compressed ristretto point
    pub fn open(&self) -> Result<Self, MpcError> {
        Ok(self
            .decompress()
            .ok_or_else(|| MpcError::ArithmeticError("error decompressing point".to_string()))?
            .open()
            .map_err(MpcError::NetworkError)?
            .compress())
    }

    /// Open a set of compressed ristrettos
    pub fn batch_open(points: &[Self]) -> Result<Vec<Self>, MpcError> {
        let decompressed = Self::batch_decompress(points)
            .ok_or_else(|| MpcError::ArithmeticError("error decompressing points".to_string()))?;
        let opened =
            AuthenticatedRistretto::batch_open(&decompressed).map_err(MpcError::NetworkError)?;
        Ok(AuthenticatedRistretto::batch_compress(&opened))
    }

    /// Open and authenticated a compressed Ristretto point
    pub fn open_and_authenticate(&self) -> Result<Self, MpcError> {
        Ok(self
            .decompress()
            .ok_or_else(|| MpcError::ArithmeticError("error decompressing point".to_string()))?
            .open_and_authenticate()?
            .compress())
    }

    /// Open and authenticate a set of compressed Ristretto points
    pub fn batch_open_and_authenticate(points: &[Self]) -> Result<Vec<Self>, MpcError> {
        let decompressed = Self::batch_decompress(points)
            .ok_or_else(|| MpcError::ArithmeticError("error decompressing points".to_string()))?;
        let opened = AuthenticatedRistretto::batch_open_and_authenticate(&decompressed)?;
        Ok(AuthenticatedRistretto::batch_compress(&opened))
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> IsIdentity
    for AuthenticatedCompressedRistretto<N, S>
{
    fn is_identity(&self) -> bool {
        self.value.is_identity()
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> ConstantTimeEq
    for AuthenticatedCompressedRistretto<N, S>
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&other.value)
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clear
    for AuthenticatedCompressedRistretto<N, S>
{
    #[allow(clippy::needless_borrow)]
    fn clear(&mut self) {
        (&mut self.value).clear();
    }
}

#[cfg(test)]
mod authenticated_ristretto_tests {
    use std::{cell::RefCell, rc::Rc};

    use clear_on_drop::clear::Clear;
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};

    use crate::{
        beaver::DummySharedScalarSource, mpc_ristretto::MpcRistrettoPoint, mpc_scalar::MpcScalar,
        network::dummy_network::DummyMpcNetwork,
    };

    use super::AuthenticatedRistretto;

    #[test]
    fn test_clear() {
        let network = Rc::new(RefCell::new(DummyMpcNetwork::new()));
        let beaver_source = Rc::new(RefCell::new(DummySharedScalarSource::new()));
        let key_share = MpcScalar::from_public_u64(2, network.clone(), beaver_source.clone());
        let mut value = AuthenticatedRistretto::from_public_u64(
            3,
            key_share,
            network.clone(),
            beaver_source.clone(),
        );
        value.mac_share = Some(MpcRistrettoPoint::from_public_u64(
            5,
            network,
            beaver_source,
        ));

        #[allow(clippy::needless_borrow)]
        (&mut value).clear();

        assert_eq!(value.to_ristretto(), RistrettoPoint::identity());
        assert_eq!(value.mac(), None);
        assert_eq!(value.key_share().to_scalar(), Scalar::zero())
    }
}
