//! Groups logic for a Ristretto Point that contains an authenticated value
use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint};
use rand_core::{RngCore, CryptoRng};
use subtle::ConstantTimeEq;

use crate::{network::{MpcNetwork}, beaver::SharedValueSource, mpc_ristretto::{MpcRistrettoPoint, MpcCompressedRistretto}, mpc_scalar::MpcScalar, Visibility, SharedNetwork, BeaverSource, macros, Visible};


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
    pub fn from_private_mpc_ristretto(x: MpcRistrettoPoint<N, S>, key_share: MpcScalar<N, S>) -> Self {
        Self::from_mpc_ristretto_with_visibility(x, Visibility::Private, key_share)
    }

    /// Create a new AuthenticatedRistretto from an existing public MpcRistrettoPoint
    pub fn from_public_mpc_ristretto(x: MpcRistrettoPoint<N, S>, key_share: MpcScalar<N, S>) -> Self {
        Self::from_mpc_ristretto_with_visibility(x, Visibility::Public, key_share)
    }

    /// Create a new AuthenticatedRistretto from an existing MpcRistrettoPoint with visiblity specified
    pub(crate) fn from_mpc_ristretto_with_visibility(
        x: MpcRistrettoPoint<N, S>,
        visibility: Visibility,
        key_share: MpcScalar<N, S>
    ) -> Self {
        Self {
            value: x,
            visibility,
            key_share,
            mac_share: None,  // Will be filled in when shared
        }
    }

    // Create a random authenticated Ristretto point, assumed private
    pub fn random<R: RngCore + CryptoRng>(
        rng: &mut R,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>
    ) -> Self {
        Self {
            value: MpcRistrettoPoint::random(rng, network, beaver_source),
            visibility: Visibility::Private,
            mac_share: None,  // Private values don't have MACs
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

/**
 * Generic trait implementations
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Visible for AuthenticatedRistretto<N, S> {
    fn visibility(&self) -> Visibility {
        self.visibility
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> PartialEq for AuthenticatedRistretto<N, S> {
    fn eq(&self, other: &Self) -> bool {
        self.value().eq(other.value())
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Eq for AuthenticatedRistretto<N, S> {}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> ConstantTimeEq for AuthenticatedRistretto<N, S> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value().ct_eq(other.value())
    }
}

/**
 * Mul and variants for borrowed, non-borrowed values
 */


/**
 * Add and variants for borrowed, non-borrowed values
 */


/**
 * Sub and variants for borrowed, non-borrowed values
 */

/**
 * Neg and variants for borrowed, non-borrowed values
 */

/**
 * Compressed Representation
 */

/// An authenticated CompressedRistrettoPoint where authentication is over the decompressed version
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
            Some(val) => Some(val.decompress()?)
        };

        Some(
            AuthenticatedRistretto {
                value: self.value.decompress()?,
                visibility: self.visibility,
                mac_share: new_mac,
                key_share: self.key_share.clone()
            }
        )
    }
}
