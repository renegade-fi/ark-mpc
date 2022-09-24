//! Groups logic for a Ristretto Point that contains an authenticated value

use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint};


use crate::{network::MpcNetwork, beaver::SharedValueSource, mpc_ristretto::MpcRistrettoPoint, mpc_scalar::MpcScalar, Visibility, SharedNetwork, BeaverSource, macros};


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

#[allow(unused_doc_comments)]
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

    macros::impl_authenticated!(MpcRistrettoPoint<N, S>, identity);
    macros::impl_authenticated!(MpcRistrettoPoint<N, S>, default);
}
