//! Implements an authenticated wrapper around the MpcScalar type for malicious security

use std::ops::Index;

use curve25519_dalek::scalar::Scalar;
use subtle::ConstantTimeEq;



use crate::{network::MpcNetwork, mpc_scalar::MpcScalar, beaver::SharedValueSource, Visibility, SharedNetwork, BeaverSource, macros, error::MpcNetworkError};


/// An authenticated scalar, wrapper around an MPC-capable Scalar that supports methods
/// to authenticate an opened result against a shared global MAC.
/// See SPDZ (https://eprint.iacr.org/2012/642.pdf) for a detailed explanation.
#[allow(dead_code)]
#[derive(Debug)]
pub struct AuthenticatedScalar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The underlying MpcScalar that this structure authenticates 
    value: MpcScalar<N, S>,
    /// The local party's share of the value's MAC. If the value is `x`, then
    /// parties hold an additive share of \delta * x; where \delta is the
    /// shared MAC key
    mac_share: Option<MpcScalar<N, S>>,
    /// The local party's share of the global MAC key `\delta`. No party knows
    /// the cleartext key, only an additive share of the key.
    key_share: MpcScalar<N, S>,
    /// The visibility of the value within the network
    visibility: Visibility,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone for AuthenticatedScalar<N, S> {
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
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedScalar<N, S> {
    #[inline]
    pub(crate) fn is_public(&self) -> bool {
        self.visibility == Visibility::Public
    }

    #[inline]
    pub fn value(&self) -> MpcScalar<N, S> {
        self.value
    }

    /// Create a new AuthenticatedScalar from a public u64 constant
    macros::impl_authenticated!(
        MpcScalar<N, S>, from_public_u64, from_private_u64, from_u64_with_visibility, u64
    );

    /// Create a new AuthenticatedScalar from a public Scalar constant
    macros::impl_authenticated!(
        MpcScalar<N, S>, from_public_scalar, from_private_scalar, from_scalar_with_visibility, Scalar
    );

    macros::impl_authenticated!(MpcScalar<N, S>, zero);
    macros::impl_authenticated!(MpcScalar<N, S>, one);
    macros::impl_authenticated!(MpcScalar<N, S>, default);

    macros::impl_authenticated!(
        MpcScalar<N, S>, 
        from_public_bytes_mod_order, 
        from_private_bytes_mod_order, 
        from_bytes_mod_order_with_visibility,
        [u8; 32]
    );

    macros::impl_authenticated!(
        MpcScalar<N, S>,
        from_bytes_mod_order_wide,
        from_public_bytes_mod_order_wide,
        from_bytes_mod_order_wide_with_visibility,
        &[u8; 64]
    );

    pub fn from_public_canonical_bytes_with_visibility(
        bytes: [u8; 32], visibility: Visibility, key_share: MpcScalar<N, S>, network: SharedNetwork<N>, beaver_source: BeaverSource<S>
    ) -> Option<Self> {
        let value = MpcScalar::<N, S>::from_canonical_bytes_with_visibility(bytes, Visibility::Public, network, beaver_source)?;

        Some(
            Self {
                value,
                visibility,
                mac_share: None,
                key_share,
            }
        )
    }

    macros::impl_authenticated!(
        MpcScalar<N, S>,
        from_public_bits,
        from_private_bits,
        from_bits_with_visibility,
        [u8; 32]
    );

    macros::impl_delegated!(to_bytes, self, [u8; 32]);
    macros::impl_delegated!(as_bytes, self, &[u8; 32]);
    macros::impl_delegated!(is_canonical, self, bool);
}

/**
 * Secret sharing implementation
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedScalar<N, S> {
    /// Shares a value with the counterparty, and creates a MAC for it using the global key
    pub fn share_secret(&self, party_id: u64) -> Result<AuthenticatedScalar<N, S>, MpcNetworkError> {
        // Share the underlying value then construct a MAC share with the counterparty
        let my_share = self.value.share_secret(party_id)?;
        let my_mac_share = &self.key_share * &my_share;

        Ok(
            Self {
                value: my_share,
                visibility: Visibility::Shared,
                key_share: self.key_share.clone(),
                mac_share: Some(my_mac_share),
            }
        )
    }

    /// From a shared value, both parties broadcast their shares and reconstruct the plaintext.
    /// The parties no longer hold a valid secret sharing of the result, they hold the result itself.
    pub fn open(&self) -> Result<AuthenticatedScalar<N, S>, MpcNetworkError> {
        if self.is_public() {
            return Ok(self.clone())
        }

        Ok(
            Self {
                value: self.value.open()?,
                visibility: Visibility::Public,
                key_share: self.key_share.clone(),
                mac_share: self.mac_share.clone(),
            }
        )
    }

    /// Open the value and authenticate it using the MAC. This works in ___ steps:
    ///     1. The parties open the value
    ///     2. The parites each commit to key_share * value - mac_share
    ///     3. The parties open these commitments and add them; if equal to 0
    ///        the value is authenticated
    pub fn open_and_authenticate(&self) -> Result<AuthenticatedScalar<N, S>, MpcNetworkError> {
        unimplemented!("Not implemented yet...");
    }
}

/**
 * Generic trait implementations
 */

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> PartialEq for AuthenticatedScalar<N, S> {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq(&other.value())
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> ConstantTimeEq for AuthenticatedScalar<N, S> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value.ct_eq(&other.value())
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Index<usize> for AuthenticatedScalar<N, S> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        self.value.index(index)
    }
}
