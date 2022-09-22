//! Implements an authenticated wrapper around the MpcScalar type for malicious security

use curve25519_dalek::scalar::Scalar;

use crate::{network::MpcNetwork, mpc_scalar::MpcScalar, beaver::SharedValueSource, Visibility, SharedNetwork, BeaverSource};


/// An authenticated scalar, wrapper around an MPC-capable Scalar that supports methods
/// to authenticate an opened result against a shared global MAC.
/// See SPDZ (https://eprint.iacr.org/2012/642.pdf) for a detailed explanation.
#[derive(Clone, Debug)]
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

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedScalar<N, S> {
    /// Create a new AuthenticatedScalar from a public u64 constant
    pub fn from_public_u64(
        value: u64,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>
    ) -> Self {
        AuthenticatedScalar::from_u64_with_visibility(
            value, 
            Visibility::Public, 
            key_share, 
            network, 
            beaver_source
        )
    }

    /// Create a new AuthenticatedScalar from a private u64 value
    pub fn from_private_u64(
        value: u64,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>
    ) -> Self {
        AuthenticatedScalar::from_u64_with_visibility(
            value, 
            Visibility::Private, 
            key_share, 
            network, 
            beaver_source
        )
    }

    /// Create a new AuthenticatedScalar from a u64 with Visibility specified
    fn from_u64_with_visibility(
        value: u64,
        visibility: Visibility,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>
    ) -> Self {
        let value = MpcScalar::from_u64_with_visibility(
            value,
            visibility,
            network,
            beaver_source,
        );

        Self { 
            value,
            mac_share: None,  // Filled in when value is shared
            key_share,
            visibility
        }
    }

    /// Create a new AuthenticatedScalar from a public Scalar constant
    pub fn from_public_scalar(
        value: Scalar,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>
    ) -> Self {
        Self::from_scalar_with_visibility(value, Visibility::Public, key_share, network, beaver_source)
    }
    
    /// Create a new AuthenticatedScalar from a private Scalar value
    pub fn from_private_scalar(
        value: Scalar,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>
    ) -> Self {
        Self::from_scalar_with_visibility(value, Visibility::Private, key_share, network, beaver_source)
    }
    
    /// Create a new AuthenticatedScalar from a Scalar with given visibility
    fn from_scalar_with_visibility(
        value: Scalar,
        visibility: Visibility,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>
    ) -> Self {
        let value = MpcScalar::from_scalar_with_visibility(
            value, visibility, network, beaver_source
        );

        Self {
            value,
            mac_share: None,  // Filled in when value is shared
            key_share,
            visibility,
        }
    }
}
