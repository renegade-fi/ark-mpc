//! Defines an MPC fabric for the protocol
//!
//! The fabric essentially acts as a dependency injection layer. That is, the MpcFabric
//! creates and manages dependencies needed to allocate network values. This provides a
//! cleaner interface for consumers of the library; i.e. clients do not have to hold onto
//! references of the network layer or the beaver sources to allocate values.

use std::{
    cell::{Ref, RefCell, RefMut},
    net::SocketAddr,
    rc::Rc,
};

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use itertools::Itertools;
use tokio::runtime::Handle;

use crate::{
    authenticated_ristretto::{AuthenticatedCompressedRistretto, AuthenticatedRistretto},
    authenticated_scalar::AuthenticatedScalar,
    beaver::SharedValueSource,
    error::MpcError,
    mpc_scalar::{scalar_to_u64, MpcScalar},
    network::{MpcNetwork, QuicTwoPartyNet},
    BeaverSource, SharedNetwork, Visibility,
};

#[derive(Clone, Debug)]
pub struct AuthenticatedMpcFabric<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The ID of this party in the MPC execution
    party_id: u64,
    /// The key share used to authenticate shared value openings
    key_share: MpcScalar<N, S>,
    /// The underlying network interface used to communicate between parties
    network: SharedNetwork<N>,
    /// The source from which the local party can draw results of the
    /// preprocessing functionality; i.e. Beaver triplets and shared scalars
    beaver_source: BeaverSource<S>,
}

impl<S: SharedValueSource<Scalar>> AuthenticatedMpcFabric<QuicTwoPartyNet, S> {
    /// Create a new AuthenticatedMpcFabric with the default (QUIC two party) network
    pub fn new(
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        beaver_source: BeaverSource<S>,
        party_id: u64,
    ) -> Result<Self, MpcError> {
        // Build the network and dial the peer
        let mut network = QuicTwoPartyNet::new(party_id, local_addr, peer_addr);
        Handle::current()
            .block_on(network.connect())
            .map_err(MpcError::NetworkError)?;

        Ok(Self::new_with_network(
            party_id,
            Rc::new(RefCell::new(network)),
            beaver_source,
        ))
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedMpcFabric<N, S> {
    /// Create a new AuthenticatedMpcFabric with a specific network implementation
    pub fn new_with_network(
        party_id: u64,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        // Create a shared key from the beaver source
        let shared_value = beaver_source.as_ref().borrow_mut().next_shared_value();
        let key_share = MpcScalar::from_scalar_with_visibility(
            shared_value,
            crate::Visibility::Shared,
            network.clone(),
            beaver_source.clone(),
        );

        Self {
            party_id,
            key_share,
            network,
            beaver_source,
        }
    }

    /// Read the party_id field
    pub fn party_id(&self) -> u64 {
        self.party_id
    }

    /// Borrow the beaver source from the fabric
    pub fn borrow_beaver_source(&self) -> Ref<S> {
        self.beaver_source.as_ref().borrow()
    }

    /// Mutably borrow the beaver source from the fabric
    pub fn borrow_beaver_source_mut(&self) -> RefMut<S> {
        self.beaver_source.as_ref().borrow_mut()
    }

    /// Allocate a single zero valued authenticated scalar
    pub fn allocate_zero(&self) -> AuthenticatedScalar<N, S> {
        AuthenticatedScalar::zero(
            self.key_share.clone(),
            self.network.clone(),
            self.beaver_source.clone(),
        )
    }

    /// Allocate a vector of zero valued authenticated scalars
    pub fn allocate_zeros(&self, n: usize) -> Vec<AuthenticatedScalar<N, S>> {
        (0..n)
            .map(|_| {
                AuthenticatedScalar::zero(
                    self.key_share.clone(),
                    self.network.clone(),
                    self.beaver_source.clone(),
                )
            })
            .collect()
    }

    /// Share a public u64 value in plaintext
    pub fn share_plaintext_u64(&self, owning_party: u64, value: u64) -> Result<u64, MpcError> {
        self.share_plaintext_scalar(owning_party, Scalar::from(value))
            .map(|val| scalar_to_u64(&val))
    }

    /// Share a batch of public u64 values in plaintext
    pub fn batch_share_plaintext_u64s(
        &self,
        owning_party: u64,
        values: &[u64],
    ) -> Result<Vec<u64>, MpcError> {
        let scalar_values = values.iter().map(|x| Scalar::from(*x)).collect_vec();
        self.batch_share_plaintext_scalars(owning_party, &scalar_values)
            .map(|values| values.iter().map(scalar_to_u64).collect_vec())
    }

    /// Share a public scalar value in plaintext
    pub fn share_plaintext_scalar(
        &self,
        owning_party: u64,
        value: Scalar,
    ) -> Result<Scalar, MpcError> {
        self.batch_share_plaintext_scalars(owning_party, &[value])
            .map(|vec| vec[0])
    }

    /// Share a batch of public scalar values in plaintext
    pub fn batch_share_plaintext_scalars(
        &self,
        owning_party: u64,
        values: &[Scalar],
    ) -> Result<Vec<Scalar>, MpcError> {
        // Mux between send and receive
        if self.party_id() == owning_party {
            Handle::current()
                .block_on(self.network.borrow_mut().send_scalars(values))
                .map_err(MpcError::NetworkError)?;

            Ok(values.to_vec())
        } else {
            let received_values = Handle::current()
                .block_on(self.network.borrow_mut().receive_scalars(values.len()))
                .map_err(MpcError::NetworkError)?;
            Ok(received_values)
        }
    }

    /// Share a serialized byte array directly
    pub fn share_bytes(&self, owning_party: u64, value: &[u8]) -> Result<Vec<u8>, MpcError> {
        if self.party_id() == owning_party {
            Handle::current()
                .block_on(self.network.borrow_mut().send_bytes(value))
                .map_err(MpcError::NetworkError)?;

            Ok(value.to_vec())
        } else {
            Handle::current()
                .block_on(self.network.borrow_mut().receive_bytes())
                .map_err(MpcError::NetworkError)
        }
    }

    /// Allocate a scalar that acts as one of the given party's private inputs to the protocol
    ///
    /// If the local party is the specified party, then this method will construct an additive sharing
    /// of the input and distribute the shares amongst the peers.
    ///
    /// If the local party is not the specified party, this method will await a share distributed by
    /// the owner of the input value.
    pub fn allocate_private_scalar(
        &self,
        owning_party: u64,
        value: Scalar,
    ) -> Result<AuthenticatedScalar<N, S>, MpcError> {
        // Create the wrapped scalar and share it
        let authenticated_value = AuthenticatedScalar::from_private_scalar(
            value,
            self.key_share.clone(),
            self.network.clone(),
            self.beaver_source.clone(),
        );

        authenticated_value
            .share_secret(owning_party)
            .map_err(MpcError::NetworkError)
    }

    /// Allocate a batch of private scalars
    pub fn batch_allocate_private_scalars(
        &self,
        owning_party: u64,
        values: &[Scalar],
    ) -> Result<Vec<AuthenticatedScalar<N, S>>, MpcError> {
        let authenticated_values = values
            .iter()
            .map(|value| {
                AuthenticatedScalar::from_private_scalar(
                    *value,
                    self.key_share.clone(),
                    self.network.clone(),
                    self.beaver_source.clone(),
                )
            })
            .collect_vec();

        AuthenticatedScalar::batch_share_secrets(owning_party, &authenticated_values)
            .map_err(MpcError::NetworkError)
    }

    /// Allocate a scalar that acts as a public value within the MPC protocol
    ///
    /// No secret shares are constructed from this, it is assumed that all parties call this method
    /// with the same (known) value
    pub fn allocate_public_scalar(&self, value: Scalar) -> AuthenticatedScalar<N, S> {
        AuthenticatedScalar::from_public_scalar(
            value,
            self.key_share.clone(),
            self.network.clone(),
            self.beaver_source.clone(),
        )
    }

    /// Allocate a batch of public scalars
    pub fn batch_allocate_public_scalar(
        &self,
        values: &[Scalar],
    ) -> Vec<AuthenticatedScalar<N, S>> {
        values
            .iter()
            .map(|value| self.allocate_public_scalar(*value))
            .collect_vec()
    }

    /// Allocate a scalar from a u64 as a private input to the MPC protocol
    pub fn allocate_private_u64(
        &self,
        owning_party: u64,
        value: u64,
    ) -> Result<AuthenticatedScalar<N, S>, MpcError> {
        self.allocate_private_scalar(owning_party, Scalar::from(value))
    }

    /// Allocate a batch of private u64s
    pub fn batch_allocate_private_u64s(
        &self,
        owning_party: u64,
        values: &[u64],
    ) -> Result<Vec<AuthenticatedScalar<N, S>>, MpcError> {
        self.batch_allocate_private_scalars(
            owning_party,
            &values.iter().map(|a| Scalar::from(*a)).collect_vec(),
        )
    }

    /// Allocate a scalar from a u64 as a public input to the MPC protocol
    pub fn allocate_public_u64(&self, value: u64) -> AuthenticatedScalar<N, S> {
        self.allocate_public_scalar(Scalar::from(value))
    }

    /// Allocate a batch of public u64s
    pub fn batch_allocate_public_u64s(&self, values: &[u64]) -> Vec<AuthenticatedScalar<N, S>> {
        values
            .iter()
            .map(|x| self.allocate_public_u64(*x))
            .collect_vec()
    }

    /// Allocate a random shared bit in the network from the pre-processing functionality (beaver source)
    ///
    /// Returns a scalar representing a shared bit
    pub fn allocate_random_shared_bit(&self) -> AuthenticatedScalar<N, S> {
        let random_bit = self.borrow_beaver_source_mut().next_shared_bit();
        let mut shared_value = AuthenticatedScalar::from_scalar_with_visibility(
            random_bit,
            Visibility::Shared,
            self.key_share.clone(),
            self.network.clone(),
            self.beaver_source.clone(),
        );

        // The value comes from the pre-processing functionality without a MAC, compute one on the fly
        shared_value.recompute_mac();
        shared_value
    }

    /// Allocate a batch of random bits in the network from the beaver source
    ///
    /// Returns a vector of scalars, each one representing a shared bit
    pub fn allocate_random_shared_bit_batch(
        &self,
        num_scalars: usize,
    ) -> Vec<AuthenticatedScalar<N, S>> {
        let random_bits = self
            .borrow_beaver_source_mut()
            .next_shared_bit_batch(num_scalars);
        random_bits
            .into_iter()
            .map(|bit| {
                let mut shared_value = AuthenticatedScalar::from_scalar_with_visibility(
                    bit,
                    Visibility::Shared,
                    self.key_share.clone(),
                    self.network.clone(),
                    self.beaver_source.clone(),
                );
                shared_value.recompute_mac();
                shared_value
            })
            .collect_vec()
    }

    /// Allocate a random scalar in the network and construct secret shares of it
    /// Uses the beaver source to generate the random scalar
    pub fn allocate_random_shared_scalar(&self) -> AuthenticatedScalar<N, S> {
        // The pre-processing functionality provides a set of additive shares of random values
        // pull one from the source.
        let random_scalar = self.beaver_source.as_ref().borrow_mut().next_shared_value();

        let mut shared_value = AuthenticatedScalar::from_scalar_with_visibility(
            random_scalar,
            Visibility::Shared,
            self.key_share.clone(),
            self.network.clone(),
            self.beaver_source.clone(),
        );

        // No MAC exists on the value when it is created from a shared pre-processing value
        // explicitly compute the MAC so that it can be validly used
        shared_value.recompute_mac();
        shared_value
    }

    /// Allocate a batch of random scalars in the network and construct secret shares of them
    /// Uses the beaver source to generate the random scalar
    pub fn allocate_random_scalars_batch(
        &self,
        num_scalars: usize,
    ) -> Vec<AuthenticatedScalar<N, S>> {
        let mut shared_values = self
            .beaver_source
            .as_ref()
            .borrow_mut()
            .next_shared_value_batch(num_scalars)
            .iter()
            .map(|value| {
                AuthenticatedScalar::from_scalar_with_visibility(
                    *value,
                    Visibility::Shared,
                    self.key_share.clone(),
                    self.network.clone(),
                    self.beaver_source.clone(),
                )
            })
            .collect::<Vec<AuthenticatedScalar<N, S>>>();

        // TODO: This can be done as a batch_mul
        // Recompute the MACs in a separate step (i.e. outside map) to allow the mutable borrow
        // of `self.beaver_source` to be released.
        // `recompute_mac` requires a `Mul` which obtains a mutable borrow of the beaver source
        shared_values
            .iter_mut()
            .for_each(|value| value.recompute_mac());
        shared_values
    }

    /// Allocate a random pair of multiplicative inverses using the beaver source; i.e. (b, b^-1)
    pub fn allocate_random_inverse_pair(
        &self,
    ) -> (AuthenticatedScalar<N, S>, AuthenticatedScalar<N, S>) {
        let inverse_pair = self
            .beaver_source
            .as_ref()
            .borrow_mut()
            .next_shared_inverse_pair();

        let mut shared_scalars = (
            AuthenticatedScalar::from_scalar_with_visibility(
                inverse_pair.0,
                Visibility::Shared,
                self.key_share.clone(),
                self.network.clone(),
                self.beaver_source.clone(),
            ),
            AuthenticatedScalar::from_scalar_with_visibility(
                inverse_pair.1,
                Visibility::Shared,
                self.key_share.clone(),
                self.network.clone(),
                self.beaver_source.clone(),
            ),
        );

        // The values from the beaver source have no MAC, compute them now
        shared_scalars.0.recompute_mac();
        shared_scalars.1.recompute_mac();
        shared_scalars
    }

    /// TODO: Optimize MAC recomputation to use batch mul interface (in a single round)
    /// Allocate a batch of random pairs of multiplicative inverses from the beaver source, i.e.:
    ///     [(b_1, b_1^-1), ..., (b_n, b_n^-1)]
    pub fn allocate_random_inverse_pair_batch(
        &self,
        num_inverses: usize,
    ) -> Vec<(AuthenticatedScalar<N, S>, AuthenticatedScalar<N, S>)> {
        let inverse_pairs = self
            .beaver_source
            .as_ref()
            .borrow_mut()
            .next_shared_inverse_pair_batch(num_inverses);

        let mut shared_scalars = inverse_pairs
            .into_iter()
            .map(|(b, b_inv)| {
                (
                    AuthenticatedScalar::from_scalar_with_visibility(
                        b,
                        Visibility::Shared,
                        self.key_share.clone(),
                        self.network.clone(),
                        self.beaver_source.clone(),
                    ),
                    AuthenticatedScalar::from_scalar_with_visibility(
                        b_inv,
                        Visibility::Shared,
                        self.key_share.clone(),
                        self.network.clone(),
                        self.beaver_source.clone(),
                    ),
                )
            })
            .collect_vec();
        shared_scalars.iter_mut().for_each(|(b, b_inv)| {
            b.recompute_mac();
            b_inv.recompute_mac();
        });

        shared_scalars
    }

    /// Allocates an `AuthenticatedScalar` from a value that is presumed to be a valid additive Shamir
    /// share of some underlying secret value.
    pub fn allocate_preshared_scalar(&self, value: Scalar) -> AuthenticatedScalar<N, S> {
        let mut shared_value = AuthenticatedScalar::from_scalar_with_visibility(
            value,
            crate::Visibility::Shared,
            self.key_share.clone(),
            self.network.clone(),
            self.beaver_source.clone(),
        );

        shared_value.recompute_mac();
        shared_value
    }

    /// Allocates a batch of `AuthenticatedScalar`s which are presumed to be a valid additive sharing
    /// of some underlying secret value
    pub fn batch_allocate_preshared_scalar(
        &self,
        values: &[Scalar],
    ) -> Vec<AuthenticatedScalar<N, S>> {
        values
            .iter()
            .map(|val| {
                let mut authenticated = AuthenticatedScalar::from_scalar_with_visibility(
                    *val,
                    Visibility::Shared,
                    self.key_share.clone(),
                    self.network.clone(),
                    self.beaver_source.clone(),
                );
                authenticated.recompute_mac();
                authenticated
            })
            .collect()
    }

    /// Allocate a RistrettoPoint that acts as one of the given party's private inputs to the protocol
    ///
    /// If the local party is the specified party, then this method will construct an additive sharing
    /// of the input and distribute the shares amongst the peers.
    ///
    /// If the local party is not the specified party, this method will await a share distributed by
    /// the owner of the input value.
    pub fn allocate_private_ristretto(
        &self,
        owning_party: u64,
        value: RistrettoPoint,
    ) -> Result<AuthenticatedRistretto<N, S>, MpcError> {
        let authenticated_value = AuthenticatedRistretto::from_private_ristretto_point(
            value,
            self.key_share.clone(),
            self.network.clone(),
            self.beaver_source.clone(),
        );

        authenticated_value
            .share_secret(owning_party)
            .map_err(MpcError::NetworkError)
    }

    /// Allocate a batch of private ristretto points
    pub fn batch_allocate_private_ristrettos(
        &self,
        owning_party: u64,
        values: &[RistrettoPoint],
    ) -> Result<Vec<AuthenticatedRistretto<N, S>>, MpcError> {
        let authenticated_values = values
            .iter()
            .map(|value| {
                AuthenticatedRistretto::from_private_ristretto_point(
                    *value,
                    self.key_share.clone(),
                    self.network.clone(),
                    self.beaver_source.clone(),
                )
            })
            .collect_vec();

        AuthenticatedRistretto::batch_share_secrets(owning_party, &authenticated_values)
            .map_err(MpcError::NetworkError)
    }

    /// Allocate a RistrettoPoint that acts as a public value within the MPC protocol
    ///
    /// No secret shares are constructed from this, it is assumed that all parties call this method
    /// with the same (known) value
    pub fn allocate_public_ristretto(&self, value: RistrettoPoint) -> AuthenticatedRistretto<N, S> {
        AuthenticatedRistretto::from_public_ristretto_point(
            value,
            self.key_share.clone(),
            self.network.clone(),
            self.beaver_source.clone(),
        )
    }

    /// Allocate a batch of public Ristretto points
    pub fn batch_allocate_public_ristretto(
        &self,
        values: &[RistrettoPoint],
    ) -> Vec<AuthenticatedRistretto<N, S>> {
        values
            .iter()
            .map(|value| self.allocate_public_ristretto(*value))
            .collect_vec()
    }

    /// Allocate a public compressed ristretto point in the MPC network
    pub fn allocate_public_compressed_ristretto(
        &self,
        value: CompressedRistretto,
    ) -> AuthenticatedCompressedRistretto<N, S> {
        AuthenticatedCompressedRistretto::from_public_compressed_ristretto(
            value,
            self.key_share.clone(),
            self.network.clone(),
            self.beaver_source.clone(),
        )
    }

    /// Allocate a batch of public compressed Ristretto points
    pub fn batch_allocate_public_compressed_ristretto(
        &self,
        values: &[CompressedRistretto],
    ) -> Vec<AuthenticatedCompressedRistretto<N, S>> {
        values
            .iter()
            .map(|value| self.allocate_public_compressed_ristretto(*value))
            .collect_vec()
    }
}
