//! Groups the definitions and trait implementations for a Ristretto point within the MPC net

use std::{
    borrow::Borrow,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use clear_on_drop::clear::Clear;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity, MultiscalarMul},
};
use futures::executor::block_on;
use itertools::izip;
use rand_core::{CryptoRng, OsRng, RngCore};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    beaver::SharedValueSource,
    commitment::RistrettoCommitment,
    error::{MpcError, MpcNetworkError},
    macros,
    mpc_scalar::MpcScalar,
    network::MpcNetwork,
    BeaverSource, SharedNetwork, Visibility, Visible,
};

/// Represents a Ristretto point that has been allocated in the MPC network
#[derive(Debug)]
pub struct MpcRistrettoPoint<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The underlying value of the Ristretto point in the network
    value: RistrettoPoint,
    /// The visibility flag; what amount of information various parties have
    visibility: Visibility,
    /// The underlying network that the MPC operates on top of
    network: SharedNetwork<N>,
    /// The source for shared values; MAC keys, beaver triplets, etc
    beaver_source: BeaverSource<S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone for MpcRistrettoPoint<N, S> {
    fn clone(&self) -> Self {
        Self {
            value: self.value(),
            visibility: self.visibility(),
            network: self.network(),
            beaver_source: self.beaver_source(),
        }
    }
}

/**
 * Static and helper methods
 */

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MpcRistrettoPoint<N, S> {
    /// Multiplies a scalar by the Ristretto base point
    #[inline]
    pub fn base_point_mul(a: Scalar) -> RistrettoPoint {
        RISTRETTO_BASEPOINT_POINT * a
    }

    /// Multiplies a Scalar encoding of a u64 by the Ristretto base point
    #[inline]
    pub fn base_point_mul_u64(a: u64) -> RistrettoPoint {
        Self::base_point_mul(Scalar::from(a))
    }
}

/**
 * Secret sharing implementation
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MpcRistrettoPoint<N, S> {
    /// From a privately held value, construct an additive secret share and distribute this to the
    /// counterparty. The local party takes a random scalar R which it multiplies by the Ristretto base
    /// point. The local party gives R to the peer, and holds a - R for herself.
    /// This method is called by both parties, only one of which transmits
    pub fn share_secret(&self, party_id: u64) -> Result<MpcRistrettoPoint<N, S>, MpcNetworkError> {
        assert!(self.is_private(), "Only private values may be shared...");
        let my_party_id = self.network.as_ref().borrow().party_id();

        if my_party_id == party_id {
            // Sending party
            let mut rng: OsRng = OsRng {};
            let random_share = RistrettoPoint::random(&mut rng);

            // Broadcast the peer's share
            block_on(
                self.network
                    .as_ref()
                    .borrow_mut()
                    .send_single_point(random_share),
            )?;

            // Local party takes a - R
            Ok(MpcRistrettoPoint {
                value: self.value() - random_share,
                visibility: Visibility::Shared,
                network: self.network.clone(),
                beaver_source: self.beaver_source.clone(),
            })
        } else {
            // Receive a secret share from the peer
            Self::receive_value(self.network.clone(), self.beaver_source.clone())
        }
    }

    /// Share a batch of privately held values
    pub fn batch_share_secrets(
        party_id: u64,
        values: &[MpcRistrettoPoint<N, S>],
    ) -> Result<Vec<MpcRistrettoPoint<N, S>>, MpcNetworkError> {
        assert!(!values.is_empty(), "Cannot batch share an empty vector");
        assert!(
            values.iter().all(|value| value.is_private()),
            "Only private values may be shared..."
        );
        let network = values[0].network();
        let beaver_source = values[0].beaver_source();
        let my_party_id = network.as_ref().borrow().party_id();

        if my_party_id == party_id {
            // Sending party
            let mut rng = OsRng {};
            let random_shares = (0..values.len())
                .map(|_| RistrettoPoint::random(&mut rng))
                .collect::<Vec<RistrettoPoint>>();

            // Broadcast the peer's share
            block_on(network.as_ref().borrow_mut().send_points(&random_shares))?;

            // Local party takes the share a - R for each a
            Ok(values
                .iter()
                .zip(random_shares.iter())
                .map(|(value, random_share)| MpcRistrettoPoint {
                    value: value.value() - random_share,
                    visibility: Visibility::Shared,
                    network: network.clone(),
                    beaver_source: beaver_source.clone(),
                })
                .collect())
        } else {
            Ok(Self::batch_receive_values(
                values.len(),
                network,
                beaver_source,
            )?)
        }
    }

    /// Local party receives a secret share of a value; as opposed to using share_secret, no existing value is needed
    pub fn receive_value(
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Result<MpcRistrettoPoint<N, S>, MpcNetworkError> {
        let value = block_on(network.as_ref().borrow_mut().receive_single_point())?;

        Ok(MpcRistrettoPoint {
            value,
            network,
            beaver_source,
            visibility: Visibility::Shared,
        })
    }

    /// Receive a batch of values
    pub fn batch_receive_values(
        num_expected: usize,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Result<Vec<MpcRistrettoPoint<N, S>>, MpcNetworkError> {
        let values = block_on(network.as_ref().borrow_mut().receive_points(num_expected))?;

        Ok(values
            .into_iter()
            .map(|value| MpcRistrettoPoint {
                value,
                visibility: Visibility::Shared,
                network: network.clone(),
                beaver_source: beaver_source.clone(),
            })
            .collect())
    }

    /// From a shared value, both parties call this function to distribute their shares to the counterparty
    /// The result is the sum of the shares of both parties and is a public value, so the result is no longer
    /// and additive secret sharing of some underlying Ristretto point
    pub fn open(&self) -> Result<MpcRistrettoPoint<N, S>, MpcNetworkError> {
        assert!(!self.is_private(), "Private values may not be opened...");
        if self.is_public() {
            return Ok(self.clone());
        }
        // Send a Ristretto point and receive one in return
        let received_point = block_on(
            self.network
                .as_ref()
                .borrow_mut()
                .broadcast_single_point(self.value()),
        )?;

        Ok(MpcRistrettoPoint {
            value: received_point + self.value(),
            visibility: Visibility::Public,
            network: self.network.clone(),
            beaver_source: self.beaver_source.clone(),
        })
    }

    /// Open a batch of `MpcRistrettoPoint`s
    pub fn batch_open(
        values: &[MpcRistrettoPoint<N, S>],
    ) -> Result<Vec<MpcRistrettoPoint<N, S>>, MpcNetworkError> {
        assert!(!values.is_empty(), "Cannot open an empty vector of values");
        assert!(
            values.iter().all(|value| !value.is_private()),
            "Private values may not be opened..."
        );

        let network = values[0].network();
        let beaver_source = values[0].beaver_source();

        // Both parties share their values
        let received_points = block_on(
            network.as_ref().borrow_mut().broadcast_points(
                &values
                    .iter()
                    .map(|value| value.value())
                    .collect::<Vec<RistrettoPoint>>(),
            ),
        )?;

        Ok(values
            .iter()
            .zip(received_points.iter())
            .map(|(my_share, peer_share)| {
                if my_share.is_public() {
                    return my_share.clone();
                }

                MpcRistrettoPoint::from_public_ristretto_point(
                    my_share.value() + peer_share,
                    network.clone(),
                    beaver_source.clone(),
                )
            })
            .collect())
    }

    /// From a shared value:
    ///     1. Each party commits to their share of the underlying value
    ///     2. The parties exchange openings and verify the peer's opening
    pub fn commit_and_open(&self) -> Result<MpcRistrettoPoint<N, S>, MpcError> {
        assert!(!self.is_private(), "Private values may not be opened");
        if self.is_public() {
            return Ok(self.clone());
        }

        let commitment = RistrettoCommitment::commit(self.value());
        let peer_commitment = block_on(
            self.network()
                .as_ref()
                .borrow_mut()
                .broadcast_single_scalar(commitment.get_commitment()),
        )
        .map_err(MpcError::NetworkError)?;

        // Open the commitment to the underlying value
        let peer_blinding = block_on(
            self.network
                .as_ref()
                .borrow_mut()
                .broadcast_single_scalar(commitment.get_blinding()),
        )
        .map_err(MpcError::NetworkError)?;

        let peer_value = block_on(
            self.network
                .as_ref()
                .borrow_mut()
                .broadcast_single_point(commitment.get_value()),
        )
        .map_err(MpcError::NetworkError)?;

        // Verify the commitment and return the opened value
        if !RistrettoCommitment::verify_from_values(peer_commitment, peer_blinding, peer_value) {
            return Err(MpcError::AuthenticationError);
        }

        Ok(Self {
            value: self.value() + peer_value,
            visibility: Visibility::Public,
            network: self.network(),
            beaver_source: self.beaver_source(),
        })
    }

    /// Commit to and open a batch of secret shared values
    pub fn batch_commit_and_open(
        values: &[MpcRistrettoPoint<N, S>],
    ) -> Result<Vec<MpcRistrettoPoint<N, S>>, MpcError> {
        assert!(
            !values.is_empty(),
            "Cannot batch commit and open an empty vector"
        );
        assert!(
            values.iter().all(|value| !value.is_private()),
            "Private values may not be opened..."
        );

        let network = values[0].network();
        let beaver_source = values[0].beaver_source();

        // Generate commitments to the points and share them with the peer
        let commitments: Vec<RistrettoCommitment> = values
            .iter()
            .map(|value| RistrettoCommitment::commit(value.value()))
            .collect();
        let peer_commitments = block_on(
            network.as_ref().borrow_mut().broadcast_scalars(
                &commitments
                    .iter()
                    .map(|comm| comm.get_commitment())
                    .collect::<Vec<Scalar>>(),
            ),
        )
        .map_err(MpcError::NetworkError)?;

        // Peers open the blinding factors for the commitments
        let peer_blinding = block_on(
            network.as_ref().borrow_mut().broadcast_scalars(
                &commitments
                    .iter()
                    .map(|comm| comm.get_blinding())
                    .collect::<Vec<Scalar>>(),
            ),
        )
        .map_err(MpcError::NetworkError)?;

        // Peers open the points they committed to
        let peer_points = block_on(
            network.as_ref().borrow_mut().broadcast_points(
                &commitments
                    .iter()
                    .map(|comm| comm.get_value())
                    .collect::<Vec<RistrettoPoint>>(),
            ),
        )
        .map_err(MpcError::NetworkError)?;

        // Verify the commitments
        izip!(
            peer_commitments.iter(),
            peer_blinding.iter(),
            peer_points.iter()
        )
        .try_for_each(|(comm, blinding, point)| {
            if !RistrettoCommitment::verify_from_values(*comm, *blinding, *point) {
                return Err(MpcError::AuthenticationError);
            }

            Ok(())
        })?;

        // Lastly, add the peer's shares to the local share for the final opened result
        Ok(values
            .iter()
            .zip(peer_points)
            .map(|(my_value, peer_value)| {
                if my_value.is_public() {
                    return my_value.clone();
                }

                MpcRistrettoPoint::from_public_ristretto_point(
                    my_value.value() + peer_value,
                    network.clone(),
                    beaver_source.clone(),
                )
            })
            .collect())
    }

    /// Fetch the next Beaver triplet from the source and cast them as MpcScalars
    /// We leave them as scalars because some are directly used as scalars for Mul
    fn next_beaver_triplet(&self) -> (MpcScalar<N, S>, MpcScalar<N, S>, MpcScalar<N, S>) {
        let (a, b, c) = self.beaver_source.as_ref().borrow_mut().next_triplet();

        (
            MpcScalar::from_scalar_with_visibility(
                a,
                Visibility::Shared,
                self.network.clone(),
                self.beaver_source.clone(),
            ),
            MpcScalar::from_scalar_with_visibility(
                b,
                Visibility::Shared,
                self.network.clone(),
                self.beaver_source.clone(),
            ),
            MpcScalar::from_scalar_with_visibility(
                c,
                Visibility::Shared,
                self.network.clone(),
                self.beaver_source.clone(),
            ),
        )
    }
}

/**
 * Wrapper type implementations
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MpcRistrettoPoint<N, S> {
    /**
     * Helper methods
     */
    #[inline]
    pub fn value(&self) -> RistrettoPoint {
        self.value
    }

    #[inline]
    pub(crate) fn network(&self) -> SharedNetwork<N> {
        self.network.clone()
    }

    #[inline]
    pub(crate) fn beaver_source(&self) -> BeaverSource<S> {
        self.beaver_source.clone()
    }

    #[inline]
    fn is_public(&self) -> bool {
        self.visibility() == Visibility::Public
    }

    #[inline]
    fn is_shared(&self) -> bool {
        self.visibility() == Visibility::Shared
    }

    #[inline]
    fn is_private(&self) -> bool {
        self.visibility() == Visibility::Private
    }

    /**
     * Casting methods
     */
    /// Creates the identity point for the Ristretto group, allocated in the network
    pub fn identity(network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Self {
        Self {
            value: RistrettoPoint::identity(),
            visibility: Visibility::Public,
            network,
            beaver_source,
        }
    }

    /// Create a Ristretto point from a u64, visibility assumed Public
    pub fn from_public_u64(
        a: u64,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_u64_with_visibility(a, Visibility::Public, network, beaver_source)
    }

    pub fn from_private_u64(
        a: u64,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_u64_with_visibility(a, Visibility::Private, network, beaver_source)
    }

    /// Create a Ristretto point from a u64, with visibility explicitly parameterized
    pub(crate) fn from_u64_with_visibility(
        a: u64,
        visibility: Visibility,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> MpcRistrettoPoint<N, S> {
        Self {
            value: Self::base_point_mul_u64(a),
            visibility,
            network,
            beaver_source,
        }
    }

    /// Create a Ristretto point from an existing, public Scalar
    pub fn from_public_scalar(
        a: Scalar,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_scalar_with_visibility(a, Visibility::Public, network, beaver_source)
    }

    /// Create a Ristretto point from an existing, private scalar
    pub fn from_private_scalar(
        a: Scalar,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_scalar_with_visibility(a, Visibility::Private, network, beaver_source)
    }

    /// Create a Ristretto point from a Scalar, with visibility explicitly parameterized
    pub fn from_scalar_with_visibility(
        a: Scalar,
        visibility: Visibility,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self {
            value: Self::base_point_mul(a),
            visibility,
            network,
            beaver_source,
        }
    }

    /// Create a new MpcRistrettoPoint from an existing, public RistrettoPoint
    pub fn from_public_ristretto_point(
        a: RistrettoPoint,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_ristretto_point_with_visibility(a, Visibility::Public, network, beaver_source)
    }

    /// Create a new MpcRistrettoPoint from an existing, private RistrettoPoint
    pub fn from_private_ristretto_point(
        a: RistrettoPoint,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_ristretto_point_with_visibility(a, Visibility::Private, network, beaver_source)
    }

    /// Create a wrapper around an existing Ristretto point with visibility specified
    pub(crate) fn from_ristretto_point_with_visibility(
        a: RistrettoPoint,
        visibility: Visibility,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self {
            value: a,
            visibility,
            network,
            beaver_source,
        }
    }

    /// A hack to allow a Scalar to be cast into an MpcScalar for multiplication via macro
    fn from_scalar_for_mul(
        a: Scalar,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> MpcScalar<N, S> {
        MpcScalar::from_public_scalar(a, network, beaver_source)
    }

    /// Create a random ristretto point
    pub fn random<R: RngCore + CryptoRng>(
        rng: &mut R,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self {
            value: RistrettoPoint::random(rng),
            visibility: Visibility::Private,
            network,
            beaver_source,
        }
    }

    // Default-esque implementation
    pub fn default(network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Self {
        Self::default_with_visibility(Visibility::Public, network, beaver_source)
    }

    pub fn default_with_visibility(
        visibility: Visibility,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_ristretto_point_with_visibility(
            RistrettoPoint::default(),
            visibility,
            network,
            beaver_source,
        )
    }

    // Build from bytes
    macros::impl_delegated_wrapper!(
        RistrettoPoint,
        from_uniform_bytes,
        from_uniform_bytes_with_visibility,
        bytes,
        &[u8; 64]
    );

    /// Convert the point to a compressed Ristrestto point
    pub fn compress(&self) -> MpcCompressedRistretto<N, S> {
        MpcCompressedRistretto {
            value: self.value().compress(),
            visibility: self.visibility,
            network: self.network.clone(),
            beaver_source: self.beaver_source.clone(),
        }
    }

    /// Double and compress a batch of points
    pub fn double_and_compress_batch<I, T>(_: I) -> Vec<MpcCompressedRistretto<N, S>>
    where
        I: IntoIterator<Item = T>,
        T: Borrow<MpcRistrettoPoint<N, S>>,
    {
        unimplemented!("double_and_compress_batch not implemented...");
    }
}

/**
 * Generic Trait Implementations
 */

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Visible for MpcRistrettoPoint<N, S> {
    fn visibility(&self) -> Visibility {
        self.visibility
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> PartialEq for MpcRistrettoPoint<N, S> {
    fn eq(&self, other: &Self) -> bool {
        self.value().eq(&other.value())
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> ConstantTimeEq
    for MpcRistrettoPoint<N, S>
{
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value().ct_eq(&other.value())
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Eq for MpcRistrettoPoint<N, S> {}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clear for MpcRistrettoPoint<N, S> {
    #[allow(clippy::needless_borrow)]
    fn clear(&mut self) {
        (&mut self.value).clear();
    }
}

/**
 * Mul and variants for borrowed, non-borrowed values
 */

/// An implementation of multiplication with the Beaver trick. This involves two openings
/// Panics in case of a network error; see mpc_scalar::MpcScalar::Mul for more info.
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a MpcScalar<N, S>>
    for &'a MpcRistrettoPoint<N, S>
{
    type Output = MpcRistrettoPoint<N, S>;

    /// Multiplies two (possibly shared) values. The only case in which we need a Beaver trick
    /// is when both lhs and rhs are Shared. If only one is shared, multiplying by a public value
    /// directly leads to an additive sharing. If both are public, we do not need an additive share.
    /// TODO(@joey): What is the correct behavior when one or both of lhs and rhs are private
    ///
    /// See https://securecomputation.org/docs/pragmaticmpc.pdf (Section 3.4) for the identities this
    /// implementation makes use of.
    #[allow(non_snake_case)]
    fn mul(self, rhs: &'a MpcScalar<N, S>) -> Self::Output {
        if self.is_shared() && rhs.is_shared() {
            let (a, b, c) = self.next_beaver_triplet();

            // Compute \alpha * \betaG for generator point G. As far as the interface is concerned:
            // self = \betaG, rhs = \alpha
            // Open the value d = [\alpha - a].open()
            let alpha_minus_a = (rhs - &a).open().unwrap();
            // Opem the value eG = [\betaG - bG].open(); where G is the Ristretto base point
            let beta_minus_b = (self - MpcRistrettoPoint::<N, S>::base_point_mul(b.value()))
                .open()
                .unwrap();

            // Identity [a * bG] = deG + d[bG] + [a]eG + [c]G
            // To construct the secret share, only the king will add the deG term
            // All multiplications here are between a shared value and a public value or
            // two public values; so the recursion will not hit this case
            let bG = MpcRistrettoPoint {
                value: MpcRistrettoPoint::<N, S>::base_point_mul(b.value()),
                visibility: Visibility::Shared,
                network: self.network.clone(),
                beaver_source: self.beaver_source.clone(),
            };
            let cG = MpcRistrettoPoint {
                value: MpcRistrettoPoint::<N, S>::base_point_mul(c.value()),
                visibility: Visibility::Shared,
                network: self.network.clone(),
                beaver_source: self.beaver_source.clone(),
            };

            let mut res = &alpha_minus_a * bG + &a * &beta_minus_b + cG;

            if self.network.as_ref().borrow().am_king() {
                res += &alpha_minus_a * &beta_minus_b;
            }

            res
        } else {
            // Directly multiply
            MpcRistrettoPoint {
                value: self.value() * rhs.value(),
                visibility: Visibility::min_visibility_two(self, rhs),
                network: self.network.clone(),
                beaver_source: self.beaver_source.clone(),
            }
        }
    }
}

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a MpcRistrettoPoint<N, S>>
    for &'a MpcScalar<N, S>
{
    type Output = MpcRistrettoPoint<N, S>;

    fn mul(self, rhs: &'a MpcRistrettoPoint<N, S>) -> Self::Output {
        rhs * self
    }
}

macros::impl_operator_variants!(MpcRistrettoPoint<N, S>, Mul, mul, *, MpcScalar<N, S>);
macros::impl_operator_variants!(MpcScalar<N, S>, Mul, mul, *, MpcRistrettoPoint<N, S>, Output=MpcRistrettoPoint<N, S>);
macros::impl_wrapper_type!(MpcRistrettoPoint<N, S>, Scalar, from_scalar_for_mul, Mul, mul, *, authenticated=false);
macros::impl_arithmetic_assign!(MpcRistrettoPoint<N, S>, MulAssign, mul_assign, *, MpcScalar<N, S>);
macros::impl_arithmetic_assign!(MpcRistrettoPoint<N, S>, MulAssign, mul_assign, *, Scalar);

/**
 * Add and variants for borrowed, non-borrowed values
 */
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Add<&'a MpcRistrettoPoint<N, S>>
    for &'a MpcRistrettoPoint<N, S>
{
    type Output = MpcRistrettoPoint<N, S>;

    fn add(self, rhs: &'a MpcRistrettoPoint<N, S>) -> Self::Output {
        // If public + shared, swap the arguments for simplicity
        if self.is_public() && rhs.is_shared() {
            return rhs + self;
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
            if self.is_public() && rhs.is_public() ||  // Both public
                self.is_shared() && rhs.is_shared() ||  // Both shared
                am_king
            // King always adds shares
            {
                self.value() + rhs.value()
            } else {
                self.value()
            }
        };

        MpcRistrettoPoint {
            value: res,
            visibility: Visibility::min_visibility_two(self, rhs),
            network: self.network.clone(),
            beaver_source: self.beaver_source.clone(),
        }
    }
}

macros::impl_operator_variants!(MpcRistrettoPoint<N, S>, Add, add, +, MpcRistrettoPoint<N, S>);
macros::impl_wrapper_type!(MpcRistrettoPoint<N, S>, RistrettoPoint, from_public_ristretto_point, Add, add, +, authenticated=false);
macros::impl_arithmetic_assign!(MpcRistrettoPoint<N, S>, AddAssign, add_assign, +, MpcRistrettoPoint<N, S>);
macros::impl_arithmetic_assign!(MpcRistrettoPoint<N, S>, AddAssign, add_assign, +, RistrettoPoint);

/**
 * Sub and variants for borrowed, non-borrowed values
 */
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Sub<&'a MpcRistrettoPoint<N, S>>
    for &'a MpcRistrettoPoint<N, S>
{
    type Output = MpcRistrettoPoint<N, S>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &'a MpcRistrettoPoint<N, S>) -> Self::Output {
        self + rhs.neg()
    }
}
macros::impl_operator_variants!(MpcRistrettoPoint<N, S>, Sub, sub, -, MpcRistrettoPoint<N, S>);
macros::impl_wrapper_type!(MpcRistrettoPoint<N, S>, RistrettoPoint, from_public_ristretto_point, Sub, sub, -, authenticated=false);
macros::impl_arithmetic_assign!(MpcRistrettoPoint<N, S>, SubAssign, sub_assign, -, MpcRistrettoPoint<N, S>);
macros::impl_arithmetic_assign!(MpcRistrettoPoint<N, S>, SubAssign, sub_assign, -, RistrettoPoint);

/**
 * Neg and variants for borrowed, non-borrowed values
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Neg for MpcRistrettoPoint<N, S> {
    type Output = MpcRistrettoPoint<N, S>;

    fn neg(self) -> Self::Output {
        (&self).neg()
    }
}

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Neg for &'a MpcRistrettoPoint<N, S> {
    type Output = MpcRistrettoPoint<N, S>;

    fn neg(self) -> Self::Output {
        MpcRistrettoPoint {
            value: self.value.neg(),
            visibility: self.visibility(),
            network: self.network.clone(),
            beaver_source: self.beaver_source.clone(),
        }
    }
}

/**
 * Multiscalar Multiplication
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MultiscalarMul
    for MpcRistrettoPoint<N, S>
{
    type Point = Self;

    /// Computes c_1P_1 + c_2P_2 + ... + c_nP_n for scalars c and points P
    fn multiscalar_mul<I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Self::Point>,
    {
        // Fetch the network and beaver source from the first element
        let mut peekable_points = points.into_iter().peekable();
        let (network, beaver_source) = {
            let first_elem: &MpcRistrettoPoint<N, S> = peekable_points.peek().unwrap().borrow();
            (first_elem.network.clone(), first_elem.beaver_source.clone())
        };

        scalars.into_iter().zip(peekable_points.into_iter()).fold(
            MpcRistrettoPoint::identity(network, beaver_source),
            |acc, pair| acc + pair.0.borrow() * pair.1.borrow(), // Pair is a 2-tuple of (c_i, P_i)
        )
    }
}

/// Represents a CompressedRistretto point allocated in the network
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct MpcCompressedRistretto<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The underlying value of the Ristretto point in the network
    value: CompressedRistretto,
    /// The visibility flag; what amount of information various parties have
    visibility: Visibility,
    /// The underlying network that the MPC operates on top of
    network: SharedNetwork<N>,
    /// The source for shared values; MAC keys, beaver triplets, etc
    beaver_source: BeaverSource<S>,
}

/**
 * Wrapper type implementation
 */
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MpcCompressedRistretto<N, S> {
    /// Convert from a public CompressedRistretto point
    pub fn from_public_compressed_ristretto(
        a: CompressedRistretto,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_compressed_ristretto_with_visibility(
            a,
            Visibility::Public,
            network,
            beaver_source,
        )
    }

    /// Convert from a private CompressedRistretto point
    pub fn from_private_compressed_ristretto(
        value: CompressedRistretto,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        Self::from_compressed_ristretto_with_visibility(
            value,
            Visibility::Private,
            network,
            beaver_source,
        )
    }

    /// Convert from a CompressedRistretto point with visibility explicitly defined
    pub(crate) fn from_compressed_ristretto_with_visibility(
        a: CompressedRistretto,
        visibility: Visibility,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Self {
        MpcCompressedRistretto {
            value: a,
            visibility,
            network,
            beaver_source,
        }
    }

    /// Get the underlying CompressedRistretto point
    pub fn value(&self) -> CompressedRistretto {
        self.value
    }

    /// Convert form a CompressedRistretto point to a RistrettoPoint
    pub fn decompress(&self) -> Option<MpcRistrettoPoint<N, S>> {
        Some(MpcRistrettoPoint {
            value: self.value.decompress()?,
            visibility: self.visibility,
            network: self.network.clone(),
            beaver_source: self.beaver_source.clone(),
        })
    }

    /// Construct a public network allocated compressed point from a byte array
    pub fn from_public_bytes(
        buf: &[u8; 32],
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> MpcCompressedRistretto<N, S> {
        Self::from_bytes_with_visibility(buf, Visibility::Public, network, beaver_source)
    }

    /// Construct a private network allocated compressed point from a byte array
    pub fn from_private_bytes(
        buf: &[u8; 32],
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> MpcCompressedRistretto<N, S> {
        Self::from_bytes_with_visibility(buf, Visibility::Private, network, beaver_source)
    }

    pub(crate) fn from_bytes_with_visibility(
        buf: &[u8; 32],
        visibility: Visibility,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> MpcCompressedRistretto<N, S> {
        MpcCompressedRistretto {
            value: CompressedRistretto(*buf),
            visibility,
            network,
            beaver_source,
        }
    }

    /// View this CompressedRistretto as an array of bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.value.as_bytes()
    }

    /// Create the identity point wrapped in an MpcCompressedRistretto
    pub fn identity(
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> MpcCompressedRistretto<N, S> {
        MpcCompressedRistretto {
            value: CompressedRistretto::identity(),
            visibility: Visibility::Public,
            network,
            beaver_source,
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> IsIdentity
    for MpcCompressedRistretto<N, S>
{
    fn is_identity(&self) -> bool {
        self.value.is_identity()
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> ConstantTimeEq
    for MpcCompressedRistretto<N, S>
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&other.value)
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clear for MpcCompressedRistretto<N, S> {
    #[allow(clippy::needless_borrow)]
    fn clear(&mut self) {
        (&mut self.value).clear();
    }
}

#[cfg(test)]
mod mpc_ristretto_tests {
    use std::{cell::RefCell, rc::Rc};

    use clear_on_drop::clear::Clear;
    use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};

    use crate::{beaver::DummySharedScalarSource, network::dummy_network::DummyMpcNetwork};

    use super::MpcRistrettoPoint;

    #[test]
    fn test_clear() {
        let network = Rc::new(RefCell::new(DummyMpcNetwork::new()));
        let beaver_source = Rc::new(RefCell::new(DummySharedScalarSource::new()));

        let mut value = MpcRistrettoPoint::from_public_u64(2, network, beaver_source);
        #[allow(clippy::needless_borrow)]
        (&mut value).clear();

        assert_eq!(value.value, RistrettoPoint::identity());
    }
}
