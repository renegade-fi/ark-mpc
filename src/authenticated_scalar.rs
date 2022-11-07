//! Implements an authenticated wrapper around the MpcScalar type for malicious security

use std::{
    borrow::Borrow,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Index, Mul, MulAssign, Neg, Sub, SubAssign},
};

use clear_on_drop::clear::Clear;
use curve25519_dalek::scalar::Scalar;
use subtle::ConstantTimeEq;

use crate::{
    beaver::SharedValueSource,
    error::{MpcError, MpcNetworkError},
    macros,
    mpc_scalar::MpcScalar,
    network::MpcNetwork,
    BeaverSource, SharedNetwork, Visibility, Visible,
};

/// An authenticated scalar, wrapper around an MPC-capable Scalar that supports methods
/// to authenticate an opened result against a shared global MAC.
/// See SPDZ (https://eprint.iacr.org/2012/642.pdf) for a detailed explanation.
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
    /// TODO: replace this with Rc<RefCell<...>> or just Rc<...>
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
    pub fn is_public(&self) -> bool {
        self.visibility == Visibility::Public
    }

    #[inline]
    pub(crate) fn is_shared(&self) -> bool {
        self.visibility == Visibility::Shared
    }

    #[inline]
    pub fn value(&self) -> &MpcScalar<N, S> {
        &self.value
    }

    #[inline]
    pub(crate) fn mac(&self) -> Option<MpcScalar<N, S>> {
        self.mac_share.clone()
    }

    #[inline]
    pub(crate) fn key_share(&self) -> MpcScalar<N, S> {
        self.key_share.clone()
    }

    #[inline]
    pub(crate) fn network(&self) -> SharedNetwork<N> {
        self.value().network.clone()
    }

    #[inline]
    pub(crate) fn beaver_source(&self) -> BeaverSource<S> {
        self.value().beaver_source.clone()
    }

    #[inline]
    pub fn to_scalar(&self) -> Scalar {
        self.value().value()
    }

    #[inline]
    /// Recompute the MAC of the given value
    pub(crate) fn recompute_mac(&mut self) {
        self.mac_share = Some(&self.key_share * &self.value)
    }

    /// Create a new AuthenticatedScalar from a public u64 constant
    macros::impl_authenticated!(
        MpcScalar<N, S>, from_public_u64, from_private_u64, from_u64_with_visibility, u64
    );

    /// Create a new AuthenticatedScalar from a public Scalar constant
    macros::impl_authenticated!(
        MpcScalar<N, S>, from_public_scalar, from_private_scalar, from_scalar_with_visibility, Scalar
    );

    /// Create a new AuthenticatedScalar from an existing private MpcScalar
    pub fn from_private_mpc_scalar(x: MpcScalar<N, S>, key_share: MpcScalar<N, S>) -> Self {
        Self::from_mpc_scalar_with_visibility(x, Visibility::Private, key_share)
    }

    /// Create a new AuthenticatedScalar from an existing public MpcScalar
    pub fn from_public_mpc_scalar(x: MpcScalar<N, S>, key_share: MpcScalar<N, S>) -> Self {
        Self::from_mpc_scalar_with_visibility(x, Visibility::Public, key_share)
    }

    /// Used as a helper with extra parameters for the macro creation
    fn from_mpc_scalar(
        x: MpcScalar<N, S>,
        key_share: MpcScalar<N, S>,
        _: SharedNetwork<N>,
        _: BeaverSource<S>,
    ) -> Self {
        Self::from_mpc_scalar_with_visibility(x, Visibility::Public, key_share)
    }

    pub(crate) fn from_mpc_scalar_with_visibility(
        x: MpcScalar<N, S>,
        visibility: Visibility,
        key_share: MpcScalar<N, S>,
    ) -> Self {
        Self {
            value: x,
            visibility,
            key_share,
            mac_share: None, // This function should not be used to construct shared values
        }
    }

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
        bytes: [u8; 32],
        visibility: Visibility,
        key_share: MpcScalar<N, S>,
        network: SharedNetwork<N>,
        beaver_source: BeaverSource<S>,
    ) -> Option<Self> {
        let value = MpcScalar::<N, S>::from_canonical_bytes_with_visibility(
            bytes,
            Visibility::Public,
            network,
            beaver_source,
        )?;

        Some(Self {
            value,
            visibility,
            mac_share: None,
            key_share,
        })
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
    pub fn share_secret(
        &self,
        party_id: u64,
    ) -> Result<AuthenticatedScalar<N, S>, MpcNetworkError> {
        // Share the underlying value then construct a MAC share with the counterparty
        let my_share = self.value.share_secret(party_id)?;
        let my_mac_share = &self.key_share * &my_share;

        Ok(Self {
            value: my_share,
            visibility: Visibility::Shared,
            key_share: self.key_share.clone(),
            mac_share: Some(my_mac_share),
        })
    }

    /// Secret share a batch of privately held AuthenticatedScalars
    pub fn batch_share_secrets(
        party_id: u64,
        secrets: &[AuthenticatedScalar<N, S>],
    ) -> Result<Vec<AuthenticatedScalar<N, S>>, MpcNetworkError> {
        if secrets.is_empty() {
            return Ok(Vec::new());
        }

        // Construct secret shares from the underlying values
        let key_share = secrets[0].key_share();
        let my_shares = MpcScalar::batch_share_secrets(
            party_id,
            &secrets
                .iter()
                .map(|secret| secret.value().clone())
                .collect::<Vec<MpcScalar<_, _>>>(),
        )?;

        // Construct the MACs for the newly shared values
        #[allow(clippy::needless_collect)]
        let my_mac_shares: Vec<MpcScalar<N, S>> = my_shares
            .iter()
            .map(|share| &key_share.clone() * share)
            .collect();

        // Build these values into AuthenticatedScalars
        Ok(my_shares
            .into_iter()
            .zip(my_mac_shares.into_iter())
            .map(|(share, mac)| AuthenticatedScalar {
                value: share,
                visibility: Visibility::Shared,
                key_share: key_share.clone(),
                mac_share: Some(mac),
            })
            .collect())
    }

    /// From a shared value, both parties broadcast their shares and reconstruct the plaintext.
    /// The parties no longer hold a valid secret sharing of the result, they hold the result itself.
    pub fn open(&self) -> Result<AuthenticatedScalar<N, S>, MpcNetworkError> {
        if self.is_public() {
            return Ok(self.clone());
        }

        Ok(Self {
            value: self.value.open()?,
            visibility: Visibility::Public,
            key_share: self.key_share.clone(),
            mac_share: self.mac_share.clone(),
        })
    }

    /// Open a batch of authenticated values, do not authenticated via MACs
    pub fn batch_open(
        values: &[AuthenticatedScalar<N, S>],
    ) -> Result<Vec<AuthenticatedScalar<N, S>>, MpcNetworkError> {
        if values.is_empty() {
            return Ok(Vec::new());
        }
        let key_share = values[0].key_share();

        // Open the values
        let opened_values = MpcScalar::batch_open(
            &values
                .iter()
                .map(|shared_value| shared_value.value().clone())
                .collect::<Vec<MpcScalar<N, S>>>(),
        )?;

        // Reconstruct `AuthenticatedScalar`s
        Ok(opened_values
            .iter()
            .map(|opened_value| {
                AuthenticatedScalar {
                    value: opened_value.clone(),
                    visibility: Visibility::Public,
                    key_share: key_share.clone(),
                    mac_share: None, // Opened values have no MAC
                }
            })
            .collect())
    }

    /// Open the value and authenticate it using the MAC. This works in ___ steps:
    ///     1. The parties open the value
    ///     2. The parites each commit to key_share * value - mac_share
    ///     3. The parties open these commitments and add them; if equal to 0 the
    ///        value is authenticated
    pub fn open_and_authenticate(&self) -> Result<AuthenticatedScalar<N, S>, MpcError> {
        // If the value is not shared, there is nothing to open and authenticate
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
            .ne(&Scalar::zero())
        {
            return Err(MpcError::AuthenticationError);
        }

        // If authentication check passes, return the opened value
        Ok(Self {
            value: opened_value,
            visibility: Visibility::Public,
            key_share: self.key_share.clone(),
            mac_share: None, // Public value has no MAC
        })
    }

    /// Open a batch of `AuthenticatedScalar`s and authenticate the result with the given MACs
    pub fn batch_open_and_authenticate(
        values: &[AuthenticatedScalar<N, S>],
    ) -> Result<Vec<AuthenticatedScalar<N, S>>, MpcError> {
        if values.is_empty() {
            return Ok(Vec::new());
        }

        let key_share = values[0].key_share();

        // 1. Open the underlying values
        let opened_values = MpcScalar::batch_open(
            &values
                .iter()
                .map(|shared_value| shared_value.value().clone())
                .collect::<Vec<MpcScalar<N, S>>>(),
        )
        .map_err(MpcError::NetworkError)?;

        // 2. Commit to the value key_share * value - mac_share, then open the values and check commitments
        let mac_check_shares = opened_values
            .iter()
            .zip(values.iter())
            .map(|(opened_value, original_value)| {
                // If the value is public (already opened, add a dummy value for the mac check)
                if original_value.is_public() {
                    MpcScalar::from_public_u64(
                        0,
                        original_value.network(),
                        original_value.beaver_source(),
                    )
                } else {
                    &key_share * opened_value - &original_value.mac().unwrap()
                }
            })
            .collect::<Vec<MpcScalar<N, S>>>();

        // 3. Verify that the MACs pass the authentication check
        MpcScalar::batch_commit_and_open(&mac_check_shares)?
            .iter()
            .try_for_each(|commit_result| {
                if commit_result.value().ne(&Scalar::zero()) {
                    return Err(MpcError::AuthenticationError);
                }

                Ok(())
            })?;

        // Construct result values from opened shares
        Ok(opened_values
            .iter()
            .map(|opened_value| {
                AuthenticatedScalar {
                    value: opened_value.clone(),
                    visibility: Visibility::Public,
                    key_share: key_share.clone(),
                    mac_share: None, // Public values have no MAC
                }
            })
            .collect::<Vec<AuthenticatedScalar<N, S>>>())
    }
}

/**
 * Generic trait implementations
 */

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Visible for AuthenticatedScalar<N, S> {
    fn visibility(&self) -> Visibility {
        self.visibility
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> PartialEq for AuthenticatedScalar<N, S> {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq(other.value())
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Eq for AuthenticatedScalar<N, S> {}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> ConstantTimeEq
    for AuthenticatedScalar<N, S>
{
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value.ct_eq(other.value())
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Index<usize>
    for AuthenticatedScalar<N, S>
{
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        self.value.index(index)
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clear for &mut AuthenticatedScalar<N, S> {
    #[allow(clippy::needless_borrow)]
    fn clear(&mut self) {
        (&mut self.value).clear();
        (&mut self.mac_share).clear();
        (&mut self.key_share).clear()
    }
}

/**
 * Mul and variants for borrowed, non-borrowed, wrapped values
 */
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&'a AuthenticatedScalar<N, S>>
    for &'a AuthenticatedScalar<N, S>
{
    type Output = AuthenticatedScalar<N, S>;

    fn mul(self, rhs: &'a AuthenticatedScalar<N, S>) -> Self::Output {
        // If public * shared, swap arguments so public is on the RHS
        if self.is_public() && rhs.is_shared() {
            return rhs * self;
        }

        let value = self.value() * rhs.value();
        let mac = {
            // Public * public results in a public value, which has no MAC
            if self.is_public() && rhs.is_public() {
                None
            } else if rhs.is_public() {
                Some(self.mac().unwrap() * rhs.value())
            } else {
                Some(&value * self.key_share())
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

macros::impl_operator_variants!(AuthenticatedScalar<N, S>, Mul, mul, *, AuthenticatedScalar<N, S>);
macros::impl_wrapper_type!(AuthenticatedScalar<N, S>, MpcScalar<N, S>, from_mpc_scalar, Mul, mul, *, authenticated=true);
macros::impl_wrapper_type!(AuthenticatedScalar<N, S>, Scalar, from_public_scalar, Mul, mul, *, authenticated=true);
macros::impl_arithmetic_assign!(AuthenticatedScalar<N, S>, MulAssign, mul_assign, *, AuthenticatedScalar<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedScalar<N, S>, MulAssign, mul_assign, *, Scalar);

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedScalar<N, S> {
    /// Batch multiply; computes a resul [a_1 * b_1, ..., a_n * b_n]
    pub fn batch_mul(
        a: &[AuthenticatedScalar<N, S>],
        b: &[AuthenticatedScalar<N, S>],
    ) -> Result<Vec<AuthenticatedScalar<N, S>>, MpcNetworkError> {
        assert_eq!(a.len(), b.len(), "batch_mul requires equal length inputs");

        // First multiply the underlying values
        let values_batch_mul = MpcScalar::batch_mul(
            &a.iter().map(|val| val.value().clone()).collect::<Vec<_>>(),
            &b.iter().map(|val| val.value().clone()).collect::<Vec<_>>(),
        )?;

        // Now compute the updated MACs:
        //      1. Find all pairs of a_i, b_i where neither value is public
        //      2. Their MACs must be computed using a full beaver mul key_share * value, so batch_mul them
        //      3. Recombine the batch_mul result with the MACs that can be updated locally
        // TODO: We can optimize this because all values are multiplied by the same value (key_share)
        // i.e. We can open a single beaver subtraction (key_share - beaver_a) and reuse it across muls
        let mut mac_mul_a = Vec::new();
        let mut mac_mul_b = Vec::new();
        for i in 0..a.len() {
            if !a[i].is_public() && !b[i].is_public() {
                mac_mul_a.push(a[0].key_share());
                mac_mul_b.push(values_batch_mul[i].clone());
            }
        }

        // Multiply the MAC keys with the values
        let mut mac_key_mul_res = MpcScalar::batch_mul(&mac_mul_a, &mac_mul_b)?;

        // Loop over values and recombine either by direct multiplication or from the MAC batch mul
        let mut res = Vec::with_capacity(a.len());
        for i in 0..a.len() {
            let mac = {
                if a[i].is_public() && b[i].is_public() {
                    None
                } else if a[i].is_public() && b[i].is_shared() {
                    Some(a[i].value() * b[i].mac().unwrap())
                } else if a[i].is_shared() && b[i].is_public() {
                    Some(a[i].mac().unwrap() * b[i].value())
                } else {
                    // Pop from the pre-computed list of key_share * value results
                    Some(mac_key_mul_res.remove(0))
                }
            };

            res.push(AuthenticatedScalar {
                value: values_batch_mul[i].clone(),
                visibility: Visibility::min_visibility_two(&a[i], &b[i]),
                mac_share: mac,
                key_share: a[0].key_share(),
            })
        }

        Ok(res)
    }
}

/**
 * Add and variants for borrowed, non-borrowed, wrapped values
 */

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Add<&'a AuthenticatedScalar<N, S>>
    for &'a AuthenticatedScalar<N, S>
{
    type Output = AuthenticatedScalar<N, S>;

    fn add(self, rhs: &'a AuthenticatedScalar<N, S>) -> Self::Output {
        // For a public value + a scalar value; always put the public value on the RHS
        if self.is_public() && rhs.is_shared() {
            return rhs + self;
        }

        // Public + Public gives no MAC
        let mac_share = {
            // The unwraps below are appropriately handled by this fist case, if a value
            // is shared, it will have a MAC
            if self.is_public() && rhs.is_public() {
                None
            } else if rhs.is_public() {
                Some(self.mac().unwrap() + &self.key_share * rhs.value())
            } else {
                // Two shared value, directly add
                Some(self.mac().unwrap() + rhs.mac().unwrap())
            }
        };

        Self::Output {
            value: self.value() + rhs.value(),
            mac_share,
            visibility: Visibility::min_visibility_two(self, rhs),
            key_share: self.key_share.clone(),
        }
    }
}

macros::impl_operator_variants!(AuthenticatedScalar<N, S>, Add, add, +, AuthenticatedScalar<N, S>);
macros::impl_wrapper_type!(AuthenticatedScalar<N, S>, MpcScalar<N, S>, from_mpc_scalar, Add, add, +, authenticated=true);
macros::impl_wrapper_type!(AuthenticatedScalar<N, S>, Scalar, from_public_scalar, Add, add, +, authenticated=true);
macros::impl_arithmetic_assign!(AuthenticatedScalar<N, S>, AddAssign, add_assign, +, AuthenticatedScalar<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedScalar<N, S>, AddAssign, add_assign, +, Scalar);

/**
 * Sub and variants for borrowed, non-borrowed, and wrapped types
 */
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Sub<&'a AuthenticatedScalar<N, S>>
    for &'a AuthenticatedScalar<N, S>
{
    type Output = AuthenticatedScalar<N, S>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &'a AuthenticatedScalar<N, S>) -> Self::Output {
        self + rhs.neg()
    }
}

macros::impl_operator_variants!(AuthenticatedScalar<N, S>, Sub, sub, -, AuthenticatedScalar<N, S>);
macros::impl_wrapper_type!(AuthenticatedScalar<N, S>, MpcScalar<N, S>, from_mpc_scalar, Sub, sub, -, authenticated=true);
macros::impl_wrapper_type!(AuthenticatedScalar<N, S>, Scalar, from_public_scalar, Sub, sub, -, authenticated=true);
macros::impl_arithmetic_assign!(AuthenticatedScalar<N, S>, SubAssign, sub_assign, -, AuthenticatedScalar<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedScalar<N, S>, SubAssign, sub_assign, -, Scalar);

/**
 * Neg and variants for borrowed, non-borrowed types
 */
impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Neg for &'a AuthenticatedScalar<N, S> {
    type Output = AuthenticatedScalar<N, S>;

    fn neg(self) -> Self::Output {
        Self::Output {
            value: self.value().neg(),
            visibility: self.visibility(),
            mac_share: self.mac().map(|value| value.neg()),
            key_share: self.key_share(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Neg for AuthenticatedScalar<N, S> {
    type Output = AuthenticatedScalar<N, S>;

    fn neg(self) -> Self::Output {
        (&self).neg()
    }
}

/**
 * Iterator traits
 */
impl<N, S, T> Product<T> for AuthenticatedScalar<N, S>
where
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
    T: Borrow<AuthenticatedScalar<N, S>>,
{
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        let mut peekable = iter.peekable();
        let first_elem = peekable.peek().unwrap();
        let key_share: MpcScalar<N, S> = first_elem.borrow().key_share.clone();
        let network: SharedNetwork<N> = first_elem.borrow().network();
        let beaver_source: BeaverSource<S> = first_elem.borrow().beaver_source();

        peekable.fold(
            AuthenticatedScalar::one(key_share, network, beaver_source),
            |acc, item| acc * item.borrow(),
        )
    }
}

impl<N, S, T> Sum<T> for AuthenticatedScalar<N, S>
where
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
    T: Borrow<AuthenticatedScalar<N, S>>,
{
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        let mut peekable = iter.peekable();
        let first_elem = peekable.peek().unwrap();
        let key_share: MpcScalar<N, S> = first_elem.borrow().key_share();
        let network: SharedNetwork<N> = first_elem.borrow().network();
        let beaver_source: BeaverSource<S> = first_elem.borrow().beaver_source();

        peekable.fold(
            AuthenticatedScalar::zero(key_share, network, beaver_source),
            |acc, item| acc + item.borrow(),
        )
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedScalar<N, S> {
    /// Computes a linear combination of the given scalars
    pub fn linear_combination(
        scalars: &[AuthenticatedScalar<N, S>],
        coeffs: &[AuthenticatedScalar<N, S>],
    ) -> Result<AuthenticatedScalar<N, S>, MpcNetworkError> {
        Ok(AuthenticatedScalar::batch_mul(scalars, coeffs)?
            .iter()
            .sum())
    }
}

#[cfg(test)]
mod authenticated_scalar_tests {
    use std::{cell::RefCell, rc::Rc};

    use clear_on_drop::clear::Clear;
    use curve25519_dalek::scalar::Scalar;

    use crate::{
        beaver::DummySharedScalarSource, mpc_scalar::MpcScalar,
        network::dummy_network::DummyMpcNetwork,
    };

    use super::AuthenticatedScalar;

    #[test]
    fn test_clear() {
        let network = Rc::new(RefCell::new(DummyMpcNetwork::new()));
        let beaver_source = Rc::new(RefCell::new(DummySharedScalarSource::new()));
        let key_share = MpcScalar::from_public_u64(2, network.clone(), beaver_source.clone());

        let mut value = AuthenticatedScalar::from_public_u64(
            3,
            key_share,
            network.clone(),
            beaver_source.clone(),
        );
        value.mac_share = Some(MpcScalar::from_public_u64(4u64, network, beaver_source));

        (&mut value).clear();

        assert_eq!(value.to_scalar(), Scalar::zero());
        assert_eq!(value.mac_share, None);
        assert_eq!(value.key_share().to_scalar(), Scalar::zero());
    }
}
