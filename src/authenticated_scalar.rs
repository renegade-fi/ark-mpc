//! Implements an authenticated wrapper around the MpcScalar type for malicious security

use std::ops::{Index, Add, AddAssign, Neg, Sub, SubAssign, Mul};

use curve25519_dalek::scalar::Scalar;
use subtle::ConstantTimeEq;

use crate::{network::MpcNetwork, mpc_scalar::MpcScalar, beaver::SharedValueSource, Visibility, SharedNetwork, BeaverSource, macros, error::{MpcNetworkError, MpcError}, Visible};


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
    pub(crate) fn is_public(&self) -> bool {
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
    fn mac(&self) -> Option<MpcScalar<N, S>> {
        self.mac_share.clone()
    }

    #[inline]
    fn key_share(&self) -> MpcScalar<N, S> {
        self.key_share.clone()
    }

    #[inline]
    fn network(&self) -> SharedNetwork<N> {
        self.value().network.clone()
    }

    #[inline]
    fn beaver_source(&self) -> BeaverSource<S> {
        self.value().beaver_source.clone()
    }
    
    #[inline]
    pub fn to_scalar(&self) -> Scalar {
        self.value().value()
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
    fn from_mpc_scalar(x: MpcScalar<N, S>, key_share: MpcScalar<N, S>, _: SharedNetwork<N>, _: BeaverSource<S>) -> Self {
        Self::from_mpc_scalar_with_visibility(x, Visibility::Public, key_share)
    }

    pub(crate) fn from_mpc_scalar_with_visibility(
        x: MpcScalar<N, S>,
        visibility: Visibility,
        key_share: MpcScalar<N, S>
    ) -> Self {
        Self {
            value: x,
            visibility,
            key_share,
            mac_share: None,  // This function should not be used to construct shared values
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
    pub fn open_and_authenticate(&self) -> Result<AuthenticatedScalar<N, S>, MpcError> {
        // TODO: implement commitment phase, current implementation is not safe
        // If the value is not shared, there is nothing to open and authenticate
        if !self.is_shared() {
            return Ok(self.clone())
        }

        // Open the value
        let opened_value = self.value().open()
            .map_err(MpcError::NetworkError)?;
        let mac_check_share = &self.key_share * &opened_value - self.mac().unwrap();

        // The opening of hte mac_check should be 0
        let mac_check_open = mac_check_share.open()
            .map_err(MpcError::NetworkError)?;
        if mac_check_open.value().ne(&Scalar::zero()) {
            return Err(MpcError::AuthenticationError)
        }

        // If authentication check passes, return the opened value
        Ok(
            Self {
                value: opened_value,
                visibility: Visibility::Public,
                key_share: self.key_share.clone(),
                mac_share: None,  // Public value has no MAC
            }
        )
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

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> ConstantTimeEq for AuthenticatedScalar<N, S> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value.ct_eq(other.value())
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Index<usize> for AuthenticatedScalar<N, S> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        self.value.index(index)
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
            return rhs * self
        }

        let value = self.value() * rhs.value();
        let mac = {
            // Public * public results in a public value, which has no MAC
            if self.is_public() && rhs.is_public() { None }
            else {
                Some(
                    &value * self.key_share()
                )
            }
        };

        Self::Output {
            value,
            visibility: Visibility::min_visibility_two(self, rhs),
            mac_share: mac,
            key_share: self.key_share()
        }
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
            return rhs + self
        }

        // Public + Public gives no MAC
        let mac_share = {
            // The unwraps below are appropriately handled by this fist case, if a value
            // is shared, it will have a MAC
            if self.is_public() && rhs.is_public() {
                None
            } else if rhs.is_public() {
                Some(
                    self.mac().unwrap() + &self.key_share * rhs.value() 
                )
            } else {
                // Two shared value, directly add
                Some(
                    self.mac().unwrap() + rhs.mac().unwrap()
                )
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

macros::impl_arithmetic_assign!(AuthenticatedScalar<N, S>, AddAssign, add_assign, +, AuthenticatedScalar<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedScalar<N, S>, AddAssign, add_assign, +, Scalar);
macros::impl_arithmetic_wrapper!(AuthenticatedScalar<N, S>, Add, add, +, AuthenticatedScalar<N, S>);
macros::impl_arithmetic_wrapped_authenticated!(
    AuthenticatedScalar<N, S>, Add, add, +, from_public_scalar, Scalar
);
macros::impl_arithmetic_wrapped_authenticated!(
    AuthenticatedScalar<N, S>, Add, add, +, from_mpc_scalar, MpcScalar<N, S>
);


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

macros::impl_arithmetic_assign!(AuthenticatedScalar<N, S>, SubAssign, sub_assign, -, AuthenticatedScalar<N, S>);
macros::impl_arithmetic_assign!(AuthenticatedScalar<N, S>, SubAssign, sub_assign, -, Scalar);
macros::impl_arithmetic_wrapper!(AuthenticatedScalar<N, S>, Sub, sub, -, AuthenticatedScalar<N, S>);
macros::impl_arithmetic_wrapped_authenticated!(
    AuthenticatedScalar<N, S>, Sub, sub, -, from_public_scalar, Scalar
);
macros::impl_arithmetic_wrapped_authenticated!(
    AuthenticatedScalar<N, S>, Sub, sub, -, from_mpc_scalar, MpcScalar<N, S>
);

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