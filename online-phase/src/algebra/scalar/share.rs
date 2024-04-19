//! Defines the maliciously secure secret sharing primitive for the `Scalar`
//! type

// ------------
// | ShareMac |
// ------------

use std::{
    iter::Sum,
    ops::{Add, Mul, Neg, Sub},
};

use ark_ec::CurveGroup;
use ark_poly::EvaluationDomain;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    algebra::{
        macros::{impl_borrow_variants, impl_commutative},
        CurvePoint, PointShare,
    },
    network::PartyId,
    PARTY0,
};

use super::Scalar;

/// A type holding both a share and a MAC
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(serialize = "C: CurveGroup", deserialize = "C: CurveGroup"))]
pub struct ScalarShare<C: CurveGroup> {
    /// The share
    pub(crate) share: Scalar<C>,
    /// The mac
    pub(crate) mac: Scalar<C>,
}

impl<C: CurveGroup> ScalarShare<C> {
    /// Constructor
    pub fn new(share: Scalar<C>, mac: Scalar<C>) -> Self {
        Self { share, mac }
    }

    /// Get the share
    pub fn share(&self) -> Scalar<C> {
        self.share
    }

    /// Set the share
    pub fn set_share(&mut self, share: Scalar<C>) {
        self.share = share;
    }

    /// Get the mac
    pub fn mac(&self) -> Scalar<C> {
        self.mac
    }

    /// Set the mac
    pub fn set_mac(&mut self, mac: Scalar<C>) {
        self.mac = mac;
    }
}

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl<C: CurveGroup> ScalarShare<C> {
    /// Add a public value to a scalar share
    pub fn add_public(&self, rhs: Scalar<C>, mac_key: Scalar<C>, party_id: PartyId) -> Self {
        let share = if party_id == PARTY0 { self.share + rhs } else { self.share };
        ScalarShare::new(share, self.mac + mac_key * rhs)
    }

    /// Subtract a public value from the share
    pub fn sub_public(&self, rhs: Scalar<C>, mac_key: Scalar<C>, party_id: PartyId) -> Self {
        self.add_public(-rhs, mac_key, party_id)
    }
}

impl<C: CurveGroup> Add for &ScalarShare<C> {
    type Output = ScalarShare<C>;

    fn add(self, rhs: Self) -> Self::Output {
        ScalarShare::new(self.share + rhs.share, self.mac + rhs.mac)
    }
}
impl_borrow_variants!(ScalarShare<C>, Add, add, +, ScalarShare<C>, C: CurveGroup);

// === Subtraction === //
impl<C: CurveGroup> Sub for &ScalarShare<C> {
    type Output = ScalarShare<C>;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}
impl_borrow_variants!(ScalarShare<C>, Sub, sub, -, ScalarShare<C>, C: CurveGroup);

impl<C: CurveGroup> Sum for ScalarShare<C> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let (shares, macs): (Vec<Scalar<_>>, Vec<Scalar<_>>) =
            iter.into_iter().map(|s| (s.share, s.mac)).unzip();

        ScalarShare::new(shares.into_iter().sum(), macs.into_iter().sum())
    }
}

// === Negation === //

impl<C: CurveGroup> Neg for &ScalarShare<C> {
    type Output = ScalarShare<C>;

    fn neg(self) -> Self::Output {
        ScalarShare::new(-self.share, -self.mac)
    }
}
impl_borrow_variants!(ScalarShare<C>, Neg, neg, -, C: CurveGroup);

// === Multiplication == //
impl<C: CurveGroup> Mul<&Scalar<C>> for &ScalarShare<C> {
    type Output = ScalarShare<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        ScalarShare::new(self.share * rhs, self.mac * rhs)
    }
}
impl_borrow_variants!(ScalarShare<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
impl_commutative!(ScalarShare<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);

impl<C: CurveGroup> Mul<&CurvePoint<C>> for &ScalarShare<C> {
    type Output = PointShare<C>;

    fn mul(self, rhs: &CurvePoint<C>) -> Self::Output {
        PointShare::new(self.share * rhs, self.mac * rhs)
    }
}
impl_borrow_variants!(
    ScalarShare<C>,
    Mul,
    mul,
    *,
    CurvePoint<C>,
    Output=PointShare<C>,
    C: CurveGroup
);
impl_commutative!(
    ScalarShare<C>,
    Mul,
    mul,
    *,
    CurvePoint<C>,
    Output=PointShare<C>,
    C: CurveGroup
);

// === FFT === //
impl<C: CurveGroup> ScalarShare<C> {
    /// An FFT/IFFT helper that encapsulates the setup and restructuring of an
    /// FFT regardless of direction
    ///
    /// If `is_forward` is set, an FFT is performed. Otherwise, an IFFT is
    /// performed
    pub fn fft_helper<D: 'static + EvaluationDomain<C::ScalarField> + Send>(
        x: &[Self],
        is_forward: bool,
        domain: D,
    ) -> Vec<Self> {
        assert!(!x.is_empty(), "FFT/IFFT helper requires non-empty input");

        // Convert to arkworks types
        let share_scalars = x.iter().map(|s| s.share.inner()).collect_vec();
        let mac_scalars = x.iter().map(|s| s.mac.inner()).collect_vec();

        // (i)FFT
        let (share_fft, mac_fft) = if is_forward {
            (domain.fft(&share_scalars), domain.fft(&mac_scalars))
        } else {
            (domain.ifft(&share_scalars), domain.ifft(&mac_scalars))
        };

        // Restructure into shares
        let new_shares = share_fft.into_iter().map(|x| Scalar::new(x)).collect_vec();
        let new_macs = mac_fft.into_iter().map(|x| Scalar::new(x)).collect_vec();

        new_shares.into_iter().zip(new_macs).map(|(share, mac)| Self { share, mac }).collect_vec()
    }
}
