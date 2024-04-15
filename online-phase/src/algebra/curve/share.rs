//! Secret share implementations for curve points

use std::{
    iter::Sum,
    ops::{Add, Mul, Neg, Sub},
};

use ark_ec::CurveGroup;
use serde::{Deserialize, Serialize};

use crate::{
    algebra::{
        macros::{impl_borrow_variants, impl_commutative},
        Scalar,
    },
    network::PartyId,
    PARTY0,
};

use super::CurvePoint;

/// An authenticated secret share of a point on a curve
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "C: CurveGroup", deserialize = "C: CurveGroup"))]
pub struct PointShare<C: CurveGroup> {
    /// The share
    pub(crate) share: CurvePoint<C>,
    /// The mac
    pub(crate) mac: CurvePoint<C>,
}

impl<C: CurveGroup> PointShare<C> {
    /// Constructor
    pub fn new(share: CurvePoint<C>, mac: CurvePoint<C>) -> Self {
        Self { share, mac }
    }

    /// Get the share
    pub fn share(&self) -> CurvePoint<C> {
        self.share
    }

    /// Get the mac
    pub fn mac(&self) -> CurvePoint<C> {
        self.mac
    }
}

// --------------
// | Arithmetic |
// --------------

// === Addition === //

impl<C: CurveGroup> PointShare<C> {
    /// Add a public value to a scalar share
    pub fn add_public(&self, rhs: CurvePoint<C>, mac_key: Scalar<C>, party_id: PartyId) -> Self {
        let share = if party_id == PARTY0 { self.share + rhs } else { self.share };
        PointShare::new(share, self.mac + mac_key * rhs)
    }

    /// Subtract a public value from the share
    pub fn sub_public(&self, rhs: CurvePoint<C>, mac_key: Scalar<C>, party_id: PartyId) -> Self {
        self.add_public(-rhs, mac_key, party_id)
    }
}

impl<C: CurveGroup> Add for &PointShare<C> {
    type Output = PointShare<C>;

    fn add(self, rhs: Self) -> Self::Output {
        PointShare::new(self.share + rhs.share, self.mac + rhs.mac)
    }
}
impl_borrow_variants!(PointShare<C>, Add, add, +, PointShare<C>, C: CurveGroup);

// === Subtraction === //
impl<C: CurveGroup> Sub for &PointShare<C> {
    type Output = PointShare<C>;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}
impl_borrow_variants!(PointShare<C>, Sub, sub, -, PointShare<C>, C: CurveGroup);

impl<C: CurveGroup> Sum for PointShare<C> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let (shares, macs): (Vec<CurvePoint<_>>, Vec<CurvePoint<_>>) =
            iter.into_iter().map(|s| (s.share, s.mac)).unzip();

        PointShare::new(shares.into_iter().sum(), macs.into_iter().sum())
    }
}

// === Negation === //

impl<C: CurveGroup> Neg for &PointShare<C> {
    type Output = PointShare<C>;

    fn neg(self) -> Self::Output {
        PointShare::new(-self.share, -self.mac)
    }
}
impl_borrow_variants!(PointShare<C>, Neg, neg, -, C: CurveGroup);

// === Multiplication == //
impl<C: CurveGroup> Mul<&Scalar<C>> for &PointShare<C> {
    type Output = PointShare<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        PointShare::new(self.share * rhs, self.mac * rhs)
    }
}
impl_borrow_variants!(PointShare<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
impl_commutative!(PointShare<C>, Mul, mul, *, Scalar<C>, C: CurveGroup);
