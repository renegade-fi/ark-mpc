//! Defines the result of the Lowgear offline phase

use std::ops::{Add, Mul, Sub};

use ark_ec::CurveGroup;
use ark_mpc::algebra::Scalar;
use mp_spdz_rs::fhe::ciphertext::Ciphertext;
use mp_spdz_rs::fhe::keys::{BGVKeypair, BGVPublicKey};
use mp_spdz_rs::fhe::params::BGVParams;
use mp_spdz_rs::fhe::plaintext::PlaintextVector;

/// The parameters setup by the offline phase
#[derive(Clone)]
pub struct LowGearParams<C: CurveGroup> {
    /// The local party's BGV keypair
    pub local_keypair: BGVKeypair<C>,
    /// The local party's MAC key share
    pub mac_key_share: Scalar<C>,
    /// The BGV public key of the counterparty
    pub other_pk: BGVPublicKey<C>,
    /// An encryption of the counterparty's MAC key share
    pub other_mac_enc: Ciphertext<C>,
    /// The BGV cryptosystem parameters
    pub bgv_params: BGVParams<C>,
}

/// A type storing values and their macs
#[derive(Default, Copy, Clone)]
pub struct ValueMac<C: CurveGroup> {
    /// The value
    pub(crate) value: Scalar<C>,
    /// The mac
    pub(crate) mac: Scalar<C>,
}

impl<C: CurveGroup> ValueMac<C> {
    /// Create a new ValueMacPair
    pub fn new(value: Scalar<C>, mac: Scalar<C>) -> Self {
        Self { value, mac }
    }

    /// Get the value
    pub fn value(&self) -> Scalar<C> {
        self.value
    }

    /// Get the mac
    pub fn mac(&self) -> Scalar<C> {
        self.mac
    }
}

impl<C: CurveGroup> Add for &ValueMac<C> {
    type Output = ValueMac<C>;

    fn add(self, other: Self) -> Self::Output {
        ValueMac::new(self.value + other.value, self.mac + other.mac)
    }
}

impl<C: CurveGroup> Sub for &ValueMac<C> {
    type Output = ValueMac<C>;

    fn sub(self, other: Self) -> Self::Output {
        ValueMac::new(self.value - other.value, self.mac - other.mac)
    }
}

impl<C: CurveGroup> Mul<Scalar<C>> for &ValueMac<C> {
    type Output = ValueMac<C>;

    fn mul(self, other: Scalar<C>) -> Self::Output {
        ValueMac::new(self.value * other, self.mac * other)
    }
}

/// A struct containing a batch of values and macs
#[derive(Clone)]
pub struct ValueMacBatch<C: CurveGroup> {
    /// The values and macs
    inner: Vec<ValueMac<C>>,
}

impl<C: CurveGroup> ValueMacBatch<C> {
    /// Create a new ValueMacBatch
    pub fn new(inner: Vec<ValueMac<C>>) -> Self {
        Self { inner }
    }

    /// Get the length of the batch
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get the inner vector
    pub fn into_inner(self) -> Vec<ValueMac<C>> {
        self.inner
    }

    /// Get all values
    pub fn values(&self) -> Vec<Scalar<C>> {
        self.inner.iter().map(|vm| vm.value).collect()
    }

    /// Get all macs
    pub fn macs(&self) -> Vec<Scalar<C>> {
        self.inner.iter().map(|vm| vm.mac).collect()
    }

    /// Get an iterator over the vector
    pub fn iter(&self) -> std::slice::Iter<'_, ValueMac<C>> {
        self.inner.iter()
    }

    /// Get a mutable iterator over the vector
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, ValueMac<C>> {
        self.inner.iter_mut()
    }

    /// Create a new ValueMacBatch from a batch of values and macs
    pub fn from_parts(values: &[Scalar<C>], macs: &[Scalar<C>]) -> Self {
        assert_eq!(values.len(), macs.len());
        if values.is_empty() {
            return Self { inner: vec![] };
        }

        let inner = values.iter().zip(macs.iter()).map(|(v, m)| ValueMac::new(*v, *m)).collect();
        Self { inner }
    }

    /// Create a new ValueMacBatch from a batch of values and macs
    /// represented as plaintexts
    pub fn from_plaintexts(values: &PlaintextVector<C>, macs: &PlaintextVector<C>) -> Self {
        assert_eq!(values.len(), macs.len());
        if values.is_empty() {
            return Self { inner: vec![] };
        }

        let scalar_values = Self::plaintext_vec_to_scalar(values);
        let scalar_macs = Self::plaintext_vec_to_scalar(macs);

        Self::from_parts(&scalar_values, &scalar_macs)
    }

    /// Convert a plaintext vector to a vector of scalars
    fn plaintext_vec_to_scalar(pt: &PlaintextVector<C>) -> Vec<Scalar<C>> {
        let mut vec = Vec::with_capacity(pt.len() * pt.get(0).num_slots());
        for i in 0..pt.len() {
            let pt = pt.get(i);
            for j in 0..pt.num_slots() {
                vec.push(pt.get_element(j));
            }
        }

        vec
    }
}

impl<C: CurveGroup> IntoIterator for ValueMacBatch<C> {
    type Item = ValueMac<C>;
    type IntoIter = std::vec::IntoIter<ValueMac<C>>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<C: CurveGroup> Add for &ValueMacBatch<C> {
    type Output = ValueMacBatch<C>;

    fn add(self, other: Self) -> Self::Output {
        ValueMacBatch::new(self.inner.iter().zip(other.inner.iter()).map(|(a, b)| a + b).collect())
    }
}

impl<C: CurveGroup> Sub for &ValueMacBatch<C> {
    type Output = ValueMacBatch<C>;

    fn sub(self, other: Self) -> Self::Output {
        ValueMacBatch::new(self.inner.iter().zip(other.inner.iter()).map(|(a, b)| a - b).collect())
    }
}

impl<C: CurveGroup> Mul<Scalar<C>> for &ValueMacBatch<C> {
    type Output = ValueMacBatch<C>;

    fn mul(self, other: Scalar<C>) -> Self::Output {
        ValueMacBatch::new(self.inner.iter().map(|a| a * other).collect())
    }
}

// Element-wise scalar multiplication
impl<C: CurveGroup> Mul<&[Scalar<C>]> for &ValueMacBatch<C> {
    type Output = ValueMacBatch<C>;

    fn mul(self, other: &[Scalar<C>]) -> Self::Output {
        ValueMacBatch::new(self.inner.iter().zip(other.iter()).map(|(a, b)| a * *b).collect())
    }
}
