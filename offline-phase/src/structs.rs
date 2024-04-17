//! Defines the result of the Lowgear offline phase

use std::ops::{Add, Mul, Sub};

use ark_ec::CurveGroup;
use ark_mpc::algebra::{Scalar, ScalarShare};
use ark_mpc::offline_prep::OfflinePhase;
use mp_spdz_rs::fhe::ciphertext::Ciphertext;
use mp_spdz_rs::fhe::keys::{BGVKeypair, BGVPublicKey};
use mp_spdz_rs::fhe::params::BGVParams;
use mp_spdz_rs::fhe::plaintext::PlaintextVector;

// ------------------------
// | Offline Phase Result |
// ------------------------

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

/// The resulting shared values created by the lowgear offline phase
#[derive(Clone)]
pub struct LowGearPrep<C: CurveGroup> {
    /// The params in the lowgear instance
    pub params: LowGearParams<C>,
    /// The shared inverse pairs
    pub inverse_pairs: (ValueMacBatch<C>, ValueMacBatch<C>),
    /// The shared bits
    pub bits: ValueMacBatch<C>,
    /// The shared random values
    pub shared_randomness: ValueMacBatch<C>,
    /// The shared Beaver triplets
    pub triplets: (ValueMacBatch<C>, ValueMacBatch<C>, ValueMacBatch<C>),
}

impl<C: CurveGroup> LowGearPrep<C> {
    /// Create a new `LowGearPrep`
    pub fn new(
        params: LowGearParams<C>,
        inverse_pairs: (ValueMacBatch<C>, ValueMacBatch<C>),
        bits: ValueMacBatch<C>,
        shared_randomness: ValueMacBatch<C>,
        triplets: (ValueMacBatch<C>, ValueMacBatch<C>, ValueMacBatch<C>),
    ) -> Self {
        Self { params, inverse_pairs, bits, shared_randomness, triplets }
    }

    /// Create an empty `LowGearPrep`
    pub fn empty(params: LowGearParams<C>) -> Self {
        Self {
            params,
            inverse_pairs: (ValueMacBatch::new(vec![]), ValueMacBatch::new(vec![])),
            bits: ValueMacBatch::new(vec![]),
            shared_randomness: ValueMacBatch::new(vec![]),
            triplets: (
                ValueMacBatch::new(vec![]),
                ValueMacBatch::new(vec![]),
                ValueMacBatch::new(vec![]),
            ),
        }
    }

    /// Append the given inverse pairs to this one
    pub fn append_inverse_pairs(&mut self, mut other: (ValueMacBatch<C>, ValueMacBatch<C>)) {
        self.inverse_pairs.0.append(&mut other.0);
        self.inverse_pairs.1.append(&mut other.1);
    }

    /// Append the given bits to this one
    pub fn append_bits(&mut self, other: &mut ValueMacBatch<C>) {
        self.bits.append(other);
    }

    /// Append the given triplets to this one
    pub fn append_triplets(
        &mut self,
        mut other: (ValueMacBatch<C>, ValueMacBatch<C>, ValueMacBatch<C>),
    ) {
        self.triplets.0.append(&mut other.0);
        self.triplets.1.append(&mut other.1);
        self.triplets.2.append(&mut other.2);
    }
}

impl<C: CurveGroup> OfflinePhase<C> for LowGearPrep<C> {
    fn next_shared_bit(&mut self) -> ScalarShare<C> {
        self.bits.split_off(1).into_inner()[0]
    }

    fn next_shared_bit_batch(&mut self, num_values: usize) -> Vec<ScalarShare<C>> {
        assert!(self.bits.len() >= num_values, "shared bits exhausted");
        self.bits.split_off(num_values).into_inner()
    }

    fn next_shared_value(&mut self) -> ScalarShare<C> {
        self.shared_randomness.split_off(1).into_inner()[0]
    }

    fn next_shared_value_batch(&mut self, num_values: usize) -> Vec<ScalarShare<C>> {
        assert!(self.shared_randomness.len() >= num_values, "shared random values exhausted");
        self.shared_randomness.split_off(num_values).into_inner()
    }

    fn next_shared_inverse_pair(&mut self) -> (ScalarShare<C>, ScalarShare<C>) {
        let (lhs, rhs) = self.next_shared_inverse_pair_batch(1);
        (lhs[0], rhs[0])
    }

    fn next_shared_inverse_pair_batch(
        &mut self,
        num_pairs: usize,
    ) -> (Vec<ScalarShare<C>>, Vec<ScalarShare<C>>) {
        assert!(self.inverse_pairs.0.len() >= num_pairs, "shared inverse pairs exhausted");
        let lhs = self.inverse_pairs.0.split_off(num_pairs);
        let rhs = self.inverse_pairs.1.split_off(num_pairs);
        (lhs.into_inner(), rhs.into_inner())
    }

    fn next_triplet(&mut self) -> (ScalarShare<C>, ScalarShare<C>, ScalarShare<C>) {
        let (a, b, c) = self.next_triplet_batch(1);
        (a[0], b[0], c[0])
    }

    fn next_triplet_batch(
        &mut self,
        num_triplets: usize,
    ) -> (Vec<ScalarShare<C>>, Vec<ScalarShare<C>>, Vec<ScalarShare<C>>) {
        assert!(self.triplets.0.len() >= num_triplets, "shared triplets exhausted");
        let a = self.triplets.0.split_off(num_triplets);
        let b = self.triplets.1.split_off(num_triplets);
        let c = self.triplets.2.split_off(num_triplets);

        (a.into_inner(), b.into_inner(), c.into_inner())
    }
}

// ------------------------
// | Authenticated Shares |
// ------------------------

/// A struct containing a batch of values and macs
#[derive(Clone, Default)]
pub struct ValueMacBatch<C: CurveGroup> {
    /// The values and macs
    inner: Vec<ScalarShare<C>>,
}

impl<C: CurveGroup> ValueMacBatch<C> {
    /// Create a new ValueMacBatch
    pub fn new(inner: Vec<ScalarShare<C>>) -> Self {
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

    /// Append the given batch to this one
    pub fn append(&mut self, other: &mut Self) {
        self.inner.append(&mut other.inner);
    }

    /// Get the inner vector
    pub fn into_inner(self) -> Vec<ScalarShare<C>> {
        self.inner
    }

    /// Get all values
    pub fn values(&self) -> Vec<Scalar<C>> {
        self.inner.iter().map(|vm| vm.share()).collect()
    }

    /// Get all macs
    pub fn macs(&self) -> Vec<Scalar<C>> {
        self.inner.iter().map(|vm| vm.mac()).collect()
    }

    /// Get an iterator over the vector
    pub fn iter(&self) -> std::slice::Iter<'_, ScalarShare<C>> {
        self.inner.iter()
    }

    /// Get a mutable iterator over the vector
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, ScalarShare<C>> {
        self.inner.iter_mut()
    }

    /// Split the batch in two at the given index
    pub fn split_at(&self, i: usize) -> (Self, Self) {
        let (lhs, rhs) = self.inner.split_at(i);
        (Self { inner: lhs.to_vec() }, Self { inner: rhs.to_vec() })
    }

    /// Split off the last `n` elements from the batch
    pub fn split_off(&mut self, n: usize) -> Self {
        let split_idx = self.len() - n;
        let split = self.inner.split_off(split_idx);
        Self { inner: split }
    }

    /// Create a new ValueMacBatch from a batch of values and macs
    pub fn from_parts(values: &[Scalar<C>], macs: &[Scalar<C>]) -> Self {
        assert_eq!(values.len(), macs.len());
        if values.is_empty() {
            return Self { inner: vec![] };
        }

        let inner = values.iter().zip(macs.iter()).map(|(v, m)| ScalarShare::new(*v, *m)).collect();
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
    type Item = ScalarShare<C>;
    type IntoIter = std::vec::IntoIter<ScalarShare<C>>;

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

#[cfg(test)]
mod test {
    use ark_mpc::{
        algebra::Scalar, test_helpers::execute_mock_mpc_with_beaver_source, PARTY0, PARTY1,
    };
    use rand::thread_rng;

    use crate::test_helpers::mock_lowgear_with_triples;

    /// Tests the use of the `LowGear` type as an `OfflinePhase` implementation
    #[tokio::test]
    async fn test_lowgear_offline_phase() {
        // Setup the mock offline phase
        let (prep1, prep2) = mock_lowgear_with_triples(
            100, // num_triples
            |mut lowgear| async move { lowgear.get_offline_result().unwrap() },
        )
        .await;

        // Run a mock mpc using the lowgear offline phase
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let expected = a * b;

        let (res, _) = execute_mock_mpc_with_beaver_source(
            |fabric| async move {
                let a_shared = fabric.share_scalar(a, PARTY0);
                let b_shared = fabric.share_scalar(b, PARTY1);

                let c = a_shared * b_shared;
                c.open().await
            },
            prep1,
            prep2,
        )
        .await;

        assert_eq!(res, expected);
    }
}
