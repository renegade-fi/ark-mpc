//! Multiplication sub-protocol using the Beaver trick

use ark_ec::CurveGroup;
use ark_mpc::{algebra::Scalar, network::MpcNetwork, PARTY0};
use itertools::Itertools;

use crate::{beaver_source::ValueMacBatch, error::LowGearError};

use super::LowGear;

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin + Send> LowGear<C, N> {
    /// Multiply two batches of values using the Beaver trick
    pub async fn beaver_mul(
        &mut self,
        lhs: &ValueMacBatch<C>,
        rhs: &ValueMacBatch<C>,
    ) -> Result<ValueMacBatch<C>, LowGearError> {
        let n = lhs.len();
        assert_eq!(rhs.len(), n, "Batch sizes must match");
        assert!(self.triples.len() >= n, "Not enough triples for batch size");

        // Get triples for the beaver trick
        let (a, b, c) = self.consume_triples(n);

        // Open d = lhs - a and e = rhs - b
        let d = self.open_and_check_macs(&(lhs - &a)).await?;
        let e = self.open_and_check_macs(&(rhs - &b)).await?;

        // Identity: [x * y] = de + d[b] + e[a] + [c]
        let de = d.iter().zip(e.iter()).map(|(d, e)| d * e).collect_vec();
        let db = &b * d.as_slice();
        let ea = &a * e.as_slice();
        let mut shared_sum = &(&db + &ea) + &c;

        // Only the first party adds the public term to their shares
        self.add_public_value(&de, &mut shared_sum);

        Ok(shared_sum)
    }

    /// Get the next `n` triples from the beaver source
    fn consume_triples(
        &mut self,
        n: usize,
    ) -> (ValueMacBatch<C>, ValueMacBatch<C>, ValueMacBatch<C>) {
        let triples = self.triples.split_off(n);

        let mut a_res = Vec::with_capacity(n);
        let mut b_res = Vec::with_capacity(n);
        let mut c_res = Vec::with_capacity(n);
        for (a, b, c) in triples.iter() {
            a_res.push(*a);
            b_res.push(*b);
            c_res.push(*c);
        }

        (ValueMacBatch::new(a_res), ValueMacBatch::new(b_res), ValueMacBatch::new(c_res))
    }

    /// Add a batch of public values to a batch of shared values
    ///
    /// Only the first party adds the public term to their shares, both parties
    /// add the corresponding mac term
    fn add_public_value(&mut self, public: &[Scalar<C>], batch: &mut ValueMacBatch<C>) {
        let is_party0 = self.party_id() == PARTY0;
        for (val, public) in batch.iter_mut().zip(public.iter()) {
            val.mac += self.mac_share * public;
            if is_party0 {
                val.value += *public;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_mpc::{algebra::Scalar, PARTY0};
    use itertools::{izip, Itertools};
    use rand::thread_rng;

    use crate::{
        beaver_source::ValueMacBatch,
        test_helpers::{encrypt_all, mock_lowgear_with_keys, TestCurve},
    };

    /// Generate random mock triples for the Beaver trick
    #[allow(clippy::type_complexity)]
    fn generate_triples(
        n: usize,
    ) -> (Vec<Scalar<TestCurve>>, Vec<Scalar<TestCurve>>, Vec<Scalar<TestCurve>>) {
        let mut rng = thread_rng();
        let a = (0..n).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();
        let b = (0..n).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();
        let c = (0..n).map(|_| Scalar::<TestCurve>::random(&mut rng)).collect_vec();

        (a, b, c)
    }

    /// Generate authenticated secret shares of a given set of values
    fn generate_authenticated_secret_shares(
        values: &[Scalar<TestCurve>],
        mac_key: Scalar<TestCurve>,
    ) -> (ValueMacBatch<TestCurve>, ValueMacBatch<TestCurve>) {
        let (shares1, shares2) = generate_secret_shares(values);
        let macs = values.iter().map(|value| *value * mac_key).collect_vec();
        let (macs1, macs2) = generate_secret_shares(&macs);

        (ValueMacBatch::from_parts(&shares1, &macs1), ValueMacBatch::from_parts(&shares2, &macs2))
    }

    /// Generate secret shares of a set of values
    fn generate_secret_shares(
        values: &[Scalar<TestCurve>],
    ) -> (Vec<Scalar<TestCurve>>, Vec<Scalar<TestCurve>>) {
        let mut rng = thread_rng();
        let mut shares1 = Vec::with_capacity(values.len());
        let mut shares2 = Vec::with_capacity(values.len());
        for value in values {
            let share1 = Scalar::<TestCurve>::random(&mut rng);
            let share2 = value - share1;
            shares1.push(share1);
            shares2.push(share2);
        }

        (shares1, shares2)
    }

    #[tokio::test]
    async fn test_beaver_mul() {
        const N: usize = 100;
        let mut rng = thread_rng();

        // Setup mock keys and triplets
        let mac_key = Scalar::<TestCurve>::random(&mut rng);
        let mac_key1 = Scalar::<TestCurve>::random(&mut rng);
        let mac_key2 = mac_key - mac_key1;

        let (a, b, c) = generate_triples(N);
        let (a1, a2) = generate_authenticated_secret_shares(&a, mac_key);
        let (b1, b2) = generate_authenticated_secret_shares(&b, mac_key);
        let (c1, c2) = generate_authenticated_secret_shares(&c, mac_key);

        mock_lowgear_with_keys(|mut lowgear| {
            // Setup the mac shares and counterparty mac share encryptions
            let is_party0 = lowgear.party_id() == PARTY0;
            lowgear.mac_share = if is_party0 { mac_key1 } else { mac_key2 };

            let other_pk = lowgear.other_pk.as_ref().unwrap();
            let other_share = if is_party0 { mac_key2 } else { mac_key1 };
            lowgear.other_mac_enc = Some(encrypt_all(other_share, other_pk, &lowgear.params));

            // Setup the mock triplets
            let (my_a, my_b, my_c) = if is_party0 { (&a1, &b1, &c1) } else { (&a2, &b2, &c2) };
            lowgear.triples = izip!(
                my_a.clone().into_inner(),
                my_b.clone().into_inner(),
                my_c.clone().into_inner()
            )
            .collect_vec();

            // Test the multiplication sub-protocol
            async move {
                let lhs = lowgear.get_authenticated_randomness_vec(N).await.unwrap();
                let rhs = lowgear.get_authenticated_randomness_vec(N).await.unwrap();
                let res = lowgear.beaver_mul(&lhs, &rhs).await.unwrap();

                // Open all values
                let lhs_open = lowgear.open_and_check_macs(&lhs).await.unwrap();
                let rhs_open = lowgear.open_and_check_macs(&rhs).await.unwrap();
                let res_open = lowgear.open_and_check_macs(&res).await.unwrap();

                // Assert that the result is equal to the expected value
                for (l, r, re) in izip!(lhs_open, rhs_open, res_open) {
                    assert_eq!(re, l * r);
                }
            }
        })
        .await;
    }
}
