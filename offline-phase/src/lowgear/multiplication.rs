//! Multiplication sub-protocol using the Beaver trick

use ark_ec::CurveGroup;
use ark_mpc::{algebra::Scalar, network::MpcNetwork, PARTY0};
use itertools::Itertools;

use crate::{error::LowGearError, structs::ValueMacBatch};

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
        assert!(self.num_triples() >= n, "Not enough triples for batch size");

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
        // let triples = self.triples.split_off(n);
        let a = self.triples.0.split_off(n);
        let b = self.triples.1.split_off(n);
        let c = self.triples.2.split_off(n);

        (a, b, c)
    }

    /// Add a batch of public values to a batch of shared values
    ///
    /// Only the first party adds the public term to their shares, both parties
    /// add the corresponding mac term
    pub(crate) fn add_public_value(&mut self, public: &[Scalar<C>], batch: &mut ValueMacBatch<C>) {
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
    use itertools::izip;

    use crate::test_helpers::mock_lowgear_with_triples;

    #[tokio::test]
    async fn test_beaver_mul() {
        const N: usize = 100;

        mock_lowgear_with_triples(N, |mut lowgear| async move {
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
        })
        .await;
    }
}
