//! Subprotocol to generate secret shares of bits, i.e. Scalars in {0, 1}

use ark_ec::CurveGroup;
use ark_mpc::{algebra::Scalar, network::MpcNetwork};
use itertools::Itertools;

use crate::error::LowGearError;

use super::LowGear;

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin + Send> LowGear<C, N> {
    /// Generate shared bits
    ///
    /// This works as follows:
    /// 1. Generate random shared values and square them via the multiplication
    ///    subprotocol
    /// 2. Open the squared values
    /// 3. Take the square root of the opened values, invert it, then multiply
    ///    with the original shared random value
    /// 4. This is either -1 or 1 with equal probability due to QR
    /// 5. Shift this range to 0, 1; i.e. add one, divide by two
    pub async fn generate_shared_bits(&mut self, n: usize) -> Result<(), LowGearError> {
        // This method requires `n` tuples to sacrifice in the multiplication step
        assert!(self.num_triples() >= n, "Not enough triples to generate {} bits", n);
        if n == 0 {
            return Ok(());
        }

        let random_vals = self.get_authenticated_randomness_vec(n).await?;
        let squared_vals = self.beaver_mul(&random_vals, &random_vals).await?;

        // Open the squared values, take the square root, invert, and multiply with the
        // original random value
        let opened_vals = self.open_and_check_macs(&squared_vals).await?;
        let sqrt_inv_vals = opened_vals.iter().map(|x| x.sqrt().unwrap().inverse()).collect_vec();

        // Multiply with the original random value and shift the resulting range
        let ones = (0..n).map(|_| Scalar::one()).collect_vec();
        let inv_twos = (0..n).map(|_| Scalar::from(2u8).inverse()).collect_vec();

        let mut neg_one_or_one = &random_vals * sqrt_inv_vals.as_slice();
        self.add_public_value(&ones, &mut neg_one_or_one);
        self.shared_bits = &neg_one_or_one * inv_twos.as_slice();

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ark_mpc::algebra::Scalar;

    use crate::test_helpers::mock_lowgear_with_triples;

    /// Tests the `generate_shared_bits` method
    #[tokio::test]
    async fn test_generate_shared_bits() {
        const N: usize = 1000;
        mock_lowgear_with_triples(N, |mut lowgear| async move {
            lowgear.generate_shared_bits(N).await.unwrap();

            // Open the shared bits and check that they are either 0 or 1
            let bits = lowgear.shared_bits.clone();
            let opened_bits = lowgear.open_and_check_macs(&bits).await.unwrap();
            assert!(opened_bits.iter().all(|x| *x == Scalar::zero() || *x == Scalar::one()));
        })
        .await;
    }
}
