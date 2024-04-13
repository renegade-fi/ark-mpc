//! Defines the subprotocol for generating tuples (a, a^{-1}) for a random value
//! a

use ark_ec::CurveGroup;
use ark_mpc::network::MpcNetwork;
use itertools::Itertools;

use crate::error::LowGearError;

use super::LowGear;

impl<C: CurveGroup, N: MpcNetwork<C> + Unpin + Send> LowGear<C, N> {
    /// Generate a set of inverse tuples
    ///
    /// 1. Multiply the left and right hand side randomness. We consider one of
    ///    these random values to be a multiplicative blinder of the other.
    /// 2. Open the product and check its MAC
    /// 3. Invert the publicly available value and multiply with the shared
    ///    product to get the inverse of the blinded randomness
    pub async fn generate_inverse_tuples(&mut self, n: usize) -> Result<(), LowGearError> {
        // We need `n` triplets to sacrifice for `n` inverse tuples
        assert!(self.triples.len() >= n, "Not enough triplets to generate {n} inverse tuples");
        let random_values = self.get_authenticated_randomness_vec(2 * n).await?;
        let (lhs, rhs) = random_values.split_at(n);

        // Multiply left and right hand side value
        let product = self.beaver_mul(&lhs, &rhs).await?;
        let product_open = self.open_and_check_macs(&product).await?;

        // Invert the publicly available value and multiply with the shared
        // product to get the inverse of the blinded randomness
        let inverses = product_open.into_iter().map(|x| x.inverse()).collect_vec();
        let shared_inverses = &rhs * inverses.as_slice(); // this leaves `1 / lhs`

        // Structure into inverse tuples
        let tuples = lhs.into_iter().zip(shared_inverses.into_iter()).collect_vec();
        self.inverse_tuples = tuples;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ark_mpc::{algebra::Scalar, test_helpers::TestCurve};
    use itertools::izip;

    use crate::{
        beaver_source::{ValueMac, ValueMacBatch},
        test_helpers::mock_lowgear_with_triples,
    };

    /// Tests generating inverse tuples
    #[tokio::test]
    async fn test_generate_inverse_tuples() {
        const N: usize = 100; // The number of tuples to generate

        mock_lowgear_with_triples(N, |mut lowgear| {
            async move {
                lowgear.generate_inverse_tuples(N).await.unwrap();

                // Check the inverse triples
                let (a, a_inv): (Vec<ValueMac<TestCurve>>, Vec<ValueMac<TestCurve>>) =
                    lowgear.inverse_tuples.clone().into_iter().unzip();
                let a_inv_open =
                    lowgear.open_and_check_macs(&ValueMacBatch::new(a_inv)).await.unwrap();
                let a_open = lowgear.open_and_check_macs(&ValueMacBatch::new(a)).await.unwrap();

                for (a, a_inv) in izip!(a_open, a_inv_open) {
                    assert_eq!(a * a_inv, Scalar::one());
                }
            }
        })
        .await;
    }
}
