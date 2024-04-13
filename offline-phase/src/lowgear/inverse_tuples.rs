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
    use ark_mpc::{algebra::Scalar, test_helpers::TestCurve, PARTY0};
    use itertools::{izip, Itertools};
    use rand::thread_rng;

    use crate::{
        beaver_source::{ValueMac, ValueMacBatch},
        test_helpers::{
            encrypt_all, generate_authenticated_secret_shares, generate_triples,
            mock_lowgear_with_keys,
        },
    };

    /// Tests generating inverse tuples
    #[tokio::test]
    async fn test_generate_inverse_tuples() {
        let mut rng = thread_rng();
        const N: usize = 100; // The number of tuples to generate

        // Generate a mac key and shares
        let mac_key = Scalar::random(&mut rng);
        let mac_key1 = Scalar::random(&mut rng);
        let mac_key2 = mac_key - mac_key1;

        // Setup a set of mock triples
        let (a, b, c) = generate_triples(N);
        let (a1, a2) = generate_authenticated_secret_shares(&a, mac_key);
        let (b1, b2) = generate_authenticated_secret_shares(&b, mac_key);
        let (c1, c2) = generate_authenticated_secret_shares(&c, mac_key);

        mock_lowgear_with_keys(|mut lowgear| {
            // Setup the mac keys
            let is_party0 = lowgear.party_id() == PARTY0;
            let other_pk = lowgear.other_pk.as_ref().unwrap();

            let my_mac_key = if is_party0 { mac_key1 } else { mac_key2 };
            let their_mac_key = if is_party0 { mac_key2 } else { mac_key1 };
            lowgear.mac_share = my_mac_key;
            lowgear.other_mac_enc = Some(encrypt_all(their_mac_key, other_pk, &lowgear.params));

            // Setup the triplets
            let (my_a, my_b, my_c) = if is_party0 { (&a1, &b1, &c1) } else { (&a2, &b2, &c2) };
            lowgear.triples =
                izip!(my_a.clone().into_iter(), my_b.clone().into_iter(), my_c.clone().into_iter())
                    .collect_vec();

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
