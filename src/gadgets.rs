//! MPC circuits implemented directly in the library as gadgets for more complex MPC operations

use std::iter;

use ark_ec::CurveGroup;
use itertools::Itertools;

use crate::{algebra::AuthenticatedScalarResult, MpcFabric};

/// A prefix product gadget, computes the prefix products of a vector of values, where
/// for `n` values, the `i`th prefix product is defined as:
///     x0 * x1 * ... * xi
///
/// The method used here is that described in (Section 4.2):
///     https://dl.acm.org/doi/pdf/10.1145/72981.72995
/// I.e. we blind each value in the product with a telescoping product, open the blinded values,
/// construct prefix products, then unblind them as shared values
pub fn prefix_product<C: CurveGroup>(
    values: &[AuthenticatedScalarResult<C>],
    fabric: &MpcFabric<C>,
) -> Vec<AuthenticatedScalarResult<C>> {
    let n = values.len();
    let (b_values, b_inv_values) = fabric.random_inverse_pairs(n + 1);

    // Blind each value in a telescoping manner, i.e. left multiply by b_inv[i-1]
    // and right multiply by b[i]
    let partial_blind = AuthenticatedScalarResult::batch_mul(&b_inv_values[..n], values);
    let blinded = AuthenticatedScalarResult::batch_mul(&partial_blind, &b_values[1..]);

    // Open the blinded values
    let blinded_open = AuthenticatedScalarResult::open_authenticated_batch(&blinded)
        .into_iter()
        .map(|v| v.value)
        .collect_vec();

    // Construct the prefix products
    // Each prefix is b[0] * blinded_open[0] * ... * blinded_open[i] * b_inv[i]

    // Each prefix is multiplied by b[0] on the left
    let b0_repeat = iter::repeat(b_values[0].clone()).take(n).collect_vec();

    // Construct a vector of the prefix products of the blinded values, the left hand multiple of
    // each term cancels the right hand blinder of the previous one in a telescoping fashion
    let mut prefix = blinded_open[0].clone();
    let mut prefixes = vec![prefix.clone()];
    for blinded_term in blinded_open[1..].iter() {
        prefix = prefix * blinded_term;
        prefixes.push(prefix.clone());
    }

    // Construct the right hand terms, this is the value b_inv[i] for the ith prefix, which cancels
    // the right hand blinder of the last term in the prefix product
    let right_hand_terms = &b_inv_values[1..];

    // Cancel each prefix term's blinders with b[0] on the lhs and b_inv[i] on the rhs
    let partial_unblind = AuthenticatedScalarResult::batch_mul_public(&b0_repeat, &prefixes);
    AuthenticatedScalarResult::batch_mul(&partial_unblind, right_hand_terms)
}

#[cfg(test)]
mod test {
    use futures::future;
    use itertools::Itertools;
    use rand::thread_rng;

    use crate::{
        algebra::{AuthenticatedScalarResult, Scalar},
        gadgets::prefix_product,
        test_helpers::execute_mock_mpc,
        PARTY0,
    };

    /// Test the prefix product implementation
    #[tokio::test]
    async fn test_prefix_prod() {
        const N: usize = 10;
        let mut rng = thread_rng();
        let values = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        let mut expected_res = vec![values[0]];
        let mut product = values[0];
        for val in values[1..].iter() {
            product *= *val;
            expected_res.push(product);
        }

        let (res, _) = execute_mock_mpc(|fabric| {
            let values = values.clone();
            async move {
                let allocated_values = fabric.batch_share_scalar(values, PARTY0 /* sender */);
                let res = prefix_product(&allocated_values, &fabric);
                let res_open = AuthenticatedScalarResult::open_authenticated_batch(&res);

                future::join_all(res_open).await
            }
        })
        .await;

        let res = res.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(res, expected_res)
    }
}
