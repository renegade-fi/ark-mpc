//! MPC circuits implemented directly in the library as gadgets for more complex
//! MPC operations

use std::iter;

use ark_ec::CurveGroup;
use itertools::Itertools;

use crate::{
    algebra::{AuthenticatedScalarResult, Scalar, ScalarResult, ScalarShare},
    MpcFabric, ResultValue,
};

/// Single bit xor, assumes that `a` and `b` are scalars representing bits
///
/// xor(a, b) = a + b - 2ab
pub fn bit_xor<C: CurveGroup>(
    a: &AuthenticatedScalarResult<C>,
    b: &AuthenticatedScalarResult<C>,
) -> AuthenticatedScalarResult<C> {
    let a_times_b = a * b;
    let fabric = a.fabric();
    let ids = vec![a.id(), b.id(), a_times_b.id()];

    fabric.new_gate_op(ids, move |mut args| {
        // Destructure the gate args
        let a_share: ScalarShare<C> = args.next().unwrap().into();
        let b_share: ScalarShare<C> = args.next().unwrap().into();
        let a_times_b_share: ScalarShare<C> = args.next().unwrap().into();

        // Compute the xor identity
        let two = Scalar::from(2u64);
        let new_share = a_share + b_share - two * a_times_b_share;

        ResultValue::ScalarShare(new_share)
    })
}

/// XOR a batch of bits
pub fn bit_xor_batch<C: CurveGroup>(
    a: &[AuthenticatedScalarResult<C>],
    b: &[AuthenticatedScalarResult<C>],
) -> Vec<AuthenticatedScalarResult<C>> {
    assert_eq!(a.len(), b.len(), "bit_xor takes bit representations of equal length");

    let a_plus_b = AuthenticatedScalarResult::batch_add(a, b);
    let a_times_b = AuthenticatedScalarResult::batch_mul(a, b);

    let twos = vec![Scalar::from(2u64); a.len()];
    let twos_times_a_times_b = AuthenticatedScalarResult::batch_mul_constant(&a_times_b, &twos);

    AuthenticatedScalarResult::batch_sub(&a_plus_b, &twos_times_a_times_b)
}

/// Single bit xor where one of the bits is public
///
/// xor(a, b) = a + b - 2ab
pub fn bit_xor_public<C: CurveGroup>(
    a: &ScalarResult<C>,
    b: &AuthenticatedScalarResult<C>,
) -> AuthenticatedScalarResult<C> {
    let fabric = a.fabric();
    let party_id = fabric.party_id();
    let mac_key = fabric.mac_key();

    let ids = vec![a.id(), b.id()];
    fabric.new_gate_op(ids, move |mut args| {
        // Public value
        let a: Scalar<C> = args.next().unwrap().into();
        let b_share: ScalarShare<C> = args.next().unwrap().into();

        // Compute the xor identity
        let two_a = Scalar::from(2u64) * a;
        let new_share = (b_share - two_a * b_share).add_public(a, mac_key, party_id);

        ResultValue::ScalarShare(new_share)
    })
}

/// XOR a batch of bits where one of the bit vectors is public
pub fn bit_xor_public_batch<C: CurveGroup>(
    a: &[ScalarResult<C>],
    b: &[AuthenticatedScalarResult<C>],
) -> Vec<AuthenticatedScalarResult<C>> {
    assert_eq!(a.len(), b.len(), "bit_xor takes bit representations of equal length");

    let a_plus_b = AuthenticatedScalarResult::batch_add_public(b, a);
    let a_times_b = AuthenticatedScalarResult::batch_mul_public(b, a);

    let twos = vec![Scalar::from(2u64); a.len()];
    let twos_times_a_times_b = AuthenticatedScalarResult::batch_mul_constant(&a_times_b, &twos);

    AuthenticatedScalarResult::batch_sub(&a_plus_b, &twos_times_a_times_b)
}

/// A prefix product gadget, computes the prefix products of a vector of values,
/// where for `n` values, the `i`th prefix product is defined as:
///     x0 * x1 * ... * xi
///
/// The method used here is that described in (Section 4.2):
///     https://dl.acm.org/doi/pdf/10.1145/72981.72995
/// I.e. we blind each value in the product with a telescoping product, open the
/// blinded values, construct prefix products, then unblind them as shared
/// values
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

    // Construct a vector of the prefix products of the blinded values, the left
    // hand multiple of each term cancels the right hand blinder of the previous
    // one in a telescoping fashion
    let mut prefix = blinded_open[0].clone();
    let mut prefixes = vec![prefix.clone()];
    for blinded_term in blinded_open[1..].iter() {
        prefix = prefix * blinded_term;
        prefixes.push(prefix.clone());
    }

    // Construct the right hand terms, this is the value b_inv[i] for the ith
    // prefix, which cancels the right hand blinder of the last term in the
    // prefix product
    let right_hand_terms = &b_inv_values[1..];

    // Cancel each prefix term's blinders with b[0] on the lhs and b_inv[i] on the
    // rhs
    let partial_unblind = AuthenticatedScalarResult::batch_mul_public(&b0_repeat, &prefixes);
    AuthenticatedScalarResult::batch_mul(&partial_unblind, right_hand_terms)
}

#[cfg(test)]
mod test {
    use futures::future;
    use itertools::Itertools;
    use rand::{thread_rng, Rng};

    use crate::{
        algebra::{AuthenticatedScalarResult, Scalar},
        gadgets::{bit_xor, bit_xor_batch, bit_xor_public, bit_xor_public_batch, prefix_product},
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

    /// Test the xor gadget
    #[tokio::test]
    async fn test_xor() {
        let (res, _) = execute_mock_mpc(|fabric| {
            async move {
                let zero = fabric.zero_authenticated();
                let one = fabric.one_authenticated();

                // 0 ^ 0 = 0
                let res = bit_xor(&zero, &zero).open_authenticated().await.unwrap();
                let mut success = res == Scalar::zero();

                // 0 ^ 1 = 1
                let res = bit_xor(&zero, &one).open_authenticated().await.unwrap();
                success = success && res == Scalar::one();

                // 1 ^ 0 = 1
                let res = bit_xor(&one, &zero).open_authenticated().await.unwrap();
                success = success && res == Scalar::one();

                // 1 ^ 1 = 0
                let res = bit_xor(&one, &one).open_authenticated().await.unwrap();
                success && res == Scalar::zero()
            }
        })
        .await;

        assert!(res)
    }

    /// Test the batch xor gadget
    #[tokio::test]
    async fn test_xor_batch() {
        const N: usize = 10;
        let mut rng = thread_rng();
        let a = (0..N).map(|_| Scalar::from(rng.gen_bool(0.5))).collect_vec();
        let b = (0..N).map(|_| Scalar::from(rng.gen_bool(0.5))).collect_vec();

        let expected_res =
            a.iter().zip(b.iter()).map(|(a, b)| a + b - Scalar::from(2u64) * a * b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a = fabric.batch_share_scalar(a, PARTY0 /* sender */);
                let b = fabric.batch_share_scalar(b, PARTY0 /* sender */);
                let res = bit_xor_batch(&a, &b);
                let res_open = AuthenticatedScalarResult::open_authenticated_batch(&res);

                future::join_all(res_open).await.into_iter().collect::<Result<Vec<_>, _>>()
            }
        })
        .await;

        assert_eq!(res.unwrap(), expected_res)
    }

    /// Test the xor public gadget
    #[tokio::test]
    async fn test_xor_public() {
        let (res, _) = execute_mock_mpc(|fabric| {
            async move {
                let zero = fabric.zero();
                let one = fabric.one();
                let zero_auth = fabric.zero_authenticated();
                let one_auth = fabric.one_authenticated();

                // 0 ^ 0 = 0
                let res = bit_xor_public(&zero, &zero_auth).open_authenticated().await.unwrap();
                let mut success = res == Scalar::zero();

                // 0 ^ 1 = 1
                let res = bit_xor_public(&zero, &one_auth).open_authenticated().await.unwrap();
                success = success && res == Scalar::one();

                // 1 ^ 0 = 1
                let res = bit_xor_public(&one, &zero_auth).open_authenticated().await.unwrap();
                success = success && res == Scalar::one();

                // 1 ^ 1 = 0
                let res = bit_xor_public(&one, &one_auth).open_authenticated().await.unwrap();
                success && res == Scalar::zero()
            }
        })
        .await;

        assert!(res)
    }

    /// Test the batch xor public gadget
    #[tokio::test]
    async fn test_xor_public_batch() {
        const N: usize = 10;
        let mut rng = thread_rng();
        let a = (0..N).map(|_| Scalar::from(rng.gen_bool(0.5))).collect_vec();
        let b = (0..N).map(|_| Scalar::from(rng.gen_bool(0.5))).collect_vec();

        let expected_res =
            a.iter().zip(b.iter()).map(|(a, b)| a + b - Scalar::from(2u64) * a * b).collect_vec();

        let (res, _) = execute_mock_mpc(|fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a = fabric.allocate_scalars(a);
                let b = fabric.batch_share_scalar(b, PARTY0 /* sender */);
                let res = bit_xor_public_batch(&a, &b);
                let res_open = AuthenticatedScalarResult::open_authenticated_batch(&res);

                future::join_all(res_open).await.into_iter().collect::<Result<Vec<_>, _>>()
            }
        })
        .await;

        assert_eq!(res.unwrap(), expected_res)
    }
}
