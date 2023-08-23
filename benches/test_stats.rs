//! A simple benchmark for testing that stats collection is properly working

use mpc_stark::{algebra::scalar::Scalar, test_helpers::execute_mock_mpc, PARTY0, PARTY1};
use rand::{distributions::uniform::SampleRange, thread_rng};

#[tokio::main]
async fn main() {
    // Run the following circuit with the `stats` feature enabled and
    // the stats will be dumped at the end of execution
    let mut rng = thread_rng();
    let depth = (0usize..=1000).sample_single(&mut rng);

    let value1 = Scalar::random(&mut rng);
    let value2 = Scalar::random(&mut rng);

    println!("Sampled depth: {depth}");
    execute_mock_mpc(|fabric| async move {
        let party0_value = fabric.share_scalar(value1, PARTY0);
        let party1_value = fabric.share_scalar(value2, PARTY1);

        let mut res = fabric.zero_authenticated();
        for _ in 0..depth {
            res = &party0_value + &res * &party1_value;
        }

        res.open().await
    })
    .await;
}
