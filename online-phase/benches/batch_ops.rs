//! Benchmarks for batch operations in a circuit

use std::time::{Duration, Instant};

use ark_mpc::{
    algebra::{AuthenticatedScalarResult, Scalar as GenericScalar},
    test_helpers::{execute_mock_mpc, TestCurve},
    PARTY0,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use futures::future;
use itertools::Itertools;
use rand::thread_rng;
use tokio::runtime::Builder as RuntimeBuilder;

/// A scalar with curve generics defined
type Scalar = GenericScalar<TestCurve>;

/// Execute a batch multiplication and return the time taken
async fn perform_batch_mul(a: Vec<Scalar>, b: Vec<Scalar>) -> Duration {
    let (duration1, duration2) = execute_mock_mpc(|fabric| {
        let a = a.clone();
        let b = b.clone();
        async move {
            let start = Instant::now();
            let a = fabric.batch_share_scalar(a, PARTY0);
            let b = fabric.batch_share_scalar(b, PARTY0);

            let res = AuthenticatedScalarResult::batch_mul(&a, &b);
            let res_open = AuthenticatedScalarResult::open_authenticated_batch(&res);

            let _ = black_box(future::join_all(res_open).await);

            start.elapsed()
        }
    })
    .await;

    Duration::max(duration1, duration2)
}

/// Benchmark batch multiplication on a range of batches
fn bench_batch_mul(c: &mut Criterion) {
    let runtime =
        RuntimeBuilder::new_multi_thread().worker_threads(3).enable_all().build().unwrap();

    let mut group = c.benchmark_group("batch-ops");

    for batch_size in [10, 100, 1000].into_iter() {
        let id = BenchmarkId::new("batch-mul", batch_size);
        group.throughput(Throughput::Elements(batch_size));
        group.bench_function(id, |b| {
            let mut async_bencher = b.to_async(&runtime);
            async_bencher.iter_custom(|n_iters| async move {
                let mut total_time = Duration::default();
                for _ in 0..n_iters {
                    let mut rng = thread_rng();
                    let a = (0..batch_size).map(|_| Scalar::random(&mut rng)).collect_vec();
                    let b = (0..batch_size).map(|_| Scalar::random(&mut rng)).collect_vec();

                    total_time += perform_batch_mul(a, b).await;
                }

                total_time
            });
        });
    }
}

criterion_group!(
    name = batch_ops;
    config = Criterion::default().sample_size(10);
    targets = bench_batch_mul
);
criterion_main!(batch_ops);
