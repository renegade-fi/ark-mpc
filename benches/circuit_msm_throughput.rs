//! Benchmarks multiscalar multiplication throughput as executed via the
//! `Executor`

use std::time::{Duration, Instant};

use ark_mpc::{algebra::AuthenticatedPointResult, test_helpers::execute_mock_mpc};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use itertools::Itertools;
use tokio::runtime::Builder as RuntimeBuilder;

/// Measure the throughput and latency of a variable-sized MSM
pub fn bench_msm_throughput(c: &mut Criterion) {
    let runtime = RuntimeBuilder::new_multi_thread()
        .worker_threads(3)
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("msm-throughput");
    for circuit_size in [100, 1000, 10000].into_iter() {
        group.throughput(Throughput::Elements(circuit_size as u64));
        group.bench_function(BenchmarkId::from_parameter(circuit_size), |b| {
            let mut b = b.to_async(&runtime);
            b.iter_custom(|n_iters| async move {
                let mut total_time = Duration::from_millis(0);
                for _ in 0..n_iters {
                    let (elapsed1, elapsed2) = execute_mock_mpc(|fabric| async move {
                        let scalars = (0..circuit_size)
                            .map(|_| fabric.one_authenticated())
                            .collect_vec();
                        let points = (0..circuit_size)
                            .map(|_| fabric.curve_identity_authenticated())
                            .collect_vec();

                        let start_time = Instant::now();

                        let res = AuthenticatedPointResult::msm(&scalars, &points);
                        black_box(res.open().await);

                        start_time.elapsed()
                    })
                    .await;

                    // Add the maximum amount of time for either party to finish to the total
                    total_time += Duration::max(elapsed1, elapsed2);
                }

                total_time
            })
        });
    }
}

criterion_group!(
    name = msm_throughput;
    config = Criterion::default().sample_size(10);
    targets = bench_msm_throughput
);
criterion_main!(msm_throughput);
