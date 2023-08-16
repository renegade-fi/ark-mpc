//! Benchmarks for multiplication gate throughput

use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use mpc_stark::{test_helpers::execute_mock_mpc, PARTY0};
use tokio::runtime::Builder as RuntimeBuilder;

/// Measure the throughput and latency of a set of sequential multiplication gates
pub fn bench_mul_throughput(c: &mut Criterion) {
    let runtime = RuntimeBuilder::new_multi_thread()
        .worker_threads(3)
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("mul-throughput");
    for circuit_size in [100, 1000, 10000].into_iter() {
        group.throughput(Throughput::Elements(circuit_size as u64));
        group.bench_function(BenchmarkId::from_parameter(circuit_size), |b| {
            let mut b = b.to_async(&runtime);
            b.iter_custom(|n_iters| async move {
                let mut total_time = Duration::from_millis(0);
                for _ in 0..n_iters {
                    let (elapsed1, elapsed2) = execute_mock_mpc(|fabric| async move {
                        let mut res = fabric.share_scalar(1, PARTY0);

                        let start_time = Instant::now();
                        for _ in 0..circuit_size {
                            res = &res * &res;
                        }

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
    name = mul_throughput;
    config = Criterion::default().sample_size(10);
    targets = bench_mul_throughput
);
criterion_main!(mul_throughput);
