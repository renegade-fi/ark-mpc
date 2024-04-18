//! Benchmarks for arithmetic on plaintext vectors

use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mp_spdz_rs::benchmark_helpers::random_plaintext_vec;
use mp_spdz_rs::fhe::params::BGVParams;
use mp_spdz_rs::TestCurve;

/// Benchmark plaintext vector addition
fn benchmark_plaintext_vec_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("plaintext-vector-ops");

    let params = BGVParams::<TestCurve>::new_no_mults();
    let slots = params.plaintext_slots();

    for vec_length in [10usize, 100, 1000] {
        group.throughput(criterion::Throughput::Elements((slots * vec_length) as u64));
        group.bench_function(BenchmarkId::new("add", vec_length), |b| {
            b.iter_custom(|n_iters| {
                let mut total_time = Duration::default();

                for _ in 0..n_iters {
                    let plaintext1 = random_plaintext_vec(vec_length, &params);
                    let plaintext2 = random_plaintext_vec(vec_length, &params);

                    let start = Instant::now();
                    let _ = black_box(&plaintext1 + &plaintext2);
                    total_time += start.elapsed();
                }

                total_time
            })
        });
    }
}

/// Benchmark plaintext vector multiplication
fn benchmark_plaintext_vec_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("plaintext-vector-ops");

    let params = BGVParams::<TestCurve>::new_no_mults();
    let slots = params.plaintext_slots();

    for vec_length in [10usize, 100, 1000] {
        group.throughput(criterion::Throughput::Elements((slots * vec_length) as u64));
        group.bench_function(BenchmarkId::new("mul", vec_length), |b| {
            b.iter_custom(|n_iters| {
                let mut total_time = Duration::default();

                for _ in 0..n_iters {
                    let plaintext1 = random_plaintext_vec(vec_length, &params);
                    let plaintext2 = random_plaintext_vec(vec_length, &params);

                    let start = Instant::now();
                    let _ = black_box(&plaintext1 * &plaintext2);
                    total_time += start.elapsed();
                }

                total_time
            })
        });
    }
}

criterion_group! {
    name = plaintext_vec_ops;
    config = Criterion::default().sample_size(10);
    targets = benchmark_plaintext_vec_addition, benchmark_plaintext_vec_multiplication
}
criterion_main!(plaintext_vec_ops);
