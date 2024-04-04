use std::time::{Duration, Instant};

use ark_mpc::algebra::Scalar;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mp_spdz_rs::benchmark_helpers::random_plaintext;
use mp_spdz_rs::fhe::{params::BGVParams, plaintext::Plaintext};
use mp_spdz_rs::TestCurve;
use rand::thread_rng;

/// Benchmark plaintext addition
fn benchmark_plaintext_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("plaintext-ops");

    let params = BGVParams::<TestCurve>::new_no_mults();
    let slots = params.plaintext_slots();

    group.throughput(criterion::Throughput::Elements(slots as u64));
    group.bench_function(BenchmarkId::new("add", ""), |b| {
        b.iter_custom(|n_iters| {
            let mut total_time = Duration::default();
            let mut rng = thread_rng();

            for _ in 0..n_iters {
                let mut plaintext1 = random_plaintext(&params);
                let mut plaintext2 = random_plaintext(&params);

                let start = Instant::now();
                let _ = black_box(&plaintext1 + &plaintext2);
                total_time += start.elapsed();
            }

            total_time
        })
    });
}

/// Benchmark plaintext multiplication
fn benchmark_plaintext_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("plaintext-ops");

    let params = BGVParams::<TestCurve>::new_no_mults();
    let slots = params.plaintext_slots();

    group.throughput(criterion::Throughput::Elements(slots as u64));
    group.bench_function(BenchmarkId::new("mul", ""), |b| {
        b.iter_custom(|n_iters| {
            let mut total_time = Duration::default();
            let mut rng = thread_rng();

            for _ in 0..n_iters {
                let plaintext1 = random_plaintext(&params);
                let plaintext2 = random_plaintext(&params);

                let start = Instant::now();
                let _ = black_box(&plaintext1 * &plaintext2);
                total_time += start.elapsed();
            }

            total_time
        })
    });
}

criterion_group! {
    name = plaintext_ops;
    config = Criterion::default();
    targets = benchmark_plaintext_addition, benchmark_plaintext_multiplication
}
criterion_main!(plaintext_ops);
