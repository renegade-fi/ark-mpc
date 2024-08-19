use std::time::{Duration, Instant};

use ark_mpc::{algebra::Scalar, test_helpers::TestCurve};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use rand::thread_rng;

/// Benchmark the serialization of scalars
fn bench_scalar_serialization(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut group = c.benchmark_group("scalar_serialization");
    group.throughput(Throughput::Elements(1));

    group.bench_function("serialize", |b| {
        b.iter_custom(|n_iters| {
            let mut total_time = Duration::from_secs(0);
            for _ in 0..n_iters {
                let scalar = Scalar::<TestCurve>::random(&mut rng);

                let start = Instant::now();
                let bytes = serde_json::to_vec(&scalar).unwrap();
                total_time += start.elapsed();

                black_box(bytes);
            }
            total_time
        })
    });
}

/// Benchmark the deserialization of scalars
fn bench_scalar_deserialization(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut group = c.benchmark_group("scalar_serialization");
    group.throughput(Throughput::Elements(1));

    group.bench_function("deserialize", |b| {
        b.iter_custom(|n_iters| {
            let mut total_time = Duration::from_secs(0);
            for _ in 0..n_iters {
                let scalar = Scalar::<TestCurve>::random(&mut rng);
                let serialized = serde_json::to_vec(&scalar).unwrap();

                // Time deserialization only
                let start = Instant::now();
                let deserialized: Scalar<TestCurve> = serde_json::from_slice(&serialized).unwrap();
                total_time += start.elapsed();

                black_box(deserialized);
            }

            total_time
        })
    });
}

criterion_group! {
    name = scalar_serialization;
    config = Criterion::default();
    targets = bench_scalar_serialization, bench_scalar_deserialization
}
criterion_main!(scalar_serialization);
