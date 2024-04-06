#![allow(clippy::unit_arg)]

use ark_mpc::{algebra::Scalar, test_helpers::TestCurve, GrowableBuffer};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::{seq::SliceRandom, thread_rng};
use std::hint::black_box;

// --------------
// | Benchmarks |
// --------------

/// Measures the throughput of the executor thread for scalar operations
#[allow(non_snake_case)]
pub fn buffer_read__sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_read__sequential");

    for buffer_size in [1_000, 10_000, 100_000, 1_000_000] {
        let buffer: GrowableBuffer<Scalar<TestCurve>> = GrowableBuffer::new(buffer_size);

        group.throughput(Throughput::Elements(buffer_size as u64));
        group.bench_function(BenchmarkId::from_parameter(buffer_size), |b| {
            b.iter(|| {
                for i in 0..buffer_size {
                    black_box(buffer.get(i));
                }
            })
        });
    }
}

/// Measures throughput of sequential write operations to the buffer
#[allow(non_snake_case)]
pub fn buffer_write__sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_write__sequential");

    for buffer_size in [1_000, 10_000, 100_000, 1_000_000, 10_000_000] {
        let mut buffer: GrowableBuffer<Scalar<TestCurve>> = GrowableBuffer::new(buffer_size);

        group.throughput(Throughput::Elements(buffer_size as u64));
        group.bench_function(BenchmarkId::from_parameter(buffer_size), |b| {
            b.iter(|| {
                for i in 0..buffer_size {
                    black_box(buffer.insert(i, Scalar::one()));
                }
            })
        });
    }
}

/// Measures throughput of random write operations to the buffer
#[allow(non_snake_case)]
pub fn buffer_write__random(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_write__random");

    for buffer_size in [1_000, 10_000, 100_000, 1_000_000, 10_000_000] {
        let mut buffer: GrowableBuffer<Scalar<TestCurve>> = GrowableBuffer::new(buffer_size);
        group.throughput(Throughput::Elements(buffer_size as u64));

        let mut rng = thread_rng();
        let mut indices: Vec<usize> = (0..buffer_size).collect();
        indices.shuffle(&mut rng);
        group.bench_function(BenchmarkId::from_parameter(buffer_size), |b| {
            b.iter(|| {
                for idx in indices.iter().copied() {
                    black_box(buffer.insert(idx, Scalar::one()));
                }
            })
        });
    }
}

criterion_group! {
    name = buffer_ops;
    config = Criterion::default();
    targets = buffer_read__sequential, buffer_write__sequential, buffer_write__random
}
criterion_main!(buffer_ops);
