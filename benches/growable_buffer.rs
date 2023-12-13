use ark_mpc::{algebra::Scalar, test_helpers::TestCurve, GrowableBuffer};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

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

criterion_group! {
    name = buffer_ops;
    config = Criterion::default();
    targets = buffer_read__sequential,
}
criterion_main!(buffer_ops);
