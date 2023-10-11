//! Defines a benchmark for native multiscalar-multiplication on `Scalar` and `CurvePoint` types

use ark_mpc::{
    algebra::{CurvePoint, Scalar},
    random_point,
    test_helpers::TestCurve,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use itertools::Itertools;
use rand::thread_rng;

/// The maximum power of two to scale the MSM benchmark to
const MAX_POWER_OF_TWO: usize = 16; // 2^16 = 65536

/// Measures the raw throughput of a native MSM
pub fn bench_native_msm(c: &mut Criterion) {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("native_msm");
    for n_elems in (0..MAX_POWER_OF_TWO).map(|i| 1 << i) {
        group.throughput(Throughput::Elements(n_elems));
        group.bench_function(BenchmarkId::from_parameter(n_elems), |b| {
            let scalars = (0..n_elems).map(|_| Scalar::random(&mut rng)).collect_vec();
            let points = (0..n_elems).map(|_| random_point()).collect_vec();
            b.iter(|| {
                black_box(CurvePoint::<TestCurve>::msm(&scalars, &points));
            })
        });
    }
}

criterion_group!(
    name = native_msm;
    config = Criterion::default().sample_size(10);
    targets = bench_native_msm
);
criterion_main!(native_msm);
