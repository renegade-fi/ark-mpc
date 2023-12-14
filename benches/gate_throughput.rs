use std::{path::Path, sync::Mutex};

use ark_mpc::{
    algebra::Scalar, beaver::PartyIDBeaverSource, network::NoRecvNetwork, test_helpers::TestCurve,
    ExecutorSizeHints, MpcFabric, PARTY0,
};
use cpuprofiler::{Profiler as CpuProfiler, PROFILER};
use criterion::{
    criterion_group, criterion_main, profiler::Profiler as CriterionProfiler, BenchmarkId,
    Criterion, Throughput,
};
use rand::{rngs::OsRng, thread_rng};
use tokio::runtime::Builder as RuntimeBuilder;

// -----------
// | Helpers |
// -----------

struct Profiler(&'static Mutex<CpuProfiler>);
impl Profiler {
    fn new() -> Self {
        Self(&PROFILER)
    }
}

impl CriterionProfiler for Profiler {
    fn start_profiling(&mut self, _benchmark_id: &str, _benchmark_dir: &Path) {
        let mut prof = self.0.lock().unwrap();
        prof.start("./benchmark.profile".to_string()).unwrap();
    }

    fn stop_profiling(&mut self, _benchmark_id: &str, _benchmark_dir: &Path) {
        let mut prof = self.0.lock().unwrap();
        prof.stop().unwrap();
    }
}

pub fn config() -> Criterion {
    Criterion::default().sample_size(100).with_profiler(Profiler::new())
}

/// Create a mock fabric for testing
pub fn mock_fabric(size_hint: usize) -> MpcFabric<TestCurve> {
    let network = NoRecvNetwork::default();
    let beaver_source = PartyIDBeaverSource::new(PARTY0);
    let size = ExecutorSizeHints { num_ops: size_hint, num_results: size_hint * 10 };

    MpcFabric::new_with_size_hint(size, network, beaver_source)
}

// --------------
// | Benchmarks |
// --------------

/// Measures the raw throughput of scalar addition
pub fn scalar_addition(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut res = Scalar::<TestCurve>::random(&mut rng);

    let mut group = c.benchmark_group("raw_scalar_addition");

    for circuit_size in [100u64, 1000].iter() {
        group.throughput(Throughput::Elements(*circuit_size));
        group.bench_function(BenchmarkId::from_parameter(circuit_size), |b| {
            b.iter(|| {
                for _ in 0..*circuit_size {
                    res = res + res;
                }
            })
        });
    }
}

/// Measures the throughput of the executor thread for scalar operations
pub fn circuit_scalar_addition(c: &mut Criterion) {
    let runtime =
        RuntimeBuilder::new_multi_thread().worker_threads(3).enable_all().build().unwrap();

    let mut group = c.benchmark_group("circuit_scalar_addition");
    for circuit_size in [100, 1000].into_iter() {
        group.throughput(Throughput::Elements(circuit_size as u64));
        group.bench_function(BenchmarkId::from_parameter(circuit_size), |b| {
            let mut b = b.to_async(&runtime);
            b.iter_batched(
                || {
                    let mut rng = OsRng {};
                    let mock_fabric = mock_fabric(circuit_size * 2);
                    let mock_scalar = mock_fabric.allocate_scalar(Scalar::random(&mut rng));

                    (mock_fabric, mock_scalar)
                },
                |(mock_fabric, mock_scalar)| async move {
                    let mut res = mock_scalar;
                    for _ in 0..circuit_size {
                        res = &res + &res;
                    }

                    res.await;
                    mock_fabric.shutdown();
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = scalar_ops;
    config = config();
    targets = scalar_addition, circuit_scalar_addition
}
criterion_main!(scalar_ops);
