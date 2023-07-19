//! A paired down version of the `gate_throughput` benchmarks that allows for tracing without
//! the overhead of criterion polluting stack samples

use cpuprofiler::PROFILER;
use mpc_stark::{
    algebra::scalar::Scalar, beaver::DummySharedScalarSource, network::NoRecvNetwork, MpcFabric,
};
use rand::thread_rng;

// -----------
// | Helpers |
// -----------

/// The number of gates to use in the benchmark
const NUM_GATES: usize = 1_000_000;

/// Create a mock fabric for testing
pub fn mock_fabric() -> MpcFabric {
    let network = NoRecvNetwork::default();
    let beaver_source = DummySharedScalarSource::new();
    MpcFabric::new(network, beaver_source)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() {
    let fabric = mock_fabric();
    let mut rng = thread_rng();
    let base = Scalar::random(&mut rng);
    let base_res = fabric.allocate_scalar(base);

    PROFILER
        .lock()
        .unwrap()
        .start("./benchmark.profile".to_string())
        .unwrap();

    let mut res = base_res;
    for _ in 0..NUM_GATES {
        res = &res + &res;
    }

    let _res = res.await;

    PROFILER.lock().unwrap().stop().unwrap();

    fabric.shutdown();
}
