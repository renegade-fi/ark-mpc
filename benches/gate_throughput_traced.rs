//! A paired down version of the `gate_throughput` benchmarks that allows for tracing without
//! the overhead of criterion polluting stack samples

use clap::Parser;
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

pub fn start_profiler(profiled: bool) {
    if profiled {
        PROFILER.lock().unwrap().start("./bench.profile").unwrap();
    }
}

pub fn stop_profiler(profiled: bool) {
    if profiled {
        PROFILER.lock().unwrap().stop().unwrap();
    }
}

// --------------------
// | CLI + Benchmarks |
// --------------------

/// The command line interface for the test harness
#[derive(Clone, Parser, Debug)]
struct Args {
    /// Whether to enable on-cpu stack sampled profiling
    #[clap(long, takes_value = false, value_parser)]
    profiled: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() {
    // Parse args
    let args = Args::parse();
    start_profiler(args.profiled);

    // Setup benchmark
    let fabric = mock_fabric();
    let mut rng = thread_rng();
    let base = Scalar::random(&mut rng);
    let base_res = fabric.allocate_scalar(base);

    let mut res = base_res;
    for _ in 0..NUM_GATES {
        res = &res + &res;
    }

    let _res = res.await;

    fabric.shutdown();
    stop_profiler(args.profiled);
}
