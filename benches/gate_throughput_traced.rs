//! A paired down version of the `gate_throughput` benchmarks that allows for tracing without
//! the overhead of criterion polluting stack samples

use std::time::Instant;

use clap::Parser;
use cpuprofiler::PROFILER;
use gperftools::HEAP_PROFILER;
use mpc_stark::{
    algebra::scalar::Scalar, beaver::PartyIDBeaverSource, network::NoRecvNetwork,
    test_helpers::TestCurve, MpcFabric, PARTY0,
};
use rand::thread_rng;

// -----------
// | Helpers |
// -----------

/// The number of gates to use in the benchmark
const NUM_GATES: usize = 10_000_000;

/// Create a mock fabric for testing
pub fn mock_fabric(size_hint: usize) -> MpcFabric<TestCurve> {
    let network = NoRecvNetwork::default();
    let beaver_source = PartyIDBeaverSource::new(PARTY0);
    MpcFabric::new_with_size_hint(size_hint, network, beaver_source)
}

pub fn start_cpu_profiler(profiled: bool) {
    if profiled {
        PROFILER.lock().unwrap().start("./cpu.profile").unwrap();
    }
}

pub fn stop_cpu_profiler(profiled: bool) {
    if profiled {
        PROFILER.lock().unwrap().stop().unwrap();
    }
}

pub fn start_heap_profiler(profiled: bool) {
    if profiled {
        HEAP_PROFILER
            .lock()
            .unwrap()
            .start("./heap.profile")
            .unwrap();
    }
}

pub fn stop_heap_profiler(profiled: bool) {
    if profiled {
        HEAP_PROFILER.lock().unwrap().stop().unwrap();
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
    cpu_profiled: bool,
    /// Whether to enable heap profiling
    #[clap(long, takes_value = false, value_parser)]
    heap_profiled: bool,
    /// The bench argument, needed for all benchmarks
    #[clap(long, takes_value = true, value_parser)]
    bench: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() {
    // Parse args
    let args = Args::parse();
    start_cpu_profiler(args.cpu_profiled);
    start_heap_profiler(args.heap_profiled);
    let start_time = Instant::now();

    // Setup benchmark
    let fabric = mock_fabric(NUM_GATES * 2);
    let allocation_time = start_time.elapsed();

    let mut rng = thread_rng();
    let base = Scalar::random(&mut rng);
    let base_res = fabric.allocate_scalar(base);

    let mut res = base_res;
    for _ in 0..NUM_GATES {
        res = &res + &res;
    }
    let circuit_creation_time = start_time.elapsed() - allocation_time;

    let _res = res.await;
    let res_time = start_time.elapsed() - allocation_time;

    println!("memory allocation took {allocation_time:?}");
    println!("circuit construction took {circuit_creation_time:?}");
    println!("circuit evaluation took {res_time:?}");

    fabric.shutdown();
    stop_cpu_profiler(args.cpu_profiled);
    stop_heap_profiler(args.heap_profiled);
}
