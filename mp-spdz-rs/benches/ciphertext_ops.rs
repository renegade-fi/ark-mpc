//! Benchmarks for ciphertext operations

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use mp_spdz_rs::benchmark_helpers::random_plaintext;
use mp_spdz_rs::fhe::{keys::BGVKeypair, params::BGVParams};
use mp_spdz_rs::TestCurve;

/// Benchmark the time to encrypt and decrypt a plaintext
fn bench_ciphertext_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("ciphertext-ops");
    let params = BGVParams::<TestCurve>::new_no_mults();
    let slots = params.plaintext_slots();
    let mut keypair = BGVKeypair::gen(&params);

    group.throughput(Throughput::Elements(slots as u64));
    group.bench_function(BenchmarkId::new("encrypt-decrypt", ""), |b| {
        b.iter_custom(|n_iters| {
            let mut total_time = std::time::Duration::default();

            for _ in 0..n_iters {
                let plaintext = random_plaintext(&params);

                let start = std::time::Instant::now();
                let ciphertext = keypair.encrypt(&plaintext);
                let _ = keypair.decrypt(&ciphertext);
                total_time += start.elapsed();
            }

            total_time
        })
    });
}

/// Benchmark addition between a ciphertext and a plaintext
///
/// This includes only the time to add the two values together
fn bench_ciphertext_plaintext_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("ciphertext-ops");
    let params = BGVParams::<TestCurve>::new_no_mults();
    let slots = params.plaintext_slots();
    let keypair = BGVKeypair::gen(&params);

    group.throughput(Throughput::Elements(slots as u64));
    group.bench_function(BenchmarkId::new("plaintext-add", ""), |b| {
        b.iter_custom(|n_iters| {
            let mut total_time = std::time::Duration::default();

            for _ in 0..n_iters {
                let plaintext = random_plaintext(&params);
                let ciphertext = keypair.encrypt(&random_plaintext(&params));

                let start = std::time::Instant::now();
                let _ = &ciphertext + &plaintext;
                total_time += start.elapsed();
            }

            total_time
        })
    });
}

/// Benchmark multiplying a ciphertext by a plaintext
fn bench_ciphertext_plaintext_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("ciphertext-ops");
    let params = BGVParams::<TestCurve>::new_no_mults();
    let slots = params.plaintext_slots();
    let keypair = BGVKeypair::gen(&params);

    group.throughput(Throughput::Elements(slots as u64));
    group.bench_function(BenchmarkId::new("plaintext-mul", ""), |b| {
        b.iter_custom(|n_iters| {
            let mut total_time = std::time::Duration::default();

            for _ in 0..n_iters {
                let plaintext = random_plaintext(&params);
                let ciphertext = keypair.encrypt(&random_plaintext(&params));

                let start = std::time::Instant::now();
                let _ = &ciphertext * &plaintext;
                total_time += start.elapsed();
            }

            total_time
        })
    });
}

/// Benchmark adding a ciphertext to another ciphertext
fn bench_ciphertext_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("ciphertext-ops");
    let params = BGVParams::<TestCurve>::new_no_mults();
    let slots = params.plaintext_slots();
    let keypair = BGVKeypair::gen(&params);

    group.throughput(Throughput::Elements(slots as u64));
    group.bench_function(BenchmarkId::new("ciphertext-add", ""), |b| {
        b.iter_custom(|n_iters| {
            let mut total_time = std::time::Duration::default();

            for _ in 0..n_iters {
                let ciphertext1 = keypair.encrypt(&random_plaintext(&params));
                let ciphertext2 = keypair.encrypt(&random_plaintext(&params));

                let start = std::time::Instant::now();
                let _ = &ciphertext1 + &ciphertext2;
                total_time += start.elapsed();
            }

            total_time
        })
    });
}

/// Benchmark multiplying a ciphertext by another ciphertext
fn bench_ciphertext_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("ciphertext-ops");
    let params = BGVParams::<TestCurve>::new(1 /* n_mults */);
    let slots = params.plaintext_slots();
    let keypair = BGVKeypair::gen(&params);

    group.throughput(Throughput::Elements(slots as u64));
    group.bench_function(BenchmarkId::new("ciphertext-mul", ""), |b| {
        b.iter_custom(|n_iters| {
            let mut total_time = std::time::Duration::default();

            for _ in 0..n_iters {
                let ciphertext1 = keypair.encrypt(&random_plaintext(&params));
                let ciphertext2 = keypair.encrypt(&random_plaintext(&params));

                let start = std::time::Instant::now();
                let _ = &ciphertext1.mul_ciphertext(&ciphertext2, &keypair.public_key);
                total_time += start.elapsed();
            }

            total_time
        })
    });
}

criterion_group! {
    name = ciphertext_ops;
    config = Criterion::default().sample_size(10);
    targets = bench_ciphertext_encrypt_decrypt,
        bench_ciphertext_plaintext_addition,
        bench_ciphertext_plaintext_multiplication,
        bench_ciphertext_addition,
        bench_ciphertext_multiplication,
}
criterion_main!(ciphertext_ops);
