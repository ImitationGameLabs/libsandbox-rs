//! Benchmark I/O throughput in sandboxed processes.
//!
//! Measures how the executor handles varying stdin input sizes and stdout output volumes.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

mod common;

fn bench_output_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("output_sizes");

    let sandbox = common::exec_sandbox(Duration::from_secs(30));

    for size in [10, 100, 1000, 10000] {
        group.bench_with_input(BenchmarkId::new("lines", size), &size, |b, &size| {
            b.iter(|| {
                let cmd = format!("for i in $(seq 1 {}); do echo line; done", size);
                let result = sandbox.run("sh", &["-c", &cmd]).unwrap();
                black_box(result)
            })
        });
    }

    group.finish();
}

fn bench_stdin_input(c: &mut Criterion) {
    let mut group = c.benchmark_group("stdin_input");

    let sandbox = common::exec_sandbox(Duration::from_secs(30));

    for size in [100, 1000, 10000] {
        group.bench_with_input(BenchmarkId::new("bytes", size), &size, |b, &size| {
            let input: Vec<u8> = vec![b'x'; size];
            b.iter(|| {
                let result = sandbox
                    .run_cmd("cat", &[])
                    .stdin(Some(&input))
                    .run()
                    .unwrap();
                black_box(result)
            })
        });
    }

    group.finish();
}

criterion_group!(output_sizes, bench_output_sizes);
criterion_group!(stdin_input, bench_stdin_input);
criterion_main!(output_sizes, stdin_input);
