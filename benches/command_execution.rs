//! Benchmark command execution overhead.
//!
//! Measures the full sandbox lifecycle: clone → cgroup → seccomp → execute → teardown.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;

mod common;

fn bench_command_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("command_execution");

    let sandbox = common::exec_sandbox(Duration::from_secs(10));

    group.bench_function("echo", |b| {
        b.iter(|| {
            let result = sandbox.run("echo", &["hello"]).unwrap();
            black_box(result)
        })
    });

    group.bench_function("true", |b| {
        b.iter(|| {
            let result = sandbox.run("true", &[]).unwrap();
            black_box(result)
        })
    });

    group.bench_function("shell_command", |b| {
        b.iter(|| {
            let result = sandbox.run("sh", &["-c", "echo test"]).unwrap();
            black_box(result)
        })
    });

    group.finish();
}

criterion_group!(benches, bench_command_execution);
criterion_main!(benches);
