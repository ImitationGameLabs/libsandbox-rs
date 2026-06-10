//! Benchmark parallel sandbox execution.
//!
//! Measures concurrency overhead: namespace creation, cgroup controller contention,
//! and thread-scaling behavior. Uses reduced sample size (10) to keep runtime manageable.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

mod common;

fn bench_parallel_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_execution");
    group.sample_size(10);

    for num_sandboxes in [2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("sandboxes", num_sandboxes),
            &num_sandboxes,
            |b, &count| {
                b.iter(|| {
                    let handles: Vec<_> = (0..count)
                        .map(|_| {
                            std::thread::spawn(|| {
                                let sandbox = common::exec_sandbox(Duration::from_secs(10));
                                sandbox.run("echo", &["test"]).unwrap()
                            })
                        })
                        .collect();

                    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
                    black_box(results)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_parallel_execution);
criterion_main!(benches);
