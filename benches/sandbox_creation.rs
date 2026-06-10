//! Benchmark sandbox creation overhead.
//!
//! Measures builder configuration cost at three tiers:
//! minimal (filesystem only), with_limits (adds resources), with_mounts (adds bind mount).
//!
//! Note: does not use `bench_common.rs` — the builder construction IS what we measure here.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use libsandbox::config::{FilesystemConfig, ResourceConfig};
use libsandbox::{Permission, Sandbox, MB};
use std::time::Duration;

fn bench_sandbox_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("sandbox_creation");

    group.bench_function("minimal", |b| {
        b.iter(|| {
            let sandbox = Sandbox::builder()
                .filesystem(
                    FilesystemConfig::builder()
                        .working_dir("/tmp")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap();
            black_box(sandbox)
        })
    });

    group.bench_function("with_limits", |b| {
        b.iter(|| {
            let sandbox = Sandbox::builder()
                .filesystem(
                    FilesystemConfig::builder()
                        .working_dir("/tmp")
                        .build()
                        .unwrap(),
                )
                .resources(
                    ResourceConfig::builder()
                        .memory_limit(256 * MB)
                        .wall_time_limit(Duration::from_secs(30))
                        .max_pids(100)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap();
            black_box(sandbox)
        })
    });

    group.bench_function("with_mounts", |b| {
        b.iter(|| {
            let sandbox = Sandbox::builder()
                .filesystem(
                    FilesystemConfig::builder()
                        .working_dir("/tmp")
                        .mount("/tmp", "/data", Permission::ReadOnly)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap();
            black_box(sandbox)
        })
    });

    group.finish();
}

criterion_group!(benches, bench_sandbox_creation);
criterion_main!(benches);
