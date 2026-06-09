//! Performance benchmarks for libsandbox
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use libsandbox::config::{FilesystemConfig, ResourceConfig, SecurityConfig};
use libsandbox::SeccompProfile;
use libsandbox::{Permission, Sandbox, MB};
use std::time::Duration;

/// Benchmark sandbox creation overhead
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

/// Benchmark command execution overhead
fn bench_command_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("command_execution");

    // Pre-create sandbox for execution benchmarks
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_secs(10))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

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

/// Benchmark with varying output sizes
fn bench_output_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("output_sizes");

    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_secs(30))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

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

/// Benchmark with stdin input
fn bench_stdin_input(c: &mut Criterion) {
    let mut group = c.benchmark_group("stdin_input");

    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_secs(30))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    for size in [100, 1000, 10000] {
        group.bench_with_input(BenchmarkId::new("bytes", size), &size, |b, &size| {
            let input: Vec<u8> = vec![b'x'; size];
            b.iter(|| {
                let result = sandbox.run_with_input("cat", &[], Some(&input)).unwrap();
                black_box(result)
            })
        });
    }

    group.finish();
}

/// Benchmark sandbox with different security profiles
#[cfg(target_os = "linux")]
fn bench_seccomp_profiles(c: &mut Criterion) {
    let mut group = c.benchmark_group("seccomp_profiles");

    for (name, profile) in [
        ("disabled", SeccompProfile::Disabled),
        ("permissive", SeccompProfile::Permissive),
        ("standard", SeccompProfile::Standard),
        ("strict", SeccompProfile::Strict),
    ] {
        group.bench_function(name, |b| {
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
                            .wall_time_limit(Duration::from_secs(10))
                            .build()
                            .unwrap(),
                    )
                    .security(
                        SecurityConfig::builder()
                            .seccomp_profile(profile.clone())
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap();
                let result = sandbox.run("echo", &["test"]).unwrap();
                black_box(result)
            })
        });
    }

    group.finish();
}

/// Benchmark parallel sandbox execution
fn bench_parallel_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_execution");
    group.sample_size(10); // Fewer samples for parallel tests

    for num_sandboxes in [2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("sandboxes", num_sandboxes),
            &num_sandboxes,
            |b, &count| {
                b.iter(|| {
                    let handles: Vec<_> = (0..count)
                        .map(|_| {
                            std::thread::spawn(|| {
                                let sandbox = Sandbox::builder()
                                    .filesystem(
                                        FilesystemConfig::builder()
                                            .working_dir("/tmp")
                                            .build()
                                            .unwrap(),
                                    )
                                    .resources(
                                        ResourceConfig::builder()
                                            .wall_time_limit(Duration::from_secs(10))
                                            .build()
                                            .unwrap(),
                                    )
                                    .build()
                                    .unwrap();
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

criterion_group!(
    benches,
    bench_sandbox_creation,
    bench_command_execution,
    bench_output_sizes,
    bench_stdin_input,
    bench_seccomp_profiles,
    bench_parallel_execution,
);

criterion_main!(benches);
