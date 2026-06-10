//! Benchmark sandbox execution under different seccomp profiles.
//!
//! Each iteration builds a fresh sandbox with the given profile and runs `echo test`.
//! The creation cost is intentionally included — different profiles have different
//! BPF filter setup overhead, which is part of what users pay for.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use libsandbox::config::{FilesystemConfig, ResourceConfig, SecurityConfig};
use libsandbox::{Sandbox, SeccompProfile};
use std::time::Duration;

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

criterion_group!(benches, bench_seccomp_profiles);
criterion_main!(benches);
