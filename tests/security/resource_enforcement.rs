//! P0: Resource Limits Enforcement Tests
//!
//! Tests for:
//! - cgroup cleanup after execution (Linux)
//! - OOM detection from cgroup events (Linux)

use libsandbox::config::{FilesystemConfig, ResourceConfig};
use libsandbox::{ErrorKind, MetricStatus, ResourceEnforcement, Sandbox, SandboxError};
use std::time::Duration;

#[cfg(target_os = "linux")]
fn is_memory_unavailable(err: &SandboxError) -> bool {
    err.kind() == ErrorKind::Resource && err.context().contains("'memory'")
}

/// Test: Max open files limit should be enforced via setrlimit
#[test]
#[cfg(unix)]
fn test_max_open_files_enforced() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .max_open_files(20)
                .wall_time_limit(Duration::from_secs(5))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Check ulimit value
    let result = sandbox.run("sh", &["-c", "ulimit -n"]).unwrap();
    let output = result.stdout.trim();

    // Should show our limit
    if output != "unlimited" {
        let limit: u32 = output.parse().unwrap_or(0);
        assert!(limit <= 20, "RLIMIT_NOFILE should be 20, got {}", limit);
    }
}

/// Test: Cgroup directories should be cleaned up after execution (Linux)
///
/// Current bug: cgroups accumulate in /sys/fs/cgroup/libsandbox-*
/// Expected: Cgroup directory deleted after sandbox exits
#[test]
#[cfg(target_os = "linux")]
fn test_linux_cgroup_cleanup() {
    use std::fs;

    let cgroup_base = "/sys/fs/cgroup";

    // Count existing libsandbox cgroups
    let count_libsandbox_cgroups = || -> usize {
        if let Ok(entries) = fs::read_dir(cgroup_base) {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with("libsandbox-"))
                .count()
        } else {
            0
        }
    };

    let initial_count = count_libsandbox_cgroups();

    // Run several sandboxes
    for _ in 0..5 {
        let sandbox = match Sandbox::builder()
            .filesystem(
                FilesystemConfig::builder()
                    .working_dir("/tmp")
                    .build()
                    .unwrap(),
            )
            .resources(
                ResourceConfig::builder()
                    .memory_limit(64 * 1024 * 1024)
                    .resource_enforcement(ResourceEnforcement::BestEffort)
                    .build()
                    .unwrap(),
            )
            .build()
        {
            Ok(sandbox) => sandbox,
            Err(err) if is_memory_unavailable(&err) => return,
            Err(err) => panic!("unexpected cgroup cleanup sandbox build failure: {err:?}"),
        };

        let _ = sandbox.run("echo", &["hello"]);
    }

    // Wait for cleanup
    std::thread::sleep(Duration::from_millis(500));

    let final_count = count_libsandbox_cgroups();

    // Should not accumulate (allow 1 transient)
    assert!(
        final_count <= initial_count + 1,
        "Cgroups leaked: before={}, after={}",
        initial_count,
        final_count
    );
}

/// Test: OOM kills should be detected via cgroup memory.events (Linux)
///
/// Current bug: killed_by_oom is always false
/// Expected: killed_by_oom is true when process exceeds memory limit
#[test]
#[cfg(target_os = "linux")]
fn test_linux_oom_detection() {
    let sandbox = match Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .memory_limit(32 * 1024 * 1024) // 32MB - very tight
                .resource_enforcement(ResourceEnforcement::BestEffort)
                .wall_time_limit(Duration::from_secs(10))
                .build()
                .unwrap(),
        )
        .build()
    {
        Ok(sandbox) => sandbox,
        Err(err) if is_memory_unavailable(&err) => return,
        Err(err) => panic!("unexpected OOM sandbox build failure: {err:?}"),
    };

    // Force an OOM condition
    let report = sandbox
        .run_detailed(
            "sh",
            &[
                "-c",
                r#"
        # Allocate memory until we OOM
        data=""
        while true; do
            data="${data}$(head -c 1048576 /dev/zero | tr '\0' 'x')"
        done
    "#,
            ],
        )
        .unwrap();
    let result = report.result;

    // Should be killed (by OOM or timeout)
    assert!(
        result.exit_code != 0 || result.killed_by_timeout,
        "Process should have been killed"
    );

    if matches!(
        report.diagnostics.limits.memory,
        libsandbox::LimitStatus::Enforced
    ) && !result.killed_by_timeout
    {
        assert!(
            result.killed_by_oom,
            "OOM kill not detected. Exit code: {}, signal: {:?}",
            result.exit_code, result.signal
        );
    }
}

/// Test: Peak memory should be collected (Linux via cgroup)
///
/// Current bug: peak_memory is always None
/// Expected: peak_memory contains actual peak RSS
#[test]
#[cfg(unix)]
fn test_peak_memory_collection() {
    let sandbox = match Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .memory_limit(256 * 1024 * 1024)
                .resource_enforcement(ResourceEnforcement::BestEffort)
                .wall_time_limit(Duration::from_secs(5))
                .build()
                .unwrap(),
        )
        .build()
    {
        Ok(sandbox) => sandbox,
        #[cfg(target_os = "linux")]
        Err(err) if is_memory_unavailable(&err) => return,
        Err(err) => panic!("unexpected peak-memory sandbox build failure: {err:?}"),
    };

    // Allocate known amount of memory
    let report = sandbox
        .run_detailed(
            "sh",
            &[
                "-c",
                r#"
        # Allocate ~10MB
        dd if=/dev/zero bs=1M count=10 2>/dev/null | cat > /dev/null
        echo "done"
    "#,
            ],
        )
        .unwrap();
    let result = report.result;

    assert_eq!(result.exit_code, 0);

    match report.diagnostics.metrics.peak_memory {
        MetricStatus::Collected => {
            let peak = result
                .peak_memory
                .expect("peak_memory should be present when metric is collected");
            assert!(
                peak > 1024 * 1024,
                "peak_memory seems too low: {} bytes",
                peak
            );
        }
        MetricStatus::Unavailable { .. } | MetricStatus::Unknown { .. } => {
            assert!(
                result.peak_memory.is_none(),
                "peak_memory should be absent when metric is unavailable"
            );
        }
    }
}

/// Test: CPU time should be collected
///
/// Current bug: cpu_time is always None
/// Expected: cpu_time contains actual CPU time used
#[test]
#[cfg(unix)]
fn test_cpu_time_collection() {
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

    // Do some CPU work
    let report = sandbox
        .run_detailed(
            "sh",
            &[
                "-c",
                r#"
        # Burn some CPU
        i=0
        while [ $i -lt 100000 ]; do
            i=$((i + 1))
        done
        echo "done"
    "#,
            ],
        )
        .unwrap();
    let result = report.result;

    assert_eq!(result.exit_code, 0);

    match report.diagnostics.metrics.cpu_time {
        MetricStatus::Collected => {
            let cpu_time = result
                .cpu_time
                .expect("cpu_time should be present when metric is collected");
            assert!(
                cpu_time > Duration::from_micros(100),
                "cpu_time seems too low: {:?}",
                cpu_time
            );
        }
        MetricStatus::Unavailable { .. } | MetricStatus::Unknown { .. } => {
            assert!(
                result.cpu_time.is_none(),
                "cpu_time should be absent when metric is unavailable"
            );
        }
    }
}
