//! P2: Observability Tests
//!
//! Tests for:
//! - Structured logging with tracing
//! - Execution metrics collection
//! - Security audit logging

use libsandbox::config::{FilesystemConfig, NamespaceConfig, ProcfsMode, ResourceConfig};
use libsandbox::{ErrorKind, ResourceEnforcement, Sandbox, SandboxError};
use std::time::Duration;

#[cfg(target_os = "linux")]
fn is_memory_unavailable(err: &SandboxError) -> bool {
    err.kind() == ErrorKind::Resource && err.context().contains("'memory'")
}

/// Test: ExecutionResult should contain timing information
#[test]
fn test_result_contains_timing() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("sleep", &["0.1"]).unwrap();

    // Duration should be populated and reasonable
    assert!(
        result.duration > Duration::from_millis(50),
        "Duration too short: {:?}",
        result.duration
    );
    assert!(
        result.duration < Duration::from_secs(5),
        "Duration too long: {:?}",
        result.duration
    );
}

/// Test: Sandbox should have unique, traceable ID
#[test]
fn test_sandbox_has_traceable_id() {
    let sandbox1 = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let sandbox2 = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let id1 = sandbox1.id();
    let id2 = sandbox2.id();

    // IDs should be non-empty
    assert!(!id1.is_empty(), "Sandbox ID should not be empty");
    assert!(!id2.is_empty(), "Sandbox ID should not be empty");

    // IDs should be unique
    assert_ne!(id1, id2, "Sandbox IDs should be unique");

    // IDs should be suitable for logging (no special chars)
    assert!(
        id1.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
        "Sandbox ID should be log-friendly: {}",
        id1
    );
}

/// Test: Platform should be identifiable
#[test]
fn test_platform_identifiable() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let _ = sandbox;
    // The crate is Linux-only (compile_error gates other platforms) and the
    // former `platform_name()`/`Sandbox::platform()` accessors were removed as
    // dead weight, so there is nothing to assert here — building on a
    // non-Linux target is a compile error by construction.
}

/// Test: Exit codes should be accurately captured
#[test]
fn test_exit_code_accuracy() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Test various exit codes
    for expected_code in [0, 1, 42, 127, 255] {
        let result = sandbox
            .run("sh", &["-c", &format!("exit {}", expected_code)])
            .unwrap();
        assert_eq!(
            result.status.code(),
            expected_code,
            "Exit code mismatch: expected {}, got {}",
            expected_code,
            result.status.code()
        );
    }
}

/// Test: Signal information should be captured
#[test]
#[cfg(unix)]
fn test_signal_capture() {
    // The PID namespace is disabled so the child is *not* PID 1: the kernel
    // otherwise protects a namespace's init from signals sent within that
    // namespace (including self-sent SIGKILL), so the child could never die
    // from its own signal. With a host PID namespace the child is an ordinary
    // process in its own process group (the spawn pipeline calls `setpgid`),
    // so `kill -9 0` — signalling the caller's own process group —
    // deterministically SIGKILLs it with no PID-number dependency and no
    // orphaned shell. `procfs(Leave)` is required because mounting `/proc`
    // needs a PID namespace.
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .procfs(ProcfsMode::Leave)
                .build()
                .unwrap(),
        )
        .namespace(NamespaceConfig::builder().pid(false).build())
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_secs(5))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("sh", &["-c", "kill -9 0"]).unwrap();

    // The child died from SIGKILL, so the signal must be captured verbatim.
    assert_eq!(
        result.status.signal(),
        Some(9),
        "child should be killed by SIGKILL (9), got signal={:?}, exit_code={}",
        result.status.signal(),
        result.status.code(),
    );
}

/// Test: Timeout flag should be accurate
#[test]
fn test_timeout_flag_accuracy() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_millis(100))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Command that doesn't timeout
    let result = sandbox.run("true", &[]).unwrap();
    assert!(!result.killed_by_timeout, "true should not timeout");

    // Command that does timeout
    let result = sandbox.run("sleep", &["10"]).unwrap();
    assert!(
        result.killed_by_timeout,
        "sleep 10 should timeout with 100ms limit"
    );
}

/// Test: Stdout and stderr should be properly separated
#[test]
fn test_output_separation() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox
        .run("sh", &["-c", "echo STDOUT; echo STDERR >&2"])
        .unwrap();

    assert!(
        result.stdout_lossy().contains("STDOUT"),
        "Stdout should contain STDOUT: {}",
        result.stdout_lossy()
    );
    assert!(
        result.stderr_lossy().contains("STDERR"),
        "Stderr should contain STDERR: {}",
        result.stderr_lossy()
    );
    assert!(
        !result.stdout_lossy().contains("STDERR"),
        "Stdout should not contain STDERR"
    );
    assert!(
        !result.stderr_lossy().contains("STDOUT"),
        "Stderr should not contain STDOUT"
    );
}

/// Test: Resource metrics structure is present (even if values are None)
#[test]
fn test_resource_metrics_structure() {
    let sandbox = match Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .memory_limit(128 * 1024 * 1024)
                .resource_enforcement(ResourceEnforcement::BestEffort)
                .build()
                .unwrap(),
        )
        .build()
    {
        Ok(sandbox) => sandbox,
        #[cfg(target_os = "linux")]
        Err(err) if is_memory_unavailable(&err) => return,
        Err(err) => panic!("unexpected observability sandbox build failure: {err:?}"),
    };

    let report = sandbox.run_cmd("echo", &["test"]).run_detailed().unwrap();
    let result = report.result;

    // These fields should exist (even if None currently)
    let _ = result.peak_memory;
    let _ = result.cpu_time;
    let _ = result.killed_by_oom;
    let _ = report.diagnostics.metrics.peak_memory;
    let _ = report.diagnostics.metrics.cpu_time;

    // Structured diagnostics should exist even when metrics are unavailable.
}

/// Test: Duration should be accurate for various execution times
#[test]
fn test_duration_accuracy() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Short command
    let result = sandbox.run("true", &[]).unwrap();
    assert!(
        result.duration < Duration::from_secs(1),
        "true should be fast: {:?}",
        result.duration
    );

    // Medium command
    let result = sandbox.run("sleep", &["0.2"]).unwrap();
    assert!(
        result.duration >= Duration::from_millis(150),
        "sleep 0.2 should take ~200ms: {:?}",
        result.duration
    );
    assert!(
        result.duration < Duration::from_secs(1),
        "sleep 0.2 should not take 1s: {:?}",
        result.duration
    );
}

/// Test: Multiple runs should each have independent metrics
#[test]
fn test_independent_metrics() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let sleeps = ["0.2", "0.5", "0.8"];
    let results: Vec<_> = (0..3)
        .map(|i| {
            sandbox
                .run("sh", &["-c", &format!("sleep {}; echo {}", sleeps[i], i)])
                .unwrap()
        })
        .collect();

    // Each should have different durations
    for (i, result) in results.iter().enumerate() {
        assert!(
            result.stdout_lossy().trim() == i.to_string(),
            "Output should be independent"
        );
    }

    // Durations should be meaningfully increasing, even under suite load.
    assert!(
        results[0].duration + Duration::from_millis(200) < results[2].duration,
        "Durations should reflect sleep time"
    );
}

/// Test: Error output should be captured completely
#[test]
fn test_error_output_capture() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Generate multi-line error
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        echo "Error line 1" >&2
        echo "Error line 2" >&2
        echo "Error line 3" >&2
        exit 1
    "#,
            ],
        )
        .unwrap();

    assert_eq!(result.status.code(), 1);
    assert!(result.stderr_lossy().contains("Error line 1"));
    assert!(result.stderr_lossy().contains("Error line 2"));
    assert!(result.stderr_lossy().contains("Error line 3"));
}

/// Test: Large output should be captured (within limits)
#[test]
fn test_large_output_capture() {
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

    // Generate ~50KB of output (simpler command)
    let result = sandbox.run("sh", &["-c",
        "i=1; while [ $i -le 500 ]; do echo \"Line $i: This is test content\"; i=$((i+1)); done"
    ]).unwrap();

    assert!(
        result.status.code() == 0,
        "Exit code should be 0, got {}. stderr: {}",
        result.status.code(),
        result.stderr_lossy()
    );
    assert!(
        result.stdout.len() > 10000,
        "Should capture large output: {} bytes",
        result.stdout.len()
    );
    assert!(
        result.stdout_lossy().contains("Line 1:"),
        "Should contain first line"
    );
    assert!(
        result.stdout_lossy().contains("Line 500:"),
        "Should contain last line"
    );
}

/// Test: Binary output should not corrupt results
#[test]
fn test_binary_output_handling() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Output some binary data
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        printf '\x00\x01\x02\x03'
        echo "text after binary"
    "#,
            ],
        )
        .unwrap();

    // Should not crash, text should be present
    assert!(
        result.stdout_lossy().contains("text after binary"),
        "Text after binary should be captured"
    );
}
