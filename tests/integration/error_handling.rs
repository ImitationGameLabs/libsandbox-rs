//! P1: Error Handling Tests
//!
//! Tests for:
//! - Graceful degradation (handle missing permissions without panic)
//! - Resource pre-check (verify permissions before execution)
//! - Detailed error types (distinguish command not found vs permission denied vs resource limit)

use libsandbox::config::{FilesystemConfig, ResourceConfig};
use libsandbox::{ErrorKind, Permission, ResourceEnforcement, Sandbox, SandboxError};
use std::time::Duration;

#[cfg(target_os = "linux")]
fn is_memory_unavailable(err: &SandboxError) -> bool {
    err.kind() == ErrorKind::Resource && err.context().contains("'memory'")
}

/// Test: Missing command should return CommandNotFound error
#[test]
fn test_error_command_not_found() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("nonexistent_command_xyz_123", &[]);

    match result {
        Err(e) => {
            // Command-not-found surfaces as an Exec-category error whose
            // context names the missing command.
            assert!(
                matches!(e.kind(), ErrorKind::Exec | ErrorKind::Io),
                "Expected an Exec/Io error, got: {:?}",
                e
            );
            assert!(
                e.context().contains("nonexistent_command_xyz_123"),
                "expected context to name the missing command: {}",
                e
            );
        }
        Ok(r) => {
            // Shell might have caught it
            assert!(r.exit_code != 0, "Nonexistent command should fail");
        }
    }
}

/// Test: Permission denied should return appropriate error
#[test]
#[cfg(unix)]
fn test_error_permission_denied() {
    use std::fs::{self, File};
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = std::env::temp_dir().join("libsandbox_perm_test");
    let _ = fs::create_dir_all(&temp_dir);
    let script = temp_dir.join("no_exec.sh");

    // Create a file without execute permission
    File::create(&script).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();

    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run(script.to_str().unwrap(), &[]);

    // Should fail with some exec/permission-related error, or exit non-zero.
    match result {
        Err(e) => {
            // Any exec/io error is acceptable for a non-executable file.
            assert!(
                matches!(
                    e.kind(),
                    ErrorKind::Exec | ErrorKind::Io | ErrorKind::Config
                ),
                "Unexpected error kind for non-executable: {:?}",
                e
            );
        }
        Ok(r) => {
            // If execution succeeded, exit code should be non-zero.
            assert!(r.exit_code != 0, "Non-executable should fail");
        }
    }

    // Cleanup
    let _ = fs::remove_file(&script);
}

/// Test: Mount of non-existent path should return PathNotFound error
#[test]
fn test_error_path_not_found() {
    let result = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .mount(
                    "/nonexistent/path/xyz",
                    "/sandbox/mount",
                    Permission::ReadOnly,
                )
                .build()
                .unwrap(),
        )
        .build();

    match result {
        Err(e) => {
            assert_eq!(e.kind(), ErrorKind::Mount);
            assert!(
                e.context().contains("nonexistent"),
                "expected context to name the path: {}",
                e
            );
        }
        Ok(_) => {
            panic!("Expected error for non-existent mount path");
        }
    }
}

/// Test: Invalid rootfs should return appropriate error
#[test]
fn test_error_invalid_rootfs() {
    let result = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .rootfs("/nonexistent/rootfs")
                .build()
                .unwrap(),
        )
        .build();

    match result {
        Err(e) => {
            assert_eq!(e.kind(), ErrorKind::Mount);
        }
        Ok(_) => {
            panic!("Expected error for non-existent rootfs");
        }
    }
}

/// Test: Graceful handling when cgroups unavailable (Linux)
#[test]
#[cfg(target_os = "linux")]
fn test_graceful_cgroup_check() {
    use libsandbox::cgroup::{probe_cgroup_support, CgroupController};

    let strict = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .memory_limit(64 * 1024 * 1024) // Requires cgroups
                .build()
                .unwrap(),
        )
        .build();

    let support = probe_cgroup_support();
    if support.can_enforce(CgroupController::Memory) {
        assert!(
            strict.is_ok(),
            "strict mode should succeed when memory controller is available"
        );
    } else {
        match strict {
            Err(e) => {
                assert_eq!(e.kind(), ErrorKind::Resource);
                assert!(
                    e.context().contains("'memory'"),
                    "expected memory-related context: {}",
                    e
                );
            }
            Ok(_) => panic!("Strict mode should fail closed when memory limit cannot be enforced"),
        }
    }

    let best_effort = Sandbox::builder()
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
        .build();
    if support.can_enforce(CgroupController::Memory) {
        assert!(
            best_effort.is_ok(),
            "best-effort mode should build when memory controller is available"
        );
    } else {
        match best_effort {
            Err(e) => {
                assert_eq!(e.kind(), ErrorKind::Resource);
                assert!(
                    e.context().contains("'memory'"),
                    "expected memory-related context: {}",
                    e
                );
            }
            Ok(_) => panic!("best-effort memory should fail closed when memory cannot be enforced"),
        }
    }
}

/// Test: Timeout errors should be distinguishable
#[test]
fn test_error_timeout_distinguishable() {
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

    let result = sandbox.run("sleep", &["10"]).unwrap();

    // Should be marked as killed by timeout
    assert!(
        result.killed_by_timeout,
        "Timeout kill should be distinguishable"
    );
}

/// Test: Errors should contain useful context
#[test]
fn test_error_contains_context() {
    let result = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .mount(
                    "/nonexistent/specific/path/for/test",
                    "/mnt",
                    Permission::ReadOnly,
                )
                .build()
                .unwrap(),
        )
        .build();

    match result {
        Err(e) => {
            assert!(
                matches!(e.kind(), ErrorKind::Mount | ErrorKind::Config),
                "Expected a Mount/Config error, got: {:?}",
                e
            );
            // Error should mention the problematic path
            let msg = e.to_string();
            assert!(
                msg.contains("nonexistent") || msg.contains("specific"),
                "Error should contain context about the problem: {}",
                msg
            );
        }
        Ok(_) => {
            panic!("Expected error for nonexistent path");
        }
    }
}

/// Test: Multiple errors should all be reported (validation)
#[test]
fn test_validation_reports_issues() {
    // This tests that validation catches problems early
    let result = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .mount("/nonexistent1", "/mnt1", Permission::ReadOnly)
                .build()
                .unwrap(),
        )
        .build();

    // Should fail at validation
    assert!(result.is_err());

    // Error should be validation-related
    match result {
        Err(e) => {
            assert_eq!(e.kind(), ErrorKind::Mount);
        }
        Ok(_) => unreachable!(),
    }
}

/// Test: Build should succeed with valid configuration
#[test]
fn test_valid_config_succeeds() {
    let result = Sandbox::builder()
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
                .wall_time_limit(Duration::from_secs(60))
                .build()
                .unwrap(),
        )
        .build();
    #[cfg(target_os = "linux")]
    if let Err(err) = &result {
        if is_memory_unavailable(err) {
            return;
        }
    }

    assert!(
        result.is_ok(),
        "Valid config should succeed: {}",
        result
            .as_ref()
            .err()
            .map(|e| format!("{:?}", e))
            .unwrap_or_default()
    );
}

/// Test: Error display should be user-friendly
#[test]
fn test_error_display_user_friendly() {
    let result = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .mount("/does/not/exist", "/mnt", Permission::ReadOnly)
                .build()
                .unwrap(),
        )
        .build();

    if let Err(e) = result {
        let display = format!("{}", e);

        // Display should be readable
        assert!(!display.is_empty(), "Error Display should not be empty");

        // Should not expose internal details excessively
        assert!(
            !display.contains("0x") || display.len() < 200,
            "Error should be user-friendly, not raw debug: {}",
            display
        );
    }
}

/// A `ChildSetup` hook that returns `Err` must surface at `spawn()` time as an
/// `Exec`-category error tagged at `ChildStage::Hook` -- deterministically, every
/// run. This exercises the spawn error-pipe drain: the parent blocks on the error
/// pipe until the child commits, so the hook failure is reported here rather than
/// being missed and later confused with the target program exiting non-zero.
#[test]
fn test_child_setup_hook_failure_surfaces_at_spawn() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let err = sandbox
        .build_spawn("true", &[])
        .child_setup(|_ctx| Err(SandboxError::new(ErrorKind::Other, "hook-failure-sentinel")))
        .start()
        .expect_err("a failing ChildSetup hook must surface at spawn");

    assert_eq!(err.kind(), ErrorKind::Exec, "got: {err:?}");
    assert!(
        err.context().contains("child-hook"),
        "expected ChildStage::Hook in context, got: {}",
        err.context()
    );
    assert!(
        err.context().contains("hook-failure-sentinel"),
        "expected the hook's message in context, got: {}",
        err.context()
    );
}
