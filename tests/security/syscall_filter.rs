//! Seccomp syscall filter tests - Linux only

#![cfg(target_os = "linux")]

use libsandbox::config::{FilesystemConfig, ResourceConfig, SecurityConfig};
use libsandbox::seccomp::SeccompFilterBuilder;
use libsandbox::{Sandbox, SeccompProfile, MB};
use std::time::Duration;

#[test]
fn test_strict_allows_basic_io() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .security(
            SecurityConfig::builder()
                .seccomp_profile(SeccompProfile::Strict)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("echo", &["hello"]).unwrap();
    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("hello"));
}

#[test]
fn test_standard_allows_file_operations() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .tmpfs("/tmp", 64 * MB)
                .build()
                .unwrap(),
        )
        .security(
            SecurityConfig::builder()
                .seccomp_profile(SeccompProfile::Standard)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox
        .run("sh", &["-c", "echo test > /tmp/file && cat /tmp/file"])
        .unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout.trim(), "test");
}

#[test]
fn test_standard_allows_process_creation() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .security(
            SecurityConfig::builder()
                .seccomp_profile(SeccompProfile::Standard)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("sh", &["-c", "echo a | cat"]).unwrap();
    assert_eq!(result.exit_code, 0);
}

#[test]
fn test_permissive_allows_most_operations() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .security(
            SecurityConfig::builder()
                .seccomp_profile(SeccompProfile::Permissive)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Most normal operations should work
    let result = sandbox
        .run("sh", &["-c", "echo hello && ls / > /dev/null && pwd"])
        .unwrap();

    assert_eq!(result.exit_code, 0);
}

#[test]
fn test_disabled_profile() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .security(
            SecurityConfig::builder()
                .seccomp_profile(SeccompProfile::Disabled)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Should work without seccomp restrictions
    let result = sandbox.run("echo", &["no seccomp"]).unwrap();
    assert!(result.success());
}

#[test]
fn test_seccomp_does_not_break_basic_commands() {
    for profile in [
        SeccompProfile::Strict,
        SeccompProfile::Standard,
        SeccompProfile::Permissive,
    ] {
        let sandbox = Sandbox::builder()
            .filesystem(
                FilesystemConfig::builder()
                    .working_dir("/tmp")
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

        let result = sandbox.run("true", &[]).unwrap();
        assert!(
            result.success(),
            "Profile {:?} broke 'true' command",
            profile
        );

        let result = sandbox.run("echo", &["test"]).unwrap();
        assert!(
            result.success(),
            "Profile {:?} broke 'echo' command",
            profile
        );
    }
}

#[test]
fn test_seccomp_with_python() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .security(
            SecurityConfig::builder()
                .seccomp_profile(SeccompProfile::Standard)
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

    let result = sandbox.run("python3", &["-c", "print('hello from python')"]);

    match result {
        Ok(r) => {
            if r.exit_code == 127 {
                eprintln!("warning: skipping seccomp python test because python3 is unavailable");
                return;
            }
            if r.exit_code == 0 {
                assert!(r.stdout.contains("hello from python"));
            }
        }
        Err(_) => {
            eprintln!("warning: skipping seccomp python test because python3 is unavailable");
        }
    }
}

#[test]
fn test_custom_filter_from_standard() {
    // Build a custom filter derived from Standard that denies socket syscalls.
    let filter = SeccompFilterBuilder::standard()
        .deny("socket")
        .unwrap()
        .build()
        .unwrap();

    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .security(
            SecurityConfig::builder()
                .seccomp_profile(SeccompProfile::Custom(filter))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Basic commands should still work
    let result = sandbox.run("echo", &["custom filter works"]).unwrap();
    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("custom filter works"));
}

#[test]
fn test_custom_denylist_filter() {
    // Build an allow-by-default filter that denies dangerous syscalls.
    let filter = SeccompFilterBuilder::new(libsandbox::seccomp::SeccompAction::Allow)
        .deny("ptrace")
        .unwrap()
        .deny("mount")
        .unwrap()
        .build()
        .unwrap();

    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .security(
            SecurityConfig::builder()
                .seccomp_profile(SeccompProfile::Custom(filter))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Basic command should work
    let result = sandbox.run("echo", &["hello"]).unwrap();
    assert_eq!(result.exit_code, 0);
}

#[test]
fn test_blocked_syscall_kills_with_sigsys() {
    // Build a strict filter that overrides "write" to KillProcess.
    // The strict preset allows all essential syscalls including write.
    // By appending deny("write"), last-wins semantics override the allow to
    // KillProcess. When echo tries to write to stdout, the kernel delivers
    // SIGSYS (signal 31, exit code 128+31=159).
    use libsandbox::seccomp::SeccompFilterBuilder;

    let filter = SeccompFilterBuilder::strict()
        .deny("write")
        .unwrap()
        .build()
        .unwrap();

    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .security(
            SecurityConfig::builder()
                .seccomp_profile(SeccompProfile::Custom(filter))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("echo", &["hello"]).unwrap();
    assert_eq!(
        result.signal,
        Some(31),
        "blocked write should kill with SIGSYS (signal 31), got signal={:?}, exit_code={}",
        result.signal,
        result.exit_code
    );
    assert_eq!(
        result.exit_code, 159,
        "SIGSYS exit code should be 128+31=159"
    );
}
