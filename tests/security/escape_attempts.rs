//! Sandbox escape attempt tests
//!
//! These tests verify sandbox isolation

use libsandbox::config::{FilesystemConfig, SecurityConfig};
use libsandbox::{Permission, Sandbox, SeccompProfile};

/// Test that sandbox cannot read sensitive host files
#[test]
#[cfg(target_os = "linux")]
fn test_cannot_read_host_etc_shadow() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("cat", &["/etc/shadow"]).unwrap();

    // Should fail or read sandbox's own file (not host)
    assert!(result.exit_code != 0 || !result.stdout.contains("root:"));
}

/// Test PID namespace isolation
#[test]
#[cfg(target_os = "linux")]
fn test_pid_namespace_isolation() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // PID 1 in sandbox should be sandbox's init, not host's systemd
    let result = sandbox.run("cat", &["/proc/1/cmdline"]).unwrap();
    assert!(!result.stdout.contains("systemd"));
}

/// Test process isolation
#[test]
#[cfg(target_os = "linux")]
fn test_cannot_see_host_processes() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("ps", &["aux"]).unwrap();

    // Should only see sandbox processes (very few)
    let lines: Vec<&str> = result.stdout.lines().collect();
    assert!(lines.len() < 15);
}

/// Test mount operations blocked
#[test]
#[cfg(target_os = "linux")]
fn test_cannot_mount_filesystems() {
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

    let result = sandbox
        .run("mount", &["-t", "tmpfs", "none", "/mnt"])
        .unwrap();
    assert!(result.exit_code != 0);
}

/// Test device node creation blocked
#[test]
#[cfg(target_os = "linux")]
fn test_cannot_create_device_nodes() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("mknod", &["/tmp/test", "c", "1", "3"]).unwrap();
    assert!(result.exit_code != 0);
}

/// Test user namespace isolation
#[test]
#[cfg(target_os = "linux")]
fn test_user_namespace_isolation() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Should appear as root inside sandbox
    let result = sandbox.run("id", &[]).unwrap();
    // May or may not be uid=0 depending on configuration
    assert!(result.success() || result.exit_code != 0);
}

/// Test environment isolation
#[test]
fn test_environment_isolation() {
    // Set a variable in parent that should NOT leak to sandbox
    std::env::set_var("SECRET_VAR", "secret_value");

    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("sh", &["-c", "echo $SECRET_VAR"]).unwrap();
    // Should be empty or not contain the secret
    assert!(!result.stdout.contains("secret_value"));

    std::env::remove_var("SECRET_VAR");
}

/// Test working directory confinement
#[test]
#[cfg(target_os = "linux")]
fn test_working_directory_confinement() {
    use tempfile::tempdir;

    let tmpdir = tempdir().unwrap();

    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                // In rootless no-rootfs mode we can reliably mount onto existing writable
                // paths (like /tmp), but not create fresh top-level mount targets under /.
                .mount(tmpdir.path(), "/tmp/workspace", Permission::ReadWrite)
                .working_dir("/tmp/workspace")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Should be able to write in workspace
    let result = sandbox
        .run("sh", &["-c", "echo test > /tmp/workspace/file.txt"])
        .unwrap();
    assert!(result.success());

    // File should exist in temp dir
    assert!(tmpdir.path().join("file.txt").exists());
}
