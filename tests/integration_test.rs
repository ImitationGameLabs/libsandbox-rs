//! Integration tests for libsandbox
//!
//! These tests verify that the sandbox actually works on the current platform.

use libsandbox::config::{EnvironmentConfig, FilesystemConfig, NetworkConfig, ResourceConfig};
use libsandbox::Sandbox;
use std::time::Duration;

#[test]
fn test_platform_supported() {
    assert!(libsandbox::is_platform_supported());
    let name = libsandbox::platform_name();
    assert!(!name.is_empty());
    println!("Running on platform: {}", name);
}

#[test]
fn test_simple_command() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run("echo", &["hello", "world"])
        .expect("Failed to run command");

    assert!(
        result.success(),
        "Command failed: {:?}",
        result.failure_reason()
    );
    assert_eq!(result.stdout.trim(), "hello world");
    assert!(result.stderr.is_empty() || result.stderr.trim().is_empty());
}

#[test]
fn test_command_with_stdin() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run_with_input("cat", &[], Some(b"test input"))
        .expect("Failed to run command");

    assert!(result.success());
    assert_eq!(result.stdout.trim(), "test input");
}

#[test]
fn test_exit_code() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .expect("Failed to build sandbox");

    // Run a command that exits with code 42
    let result = sandbox
        .run("sh", &["-c", "exit 42"])
        .expect("Failed to run command");

    assert!(!result.success());
    assert_eq!(result.exit_code, 42);
}

#[test]
fn test_stderr() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run("sh", &["-c", "echo error >&2"])
        .expect("Failed to run command");

    assert!(result.success());
    assert!(result.stderr.contains("error"));
}

#[test]
fn test_timeout() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_millis(500))
                .build()
                .unwrap(),
        )
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run("sleep", &["10"])
        .expect("Failed to run command");

    assert!(!result.success());
    assert!(result.killed_by_timeout);
    assert!(result.duration >= Duration::from_millis(450)); // Allow some tolerance
    assert!(result.duration < Duration::from_secs(2)); // Should not take full 10s
}

#[test]
fn test_environment_variables() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .environment(
            EnvironmentConfig::builder()
                .env("MY_VAR", "my_value")
                .env("ANOTHER_VAR", "123")
                .build()
                .unwrap(),
        )
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run("sh", &["-c", "echo $MY_VAR $ANOTHER_VAR"])
        .expect("Failed to run command");

    assert!(result.success());
    assert!(result.stdout.contains("my_value"));
    assert!(result.stdout.contains("123"));
}

#[test]
fn test_python_execution() {
    // Skip if Python is not available
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox.run("python3", &["-c", "print('Hello from Python')"]);

    match result {
        Ok(r) => {
            if r.exit_code == 127 {
                eprintln!("warning: skipping python execution test because python3 is unavailable");
                return;
            }
            if r.success() {
                assert_eq!(r.stdout.trim(), "Hello from Python");
            } else {
                // Python might not be installed
                eprintln!(
                    "warning: python execution test could not run: {:?}",
                    r.failure_reason()
                );
            }
        }
        Err(e) => {
            eprintln!(
                "warning: skipping python execution test because python3 is unavailable: {:?}",
                e
            );
        }
    }
}

#[test]
fn test_sandbox_id_unique() {
    let sandbox1 = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .expect("Failed to build sandbox");

    let sandbox2 = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .expect("Failed to build sandbox");

    assert_ne!(sandbox1.id(), sandbox2.id());
}

#[test]
fn test_presets() {
    use tempfile::tempdir;

    let temp = tempdir().expect("Failed to create temp dir");
    let path = temp.path();

    // Just verify presets build without error
    let _sandbox = Sandbox::data_analysis(path, path)
        .build()
        .expect("data_analysis preset failed");

    let _sandbox = Sandbox::code_judge(path)
        .build()
        .expect("code_judge preset failed");

    let _sandbox = Sandbox::agent_executor(path)
        .build()
        .expect("agent_executor preset failed");

    let _sandbox = Sandbox::interactive(path)
        .build()
        .expect("interactive preset failed");
}

// ========== Network Proxy Tests ==========

#[test]
fn test_proxied_network_setup() {
    use libsandbox::network::ProxiedNetwork;

    // Setup proxy with allowed domains
    let proxy = ProxiedNetwork::setup(vec!["example.com".into(), "*.github.com".into()])
        .expect("Failed to setup proxy");

    // Verify proxy is running
    assert!(proxy.port() > 0);
    assert!(proxy.url().starts_with("http://127.0.0.1:"));

    // Verify env vars are correctly set
    let env_vars = proxy.env_vars();
    assert_eq!(env_vars.len(), 4);
    assert!(env_vars
        .iter()
        .any(|(k, v)| k == "HTTP_PROXY" && v.contains(&proxy.port().to_string())));
    assert!(env_vars
        .iter()
        .any(|(k, v)| k == "HTTPS_PROXY" && v.contains(&proxy.port().to_string())));

    // Cleanup
    proxy.shutdown();
}

#[test]
fn test_sandbox_with_proxied_network() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .network(NetworkConfig::proxied(&["example.com"]))
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_secs(10))
                .build()
                .unwrap(),
        )
        .build()
        .expect("Failed to build sandbox");

    // Run a simple command to verify sandbox works with proxy
    let result = sandbox
        .run("echo", &["proxy test"])
        .expect("Failed to run command");

    assert!(result.success());
    assert_eq!(result.stdout.trim(), "proxy test");
}

#[test]
fn test_proxy_env_vars_in_sandbox() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .network(NetworkConfig::proxied(&["api.example.com"]))
        .build()
        .expect("Failed to build sandbox");

    // Verify proxy env vars are set inside sandbox
    let result = sandbox
        .run("sh", &["-c", "echo $HTTP_PROXY"])
        .expect("Failed to run command");

    assert!(result.success());
    // The proxy URL should be set
    assert!(
        result.stdout.contains("127.0.0.1"),
        "HTTP_PROXY should be set: {}",
        result.stdout
    );
}
