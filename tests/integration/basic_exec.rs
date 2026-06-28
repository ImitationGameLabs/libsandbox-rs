//! Basic execution tests

use libsandbox::config::{EnvironmentConfig, FilesystemConfig};
use libsandbox::Sandbox;

#[test]
fn test_echo() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("echo", &["hello", "world"]).unwrap();

    assert_eq!(result.status.code(), 0);
    assert!(result.stdout_lossy().contains("hello"));
}

#[test]
fn test_exit_code_propagation() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    for code in [0, 1, 42] {
        let result = sandbox
            .run("sh", &["-c", &format!("exit {}", code)])
            .unwrap();

        assert_eq!(result.status.code(), code);
    }
}

#[test]
fn test_stderr_capture() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("sh", &["-c", "echo error >&2"]).unwrap();

    assert!(result.stderr_lossy().contains("error"));
}

#[test]
fn test_stdin_input() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let input = b"hello\nworld\n";

    let result = sandbox
        .run_cmd("cat", &[])
        .stdin(Some(input))
        .run()
        .unwrap();
    assert!(result.stdout_lossy().contains("hello"));
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
                .env("FOO", "bar")
                .env("BAZ", "qux")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("sh", &["-c", "echo $FOO $BAZ"]).unwrap();

    assert!(result.stdout_lossy().contains("bar"));
    assert!(result.stdout_lossy().contains("qux"));
}

#[test]
fn test_working_directory() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("pwd", &[]).unwrap();
    assert!(
        result.stdout_lossy().contains("/tmp") || result.stdout_lossy().contains("/private/tmp")
    );
}

#[test]
fn test_command_not_found() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("nonexistent_command_12345", &[]);
    assert!(result.is_err() || !result.unwrap().success());
}

#[test]
fn test_long_output() {
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
        .run(
            "sh",
            &["-c", "for i in $(seq 1 1000); do echo line$i; done"],
        )
        .unwrap();
    assert!(result.success());
    assert!(result.stdout_lossy().contains("line1"));
    assert!(result.stdout_lossy().contains("line1000"));
}

#[test]
fn test_binary_output() {
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
        .run("sh", &["-c", "printf '\\x00\\x01\\x02'"])
        .unwrap();
    assert!(result.success());
}
