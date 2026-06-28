//! Network Whitelist Example
//!
//! Demonstrates using libsandbox's network whitelisting feature to allow
//! sandboxed processes to access only specific domains. Requires the `tokio`
//! feature (the default).
//!
//! Run with: cargo run --example network_allow

#![cfg_attr(not(feature = "tokio"), allow(unused))]

#[cfg(feature = "tokio")]
use libsandbox::config::{
    EnvironmentConfig, FilesystemConfig, NetworkConfig, ResourceConfig, SeccompProfile,
    SecurityConfig,
};
#[cfg(feature = "tokio")]
use libsandbox::{Permission, Sandbox};
#[cfg(feature = "tokio")]
use std::time::Duration;

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!("network_allow example requires the `tokio` feature; rebuild with --features tokio");
}

#[cfg(feature = "tokio")]
fn main() {
    println!("=== Network Whitelist Example ===\n");

    // Create workspace
    let workspace = std::env::temp_dir().join("libsandbox_network_demo");
    std::fs::create_dir_all(&workspace).unwrap();

    // 1. No network access (default)
    println!("1. No network access (default):");
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
        .network(NetworkConfig::none())
        .build()
        .unwrap();

    let result = sandbox.run(
        "curl",
        &["-s", "--connect-timeout", "3", "https://httpbin.org/ip"],
    );

    // Treat an Err (curl missing / exec blocked) as a blocked outcome by
    // defaulting to a non-zero exit code and empty stdout.
    let (exit_code, stdout_empty) = match result {
        Ok(r) => (r.status.code(), r.stdout.is_empty()),
        Err(_) => (1, true),
    };

    if exit_code != 0 || stdout_empty {
        println!("   [BLOCKED] Network access denied (expected)\n");
    } else {
        println!("   [WARNING] Network access NOT blocked!\n");
    }

    // 2. Whitelist specific domains
    println!("2. Whitelist specific domains:");
    println!("   Allowed: httpbin.org, *.github.com");

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
        .network(NetworkConfig::proxied(&["httpbin.org", "*.github.com"]))
        .build()
        .unwrap();

    // This should work - httpbin.org is whitelisted
    println!("\n   Testing httpbin.org (whitelisted):");
    let result = sandbox.run(
        "curl",
        &["-s", "--connect-timeout", "5", "http://httpbin.org/ip"],
    );

    match result {
        Ok(r) if r.success() && !r.stdout.is_empty() => {
            println!("   [ALLOWED] Response: {}", r.stdout_lossy().trim());
        }
        Ok(r) => {
            println!(
                "   [BLOCKED/ERROR] exit={}, stderr={}",
                r.status.code(),
                r.stderr_lossy().trim()
            );
        }
        Err(e) => {
            println!("   [ERROR] {}", e);
        }
    }

    // This should work - wildcard matches api.github.com
    println!("\n   Testing api.github.com (matches *.github.com):");
    let result = sandbox.run(
        "curl",
        &["-s", "--connect-timeout", "5", "https://api.github.com/zen"],
    );

    match result {
        Ok(r) if r.success() && !r.stdout.is_empty() => {
            println!("   [ALLOWED] Response: {}", r.stdout_lossy().trim());
        }
        Ok(r) => {
            println!("   [BLOCKED/ERROR] exit={}", r.status.code());
        }
        Err(e) => {
            println!("   [ERROR] {}", e);
        }
    }

    // This should be blocked - example.com is not whitelisted
    println!("\n   Testing example.com (NOT whitelisted):");
    let result = sandbox.run(
        "curl",
        &[
            "-s",
            "--connect-timeout",
            "3",
            "-x",
            &format!("http://127.0.0.1:{}", get_proxy_port()),
            "http://example.com/",
        ],
    );

    match result {
        Ok(r)
            if r.stdout_lossy().contains("403")
                || r.stdout_lossy().contains("not in whitelist") =>
        {
            println!("   [BLOCKED] Domain not in whitelist (expected)");
        }
        Ok(r) if r.status.code() != 0 => {
            println!("   [BLOCKED] Request failed (expected)");
        }
        Ok(r) => {
            println!(
                "   [?] Response: {}",
                r.stdout_lossy().chars().take(100).collect::<String>()
            );
        }
        Err(e) => {
            println!("   [ERROR] {}", e);
        }
    }

    // 3. AI/API use case
    println!("\n3. AI API access pattern:");
    println!("   Whitelist: api.openai.com, api.anthropic.com");

    // Create a Python script that demonstrates API-style access
    let script = r#"
import urllib.request
import json
import os

# In real usage, this would call the actual API
# Here we just demonstrate the pattern
print("AI API access pattern demonstration")
print("Whitelisted domains: api.openai.com, api.anthropic.com")
print("Other domains would be blocked by the proxy")

# Environment is isolated
print(f"HOME: {os.environ.get('HOME', 'not set')}")
print(f"PATH: {os.environ.get('PATH', 'not set')[:50]}...")
"#;

    let script_path = workspace.join("api_demo.py");
    std::fs::write(&script_path, script).unwrap();

    // Mount workspace and run. Compose the agent-shaped config inline (presets
    // were removed in favor of explicit composition).
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .mount(&workspace, "/workspace", Permission::ReadWrite)
                .tmpfs("/tmp", 512 * 1024 * 1024)
                .working_dir("/workspace")
                .build()
                .unwrap(),
        )
        .security(
            SecurityConfig::builder()
                .seccomp_profile(SeccompProfile::Standard)
                .build()
                .unwrap(),
        )
        .environment(
            EnvironmentConfig::builder()
                .env("HOME", "/workspace")
                .env("USER", "sandbox")
                .build()
                .unwrap(),
        )
        .network(NetworkConfig::proxied(&[
            "api.openai.com",
            "api.anthropic.com",
        ]))
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_secs(10))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox.run("python3", &["/workspace/api_demo.py"]).unwrap();
    println!("{}", result.stdout_lossy());

    // Cleanup
    std::fs::remove_dir_all(&workspace).ok();

    println!("=== Network whitelist example complete ===");
}

/// Get proxy port (in real usage, this would be from sandbox config)
fn get_proxy_port() -> u16 {
    // Default proxy port range starts at 18000
    18000
}
