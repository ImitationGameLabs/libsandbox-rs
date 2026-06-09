//! # libsandbox
//!
//! A Linux-first sandbox runtime providing namespace isolation, cgroup v2
//! resource limits, seccomp filtering, and network isolation.
//!
//! ## One-shot execution
//!
//! ```rust,no_run
//! use libsandbox::{Sandbox, Permission, MB};
//! use libsandbox::config::{FilesystemConfig, ResourceConfig, NetworkConfig};
//! use std::time::Duration;
//!
//! let sandbox = Sandbox::builder()
//!     .filesystem(
//!         FilesystemConfig::builder()
//!             .mount("/data/input", "/input", Permission::ReadOnly)
//!             .working_dir("/tmp")
//!             .build()
//!             .unwrap()
//!     )
//!     .resources(
//!         ResourceConfig::builder()
//!             .memory_limit(512 * MB)
//!             .wall_time_limit(Duration::from_secs(30))
//!             .build()
//!             .unwrap()
//!     )
//!     .network(NetworkConfig::none())
//!     .build()
//!     .unwrap();
//!
//! let result = sandbox.run("python3", &["-c", "print('hello')"]).unwrap();
//! println!("{}", result.stdout);
//! ```
//!
//! ## Spawn (persistent process)
//!
//! ```rust,no_run
//! use libsandbox::{Sandbox, Stdio};
//!
//! let sandbox = Sandbox::builder().build().unwrap();
//! let child = sandbox.spawn("bash", &["--login"]).unwrap();
//! // interact via child.stdout_fd(), child.stdin_fd(), etc.
//! let status = child.wait().unwrap();
//! println!("exit: {}", status.code());
//! ```
//!
//! On Linux, explicitly requested cgroup-backed limits fail closed by default.
//! `ResourceEnforcement::BestEffort` only relaxes controllers that can still be
//! honestly provisioned on the current execution path. Rootless memory limits
//! continue to fail closed unless a usable delegated cgroup v2 parent is
//! available; inspect `Sandbox::run_detailed()` diagnostics for degraded
//! non-memory limits.

pub mod builder;
pub mod config;
pub mod cgroup;
pub mod error;
pub mod executor;
pub mod mount;
pub mod namespace;
pub mod network;
pub mod process;
pub mod result;
pub mod sandbox;
pub mod seccomp;
pub mod stdio;

// Re-exports: types from config modules (maintaining backward-compatible paths)
pub use config::{
    CgroupLimitRequests, EnvironmentBuilder, EnvironmentConfig, ExecutionPolicy, FilesystemBuilder,
    FilesystemConfig, Mount, MountOptions, NetworkBuilder, NetworkConfig, NetworkMode, Permission,
    ResourceConfig, ResourceEnforcement, SeccompProfile, SecurityBuilder, SecurityConfig,
};
// Re-exports: builder and core types
pub use builder::{SandboxBuilder, SandboxConfig};
pub use error::{Result, SandboxError};
pub use mount::{DynamicMount, MountHandle};
pub use process::{Child, ExitStatus};
pub use result::{
    ExecutionDiagnostics, ExecutionReport, ExecutionResult, LimitDiagnostics, LimitStatus,
    MetricDiagnostics, MetricStatus,
};
pub use sandbox::{Sandbox, SpawnBuilder};
pub use stdio::Stdio;

/// 1 KB in bytes
pub const KB: u64 = 1024;
/// 1 MB in bytes
pub const MB: u64 = 1024 * 1024;
/// 1 GB in bytes
pub const GB: u64 = 1024 * 1024 * 1024;

/// Check if the current platform supports sandboxing
pub fn is_platform_supported() -> bool {
    crate::executor::is_supported()
}

/// Get the current platform name
pub fn platform_name() -> &'static str {
    "linux"
}
