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
//! println!("{}", result.stdout_lossy());
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

// API documentation is `cargo doc` -- every public item must be documented so the
// rendered reference stays complete. This denies the build on a missing doc-comment.
#![deny(missing_docs)]

pub mod builder;
pub mod cgroup;
pub mod config;
pub mod error;
pub(crate) mod executor;
#[cfg(all(target_os = "linux", feature = "landlock"))]
pub mod landlock;
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
    FilesystemConfig, Mount, MountFlags, NamespaceBuilder, NamespaceConfig, NetworkBuilder,
    NetworkConfig, NetworkMode, Permission, ResourceConfig, ResourceEnforcement, SeccompProfile,
    SecurityBuilder, SecurityConfig,
};
// Re-exports: builder and core types
pub use builder::SandboxBuilder;
pub use error::{ErrorKind, Result, SandboxError};
pub use mount::{DynamicMount, MountHandle};
pub use process::{
    install_rlimits, install_seccomp, prepare_rlimits, prepare_seccomp, Child, ChildCtx,
    ChildOutput, ChildPayload, ChildSetup, DetachedChild, ExitStatus, PreparedRlimits,
};
pub use result::{
    ExecutionDiagnostics, ExecutionReport, ExecutionResult, LimitDiagnostics, LimitStatus,
    MetricDiagnostics, MetricStatus,
};
pub use sandbox::{RunBuilder, Sandbox, SpawnBuilder};
pub use stdio::Stdio;

// Landlock mechanism (optional, feature-gated). Each item gated individually so the
// crate compiles cleanly with the feature off.
#[cfg(all(target_os = "linux", feature = "landlock"))]
pub use landlock::{
    install_landlock, landlock_hook, prepare_landlock, AccessDecision, PreparedLandlock, ReadPolicy,
};

// Mount-namespace child-side primitives (Linux only; libc syscalls, no extra dependency). A
// `prepare_*`/`install_*` pair mirroring the landlock/seccomp/rlimits primitives, for a
// caller-driven `pre_exec`.
#[cfg(target_os = "linux")]
pub use mount::child::{
    install_bind, install_mount, install_tmpfs, install_user_mount_ns, prepare_bind, prepare_mount,
    prepare_tmpfs, prepare_user_mount_ns, PreparedBind, PreparedMount, PreparedTmpfs,
    PreparedUserMountNs, RemountRecursion,
};

/// 1 KB in bytes
pub const KB: u64 = 1024;
/// 1 MB in bytes
pub const MB: u64 = 1024 * 1024;
/// 1 GB in bytes
pub const GB: u64 = 1024 * 1024 * 1024;

/// Whether sandboxing is supported on the current host.
///
/// Probes unprivileged user-namespace availability — the kernel feature the
/// sandbox's isolation builds on. The crate fails to compile off Linux, so a
/// `true` result means "Linux host with unprivileged userns enabled".
pub fn is_supported() -> bool {
    crate::executor::is_supported()
}
