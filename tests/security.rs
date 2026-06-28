//! Security tests entry point

#[path = "security/escape_attempts.rs"]
mod escape_attempts;

#[path = "security/resource_exhaustion.rs"]
mod resource_exhaustion;

#[cfg(target_os = "linux")]
#[path = "security/syscall_filter.rs"]
mod syscall_filter;

// Process management tests (zombie, process groups, signals)
#[cfg(unix)]
#[path = "security/process_management.rs"]
mod process_management;

// Resource enforcement tests (setrlimit, cgroups, OOM)
#[path = "security/resource_enforcement.rs"]
mod resource_enforcement;

// Network security tests (IP bypass, proxy). Requires the tokio feature
// (the HTTP proxy is a tokio runtime).
#[cfg(feature = "tokio")]
#[path = "security/network_security.rs"]
mod network_security;
