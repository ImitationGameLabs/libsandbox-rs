//! Platform support detection.
//!
//! Historically this module hosted a `LinuxExecutor` struct, but the spawn/run
//! pipeline is now composed from the parent-side protocol (`process::protocol`)
//! and child-side toolbox (`process::child_setup`), exposed as free functions
//! in `process::spawn` / `process::run`. There is no executor type left to
//! abstract.

#[cfg(not(target_os = "linux"))]
compile_error!("libsandbox requires Linux");

/// Check if Linux sandboxing is supported (unprivileged user namespaces).
pub fn is_supported() -> bool {
    check_user_namespace_support()
}

fn check_user_namespace_support() -> bool {
    // Check if unprivileged user namespaces are enabled.
    std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map(|s| s.trim() == "1")
        .unwrap_or(true) // If file doesn't exist, assume enabled (newer kernels)
}

/// Pre-check user-namespace support; returns an error if disabled.
pub(crate) fn check_support() -> crate::error::Result<()> {
    if !check_user_namespace_support() {
        return Err(crate::error::SandboxError::new(crate::error::ErrorKind::Namespace, "unprivileged user namespaces disabled (run: sudo sysctl kernel.unprivileged_userns_clone=1)"));
    }
    Ok(())
}
