//! Path validation for dynamic mount operations.

use crate::error::{ErrorKind, Result, SandboxError};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Paths that must not be used as dynamic mount targets.
const CRITICAL_PATHS: &[&[u8]] = &[b"/", b"/proc", b"/sys", b"/dev", b"/run", b"/old_root"];

/// Validate a target path for dynamic mount operations.
///
/// Checks:
/// - Must be absolute (no relative paths)
/// - Must not contain `..` components
/// - Must not overlap with critical system paths
pub(crate) fn validate_mount_target(target: &Path) -> Result<()> {
    // Must be absolute.
    if !target.has_root() {
        return Err(SandboxError::new(
            ErrorKind::Mount,
            format!(
                "invalid mount path {}: {}",
                target.to_path_buf().display(),
                "target path must be absolute"
            ),
        ));
    }

    // Must not contain ".." components.
    for component in target.components() {
        if let std::path::Component::ParentDir = component {
            return Err(SandboxError::new(
                ErrorKind::Mount,
                format!(
                    "invalid mount path {}: {}",
                    target.to_path_buf().display(),
                    "target path must not contain '..' components"
                ),
            ));
        }
    }

    // Must not target critical system paths (byte-level comparison to
    // handle non-UTF-8 paths correctly).
    let target_bytes = target.as_os_str().as_bytes();
    for critical in CRITICAL_PATHS {
        let is_exact = target_bytes == *critical;
        let is_prefix = target_bytes.len() > critical.len()
            && target_bytes[..critical.len()] == critical[..]
            && target_bytes[critical.len()] == b'/';
        if is_exact || is_prefix {
            return Err(SandboxError::new(
                ErrorKind::Mount,
                format!(
                    "invalid mount path {}: target path must not overlap with critical path {}",
                    target.to_path_buf().display(),
                    String::from_utf8_lossy(critical)
                ),
            ));
        }
    }

    Ok(())
}

/// Validate a source path for dynamic bind mount.
///
/// Checks:
/// - Must exist on the host filesystem
pub(crate) fn validate_mount_source(source: &Path) -> Result<()> {
    if !source.exists() {
        return Err(SandboxError::new(
            ErrorKind::Mount,
            format!("path not found: {}", source.display()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_target() {
        assert!(validate_mount_target(Path::new("/data/input")).is_ok());
        assert!(validate_mount_target(Path::new("/workspace")).is_ok());
        assert!(validate_mount_target(Path::new("/a/deep/nested/path")).is_ok());
    }

    #[test]
    fn test_reject_relative_target() {
        assert!(validate_mount_target(Path::new("relative/path")).is_err());
        assert!(validate_mount_target(Path::new("./relative")).is_err());
    }

    #[test]
    fn test_reject_traversal() {
        assert!(validate_mount_target(Path::new("/../etc")).is_err());
        assert!(validate_mount_target(Path::new("/data/../etc")).is_err());
        assert!(validate_mount_target(Path::new("/data/..")).is_err());
    }

    #[test]
    fn test_reject_critical_paths() {
        assert!(validate_mount_target(Path::new("/")).is_err());
        assert!(validate_mount_target(Path::new("/proc")).is_err());
        assert!(validate_mount_target(Path::new("/proc/self")).is_err());
        assert!(validate_mount_target(Path::new("/sys")).is_err());
        assert!(validate_mount_target(Path::new("/sys/kernel")).is_err());
        assert!(validate_mount_target(Path::new("/dev")).is_err());
        assert!(validate_mount_target(Path::new("/dev/null")).is_err());
        assert!(validate_mount_target(Path::new("/run")).is_err());
        assert!(validate_mount_target(Path::new("/run/foo")).is_err());
        assert!(validate_mount_target(Path::new("/old_root")).is_err());
    }

    #[test]
    fn test_reject_nonexistent_source() {
        assert!(validate_mount_source(Path::new("/nonexistent/path/xyz")).is_err());
    }

    #[test]
    fn test_allow_near_critical() {
        // Substrings that are NOT prefixes — must be allowed.
        assert!(validate_mount_target(Path::new("/procmount")).is_ok());
        assert!(validate_mount_target(Path::new("/devmapper")).is_ok());
        assert!(validate_mount_target(Path::new("/runtime")).is_ok());
        assert!(validate_mount_target(Path::new("/sysadmin")).is_ok());
    }

    #[test]
    fn test_reject_root_target() {
        assert!(validate_mount_target(Path::new("/")).is_err());
    }

    #[test]
    fn test_reject_run_target() {
        assert!(validate_mount_target(Path::new("/run")).is_err());
        assert!(validate_mount_target(Path::new("/run/lock")).is_err());
        assert!(validate_mount_target(Path::new("/run/user/1000")).is_err());
    }
}
