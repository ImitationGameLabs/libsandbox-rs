//! Dynamic mount handle for running sandboxes.
//!
//! [`MountHandle`] is obtained from [`Child::mount_handle`](crate::Child::mount_handle)
//! and provides methods to add, remove, and remount filesystem entries inside
//! a running sandbox's mount namespace.

use crate::config::Permission;
use crate::error::Result;
use super::validation::{validate_mount_source, validate_mount_target};
use super::syscalls::{
    check_child_alive, dynamic_bind_mount, dynamic_remount, dynamic_tmpfs, dynamic_unmount,
};
use std::os::fd::OwnedFd;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Inner type shared between MountHandle and DynamicMount via Arc
// ---------------------------------------------------------------------------

/// Internal state shared between a `MountHandle` and its `DynamicMount` children.
pub(crate) struct MountHandleInner {
    pub(crate) user_ns_fd: OwnedFd,
    pub(crate) mnt_ns_fd: OwnedFd,
    pub(crate) child_pidfd: Option<OwnedFd>,
}

// ---------------------------------------------------------------------------
// MountHandle
// ---------------------------------------------------------------------------

/// Handle for dynamic mount operations on a running sandbox.
///
/// Obtained via [`Child::mount_handle()`](crate::Child::mount_handle). Owns
/// the namespace file descriptors needed to enter the child's namespaces.
///
/// Multiple `MountHandle` instances can exist for the same sandbox (each call
/// to `mount_handle()` duplicates the fds). All operations are independent.
///
/// The handle can outlive the `Child` — namespace fds remain valid as long as
/// the namespace has any reference (kernel reference counting).
pub struct MountHandle {
    inner: Arc<MountHandleInner>,
}

impl MountHandle {
    /// Create a new `MountHandle` from pre-opened namespace fds.
    pub(crate) fn new(
        user_ns_fd: OwnedFd,
        mnt_ns_fd: OwnedFd,
        child_pidfd: Option<OwnedFd>,
    ) -> Self {
        Self {
            inner: Arc::new(MountHandleInner {
                user_ns_fd,
                mnt_ns_fd,
                child_pidfd,
            }),
        }
    }

    /// Add a bind mount into the running sandbox.
    ///
    /// `source` is a path on the host. `target` is the path as seen from
    /// inside the sandbox (absolute, post-pivot-root).
    ///
    /// Returns a [`DynamicMount`] handle that can be used to remove the mount
    /// later. Dropping the handle without calling `remove()` does NOT unmount
    /// — a warning is logged.
    pub fn add_mount(
        &self,
        source: &Path,
        target: &Path,
        permission: Permission,
    ) -> Result<DynamicMount> {
        self.check_alive()?;

        validate_mount_source(source)?;
        validate_mount_target(target)?;

        dynamic_bind_mount(
            source,
            target,
            &permission,
            self.inner.user_ns_fd.as_raw_fd(),
            self.inner.mnt_ns_fd.as_raw_fd(),
        )?;

        Ok(DynamicMount {
            target: target.to_path_buf(),
            host_source: Some(source.to_path_buf()),
            inner: Arc::clone(&self.inner),
            removed: false,
        })
    }

    /// Remove a previously added dynamic mount.
    ///
    /// Convenience wrapper that calls `handle.remove()`.
    pub fn remove_mount(&self, mut handle: DynamicMount) -> Result<()> {
        handle.remove()
    }

    /// Change the permission of an existing mount (remount).
    ///
    /// `target` is the path inside the sandbox. `permission` is the new
    /// permission to apply.
    pub fn remount(&self, target: &Path, permission: Permission) -> Result<()> {
        self.check_alive()?;
        validate_mount_target(target)?;

        dynamic_remount(
            target,
            &permission,
            true, // recursive by default for safety
            self.inner.user_ns_fd.as_raw_fd(),
            self.inner.mnt_ns_fd.as_raw_fd(),
        )
    }

    /// Add a tmpfs (memory-backed filesystem) into the running sandbox.
    ///
    /// `target` is the mount point inside the sandbox. `size_bytes` is the
    /// maximum size of the tmpfs. Note: the actual usable size may be less
    /// if a cgroup memory limit is in effect.
    pub fn add_tmpfs(&self, target: &Path, size_bytes: u64) -> Result<DynamicMount> {
        self.check_alive()?;
        validate_mount_target(target)?;

        dynamic_tmpfs(
            target,
            size_bytes,
            self.inner.user_ns_fd.as_raw_fd(),
            self.inner.mnt_ns_fd.as_raw_fd(),
        )?;

        Ok(DynamicMount {
            target: target.to_path_buf(),
            host_source: None,
            inner: Arc::clone(&self.inner),
            removed: false,
        })
    }

    /// Check if the sandboxed child is still alive.
    fn check_alive(&self) -> Result<()> {
        check_child_alive(self.inner.child_pidfd.as_ref().map(|fd| fd.as_raw_fd()))
    }
}

impl std::fmt::Debug for MountHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountHandle")
            .field(
                "child_pidfd",
                &self.inner.child_pidfd.as_ref().map(|_| "some"),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// DynamicMount
// ---------------------------------------------------------------------------

/// Represents a dynamically added mount inside the sandbox.
///
/// Created by [`MountHandle::add_mount()`] or [`MountHandle::add_tmpfs()`].
/// Call [`remove()`](DynamicMount::remove) to unmount. Dropping without
/// removal logs a warning — the mount persists until the sandbox exits.
pub struct DynamicMount {
    target: PathBuf,
    host_source: Option<PathBuf>,
    inner: Arc<MountHandleInner>,
    removed: bool,
}

impl DynamicMount {
    /// Remove this mount from the sandbox.
    ///
    /// After removal, the mount point directory still exists but the mounted
    /// content is no longer accessible. The mount is detached lazily
    /// (`MNT_DETACH`) so it won't fail if the mount is busy.
    pub fn remove(&mut self) -> Result<()> {
        if self.removed {
            return Ok(());
        }

        dynamic_unmount(
            &self.target,
            self.inner.user_ns_fd.as_raw_fd(),
            self.inner.mnt_ns_fd.as_raw_fd(),
        )?;

        self.removed = true;
        Ok(())
    }

    /// The target path inside the sandbox where this mount is attached.
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// The host source path that was mounted, or `None` for tmpfs mounts.
    pub fn source(&self) -> Option<&Path> {
        self.host_source.as_deref()
    }
}

impl Drop for DynamicMount {
    fn drop(&mut self) {
        if !self.removed {
            tracing::warn!(
                "DynamicMount at {} dropped without explicit remove(); \
                 mount persists until the sandbox exits",
                self.target.display()
            );
        }
    }
}

impl std::fmt::Debug for DynamicMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicMount")
            .field("target", &self.target)
            .field("source", &self.host_source)
            .field("removed", &self.removed)
            .finish()
    }
}
