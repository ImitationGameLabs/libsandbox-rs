//! Filesystem configuration and builder.

use crate::error::{Result, SandboxError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Fine-grained mount options for the `Permission::Custom` variant.
///
/// Default values prioritize security: `no_suid` and `no_dev` are `true`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountOptions {
    /// Mount read-only.
    #[serde(default)]
    pub read_only: bool,
    /// Prevent execution of binaries on this mount.
    #[serde(default)]
    pub no_exec: bool,
    /// Ignore set-user-ID and set-group-ID bits (default: true).
    #[serde(default = "true_val")]
    pub no_suid: bool,
    /// Disallow device files on this mount (default: true).
    #[serde(default = "true_val")]
    pub no_dev: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            read_only: false,
            no_exec: false,
            no_suid: true,
            no_dev: true,
        }
    }
}

/// Helper for serde default bool values.
const fn true_val() -> bool {
    true
}

/// File/directory mount permission.
///
/// Use `ReadOnly` or `ReadWrite` for the common cases, or `Custom(MountOptions)`
/// for fine-grained control over mount flags.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    /// Read-only mount.
    ReadOnly,
    /// Read-write mount.
    ReadWrite,
    /// Fine-grained mount options.
    Custom(MountOptions),
}

/// Mount configuration.
#[derive(Clone, Debug)]
pub struct Mount {
    pub source: PathBuf,
    pub target: PathBuf,
    pub permission: Permission,
}

/// Filesystem configuration produced by [`FilesystemBuilder`].
#[derive(Clone, Debug)]
pub struct FilesystemConfig {
    pub mounts: Vec<Mount>,
    pub tmpfs_mounts: Vec<(PathBuf, u64)>,
    pub working_dir: PathBuf,
    pub rootfs: Option<PathBuf>,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
            working_dir: PathBuf::from("/"),
            rootfs: None,
        }
    }
}

impl FilesystemConfig {
    /// Create a new [`FilesystemBuilder`].
    pub fn builder() -> FilesystemBuilder {
        FilesystemBuilder::new()
    }
}

/// Fluent builder for [`FilesystemConfig`].
#[derive(Clone)]
pub struct FilesystemBuilder {
    config: FilesystemConfig,
}

impl Default for FilesystemBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FilesystemBuilder {
    /// Create a new `FilesystemBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            config: FilesystemConfig::default(),
        }
    }

    /// Mount a file or directory into the sandbox.
    pub fn mount(
        mut self,
        source: impl Into<PathBuf>,
        target: impl Into<PathBuf>,
        permission: Permission,
    ) -> Self {
        self.config.mounts.push(Mount {
            source: source.into(),
            target: target.into(),
            permission,
        });
        self
    }

    /// Mount a tmpfs (memory filesystem).
    pub fn tmpfs(mut self, path: impl Into<PathBuf>, size_bytes: u64) -> Self {
        self.config.tmpfs_mounts.push((path.into(), size_bytes));
        self
    }

    /// Set the working directory inside the sandbox.
    pub fn working_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.working_dir = path.into();
        self
    }

    /// Use a custom rootfs.
    pub fn rootfs(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.rootfs = Some(path.into());
        self
    }

    /// Build the [`FilesystemConfig`].
    pub fn build(self) -> Result<FilesystemConfig> {
        // Structural validation: tmpfs size must be > 0
        for (path, size) in &self.config.tmpfs_mounts {
            if *size == 0 {
                return Err(SandboxError::Config(format!(
                    "tmpfs size for {} must be greater than 0",
                    path.display()
                )));
            }
        }
        Ok(self.config)
    }
}
