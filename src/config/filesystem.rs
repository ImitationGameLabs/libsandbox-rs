//! Filesystem configuration and builder.

use crate::error::{ErrorKind, Result, SandboxError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Mount flag bits, config-owned (no `nix` dependency in the config layer).
///
/// A `#[repr(transparent)]` newtype over the raw `MsFlags` bit values so the
/// config graph stays serde-serializable and `nix` stays out of the public
/// config API. The conversion to `nix::mount::MsFlags` happens only at the
/// `mount::ops` boundary.
#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountFlags(u32);

impl MountFlags {
    /// No flags (read-write, executable, suid/dev allowed).
    pub const NONE: Self = Self(0);
    /// Mount read-only (`MS_RDONLY`).
    pub const READ_ONLY: Self = Self(libc::MS_RDONLY as u32);
    /// Disallow program execution (`MS_NOEXEC`).
    pub const NO_EXEC: Self = Self(libc::MS_NOEXEC as u32);
    /// Ignore set-user-ID / set-group-ID bits (`MS_NOSUID`).
    pub const NO_SUID: Self = Self(libc::MS_NOSUID as u32);
    /// Disallow device files (`MS_NODEV`).
    pub const NO_DEV: Self = Self(libc::MS_NODEV as u32);

    /// Empty flag set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Raw bit value (for the `mount::ops` boundary conversion).
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Whether `other` is fully contained in this set.
    pub const fn contains(&self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Insert `other` in place.
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

impl std::fmt::Debug for MountFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bits = Vec::new();
        if self.contains(Self::READ_ONLY) {
            bits.push("READ_ONLY");
        }
        if self.contains(Self::NO_EXEC) {
            bits.push("NO_EXEC");
        }
        if self.contains(Self::NO_SUID) {
            bits.push("NO_SUID");
        }
        if self.contains(Self::NO_DEV) {
            bits.push("NO_DEV");
        }
        if bits.is_empty() {
            f.write_str("MountFlags(NONE)")
        } else {
            f.debug_tuple("MountFlags")
                .field(&bits.join(" | "))
                .finish()
        }
    }
}

impl std::ops::BitOr for MountFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for MountFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// How `/proc` is handled inside the sandbox mount namespace.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcfsMode {
    /// Remount a fresh `proc` filesystem (the historical default).
    #[default]
    Remount,
    /// Leave `/proc` untouched.
    Leave,
    /// Hide `/proc` by mounting an empty tmpfs over it.
    Hide,
}

/// How the root filesystem is established when a `rootfs` is configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootfsMode {
    /// `pivot_root` into the rootfs (the default). `old_root` customizes where
    /// the old root is pivoted out to (default `$rootfs/old_root`).
    Pivot { old_root: Option<PathBuf> },
    /// `chroot` into the rootfs without pivoting. Simpler, but the old root
    /// remains reachable inside the namespace via file descriptors opened
    /// before `chroot`.
    Chroot,
}

impl Default for RootfsMode {
    fn default() -> Self {
        Self::Pivot { old_root: None }
    }
}

/// File/directory mount permission.
///
/// Use `ReadOnly` or `ReadWrite` for the common cases, or `Custom(MountFlags)`
/// for fine-grained control over mount flags.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    /// Read-only mount.
    ReadOnly,
    /// Read-write mount.
    ReadWrite,
    /// Fine-grained mount flags.
    Custom(MountFlags),
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
    /// How `/proc` is handled. Defaults to [`ProcfsMode::Remount`].
    pub procfs: ProcfsMode,
    /// How the rootfs is established. Defaults to [`RootfsMode::Pivot`].
    pub rootfs_mode: RootfsMode,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
            working_dir: PathBuf::from("/"),
            rootfs: None,
            procfs: ProcfsMode::default(),
            rootfs_mode: RootfsMode::default(),
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

    /// How `/proc` is handled inside the sandbox.
    pub fn procfs(mut self, mode: ProcfsMode) -> Self {
        self.config.procfs = mode;
        self
    }

    /// How the rootfs is established (pivot vs chroot).
    pub fn rootfs_mode(mut self, mode: RootfsMode) -> Self {
        self.config.rootfs_mode = mode;
        self
    }

    /// Build the [`FilesystemConfig`].
    pub fn build(self) -> Result<FilesystemConfig> {
        // Structural validation: tmpfs size must be > 0
        for (path, size) in &self.config.tmpfs_mounts {
            if *size == 0 {
                return Err(SandboxError::new(
                    ErrorKind::Config,
                    format!(
                        "configuration error: tmpfs size for {} must be greater than 0",
                        path.display()
                    ),
                ));
            }
        }
        Ok(self.config)
    }
}
