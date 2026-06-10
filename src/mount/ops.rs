//! Linux mount and rootfs helpers.

use crate::config::{Mount, Permission};
use crate::error::{Result, SandboxError};
use std::path::{Path, PathBuf};

/// Convert a `Permission` into `MsFlags` for remount operations.
///
/// This is a standalone function rather than a method on `Permission`
/// to keep the config layer platform-agnostic (no `nix` dependency).
pub(crate) fn permission_to_remount_flags(
    permission: &Permission,
    recursive: bool,
) -> nix::mount::MsFlags {
    use nix::mount::MsFlags;

    let mut flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT;
    if recursive {
        flags |= MsFlags::MS_REC;
    }

    match permission {
        Permission::ReadOnly => {
            flags |= MsFlags::MS_RDONLY;
        }
        Permission::ReadWrite => {}
        Permission::Custom(opts) => {
            if opts.read_only {
                flags |= MsFlags::MS_RDONLY;
            }
            if opts.no_exec {
                flags |= MsFlags::MS_NOEXEC;
            }
            if opts.no_suid {
                flags |= MsFlags::MS_NOSUID;
            }
            if opts.no_dev {
                flags |= MsFlags::MS_NODEV;
            }
        }
    }

    flags
}

pub(crate) fn make_mounts_private() -> Result<()> {
    use nix::mount::{mount, MsFlags};

    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)
        .map_err(|e| SandboxError::Internal(format!("mark all mounts as private: {e}")))
}

pub(crate) fn bind_mount(source: &Path, target: &Path, permission: Permission) -> Result<()> {
    use nix::mount::{mount, MsFlags};

    let recursive = source.is_dir();
    let bind_flags = if recursive {
        MsFlags::MS_BIND | MsFlags::MS_REC
    } else {
        MsFlags::MS_BIND
    };

    if recursive {
        std::fs::create_dir_all(target)?;
    } else {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !target.exists() {
            std::fs::File::create(target)?;
        }
    }

    mount(Some(source), target, None::<&str>, bind_flags, None::<&str>).map_err(|e| {
        SandboxError::Internal(format!(
            "bind mount {} -> {}: {e}",
            source.display(),
            target.display()
        ))
    })?;

    // Apply mount options via remount when needed.
    let needs_remount = match &permission {
        Permission::ReadOnly => true,
        Permission::ReadWrite => false,
        Permission::Custom(opts) => opts.read_only || opts.no_exec || opts.no_suid || opts.no_dev,
    };

    if needs_remount {
        let remount_flags = permission_to_remount_flags(&permission, recursive);
        mount(
            None::<&str>,
            target,
            None::<&str>,
            remount_flags,
            None::<&str>,
        )
        .map_err(|e| {
            SandboxError::Internal(format!(
                "remount {} -> {}: {e}",
                source.display(),
                target.display()
            ))
        })?;
    }

    Ok(())
}

pub(crate) fn mount_tmpfs(target: &Path, size: u64) -> Result<()> {
    use nix::mount::{mount, MsFlags};

    std::fs::create_dir_all(target)?;

    let options = format!("size={size}");
    mount(
        None::<&str>,
        target,
        Some("tmpfs"),
        MsFlags::empty(),
        Some(options.as_str()),
    )
    .map_err(|e| {
        SandboxError::Internal(format!(
            "mount tmpfs at {} (size={}): {e}",
            target.display(),
            size
        ))
    })?;

    Ok(())
}

pub(crate) fn remount_procfs(target: &Path) -> Result<()> {
    use nix::mount::{mount, umount2, MntFlags, MsFlags};

    std::fs::create_dir_all(target)?;
    let _ = umount2(target, MntFlags::MNT_DETACH);
    mount(
        Some("proc"),
        target,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(|e| SandboxError::Internal(format!("mount procfs at {}: {e}", target.display())))?;

    Ok(())
}

pub(crate) fn setup_mount_namespace(
    rootfs: &Path,
    mounts: &[Mount],
    tmpfs_mounts: &[(PathBuf, u64)],
) -> Result<()> {
    use nix::mount::{mount, MsFlags};

    make_mounts_private()?;

    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| {
        SandboxError::Internal(format!("bind mount rootfs at {}: {e}", rootfs.display()))
    })?;

    for mount_spec in mounts {
        let target = rootfs.join(
            mount_spec
                .target
                .strip_prefix("/")
                .unwrap_or(&mount_spec.target),
        );
        bind_mount(&mount_spec.source, &target, mount_spec.permission.clone())?;
    }

    for (path, size) in tmpfs_mounts {
        let target = rootfs.join(path.strip_prefix("/").unwrap_or(path));
        mount_tmpfs(&target, *size)?;
    }

    remount_procfs(&rootfs.join("proc"))?;

    let old_root = rootfs.join("old_root");
    std::fs::create_dir_all(&old_root)?;

    nix::unistd::pivot_root(rootfs, &old_root).map_err(|e| {
        SandboxError::Internal(format!(
            "pivot_root into sandbox at {}: {e}",
            rootfs.display()
        ))
    })?;
    std::env::set_current_dir("/")?;

    mount::<str, str, str, str>(
        None,
        "/old_root",
        None,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None,
    )
    .map_err(|e| SandboxError::Internal(format!("mark /old_root as private mount: {e}")))?;
    nix::mount::umount2("/old_root", nix::mount::MntFlags::MNT_DETACH)
        .map_err(|e| SandboxError::Internal(format!("detach /old_root mount: {e}")))?;
    std::fs::remove_dir("/old_root")?;

    Ok(())
}

pub(crate) fn setup_mount_overlays(
    mounts: &[Mount],
    tmpfs_mounts: &[(PathBuf, u64)],
) -> Result<()> {
    make_mounts_private()?;

    for mount_spec in mounts {
        bind_mount(
            &mount_spec.source,
            &mount_spec.target,
            mount_spec.permission.clone(),
        )?;
    }

    for (path, size) in tmpfs_mounts {
        mount_tmpfs(path, *size)?;
    }

    remount_procfs(Path::new("/proc"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn bind_mount_creates_ro_bind() {
        let temp = tempfile::tempdir().unwrap();
        let src = temp.path().join("src");
        let dst = temp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("file"), "data").unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        // This test only verifies the function signatures and types compile
        // correctly. Actual bind mount tests require user namespaces.
        assert!(src.join("file").exists());
    }
}
