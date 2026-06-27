//! Linux mount and rootfs helpers.
//!
//! The initial mount-namespace setup runs in the sandboxed child (called from
//! [`crate::process::child_setup::exec_sandboxed`]); the dynamic mount primitives
//! live in [`crate::mount::syscalls`].

use crate::config::{Mount, MountFlags, Permission, ProcfsMode, RootfsMode};
use crate::error::{ErrorKind, Result, SandboxError};
use std::path::{Path, PathBuf};

/// Convert a [`crate::config::MountFlags`] bit set into `MsFlags` for the
/// remount that applies permission flags after a bind mount.
///
/// This is the boundary where the config-owned `MountFlags` (no `nix` dep)
/// meets the kernel-binding layer.
fn mount_flags_to_ms(flags: crate::config::MountFlags) -> nix::mount::MsFlags {
    use nix::mount::MsFlags;
    let mut out = MsFlags::empty();
    if flags.contains(crate::config::MountFlags::READ_ONLY) {
        out |= MsFlags::MS_RDONLY;
    }
    if flags.contains(crate::config::MountFlags::NO_EXEC) {
        out |= MsFlags::MS_NOEXEC;
    }
    if flags.contains(crate::config::MountFlags::NO_SUID) {
        out |= MsFlags::MS_NOSUID;
    }
    if flags.contains(crate::config::MountFlags::NO_DEV) {
        out |= MsFlags::MS_NODEV;
    }
    out
}

/// Convert a `Permission` into `MsFlags` for remount operations.
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
        Permission::ReadOnly => flags | MsFlags::MS_RDONLY,
        Permission::ReadWrite => flags,
        Permission::Custom(mount_flags) => flags | mount_flags_to_ms(*mount_flags),
    }
}

/// Compute the remount flags for a bind mount, or `None` when no remount is needed.
///
/// `ReadWrite` and an empty `Custom` flag set skip the remount entirely — a no-op
/// `MS_BIND|MS_REMOUNT` would otherwise be issued. This is the single gate shared by
/// `bind_mount`, `dynamic_bind_mount`, and the child-side `install_bind` primitive so the three
/// cannot drift on which permissions trigger a remount.
pub(crate) fn remount_flags(permission: &Permission, recursive: bool) -> Option<nix::mount::MsFlags> {
    match permission {
        Permission::ReadWrite => None,
        Permission::Custom(flags) if *flags == MountFlags::NONE => None,
        _ => Some(permission_to_remount_flags(permission, recursive)),
    }
}

pub(crate) fn make_mounts_private() -> Result<()> {
    use nix::mount::{mount, MsFlags};

    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)
        .map_err(|e| {
            SandboxError::new(ErrorKind::Mount, format!("mark all mounts as private: {e}"))
        })
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
        SandboxError::new(
            ErrorKind::Mount,
            format!(
                "bind mount {} -> {}: {e}",
                source.display(),
                target.display()
            ),
        )
    })?;

    // Apply mount options via remount when the permission requests any flags.
    if let Some(remount_flags) = remount_flags(&permission, recursive) {
        mount(None::<&str>, target, None::<&str>, remount_flags, None::<&str>).map_err(|e| {
            SandboxError::new(
                ErrorKind::Mount,
                format!("remount {} -> {}: {e}", source.display(), target.display()),
            )
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
        SandboxError::new(
            ErrorKind::Mount,
            format!("tmpfs at {} (size={}): {e}", target.display(), size),
        )
    })?;

    Ok(())
}

/// Remount a fresh `proc` filesystem at `target`.
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
    .map_err(|e| {
        SandboxError::new(
            ErrorKind::Mount,
            format!("procfs at {}: {e}", target.display()),
        )
    })?;

    Ok(())
}

/// Apply the requested [`ProcfsMode`] at `target`.
fn apply_procfs(target: &Path, mode: ProcfsMode) -> Result<()> {
    match mode {
        ProcfsMode::Remount => remount_procfs(target),
        ProcfsMode::Hide => mount_tmpfs(target, 0),
        ProcfsMode::Leave => Ok(()),
    }
}

/// Bind-mount the rootfs onto itself so it can be pivoted into.
fn bind_rootfs(rootfs: &Path) -> Result<()> {
    use nix::mount::{mount, MsFlags};

    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| {
        SandboxError::new(
            ErrorKind::Mount,
            format!("bind mount rootfs at {}: {e}", rootfs.display()),
        )
    })
}

/// Pivot the root filesystem: move the old root to `old_root`, make `/` the
/// new rootfs, then detach the old root.
fn pivot_into(rootfs: &Path, old_root: &Path) -> Result<()> {
    use nix::mount::{mount, umount2, MntFlags, MsFlags};

    std::fs::create_dir_all(old_root)?;
    nix::unistd::pivot_root(rootfs, old_root).map_err(|e| {
        SandboxError::new(
            ErrorKind::Mount,
            format!("pivot_root into sandbox at {}: {e}", rootfs.display()),
        )
    })?;
    std::env::set_current_dir("/")?;

    mount::<str, str, str, str>(
        None,
        "/old_root",
        None,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None,
    )
    .map_err(|e| {
        SandboxError::new(
            ErrorKind::Mount,
            format!("mark /old_root as private mount: {e}"),
        )
    })?;
    umount2("/old_root", MntFlags::MNT_DETACH)
        .map_err(|e| SandboxError::new(ErrorKind::Mount, format!("detach /old_root mount: {e}")))?;
    std::fs::remove_dir("/old_root")?;
    Ok(())
}

/// chroot into the rootfs. Simpler than pivot but the old root remains
/// reachable via pre-opened file descriptors.
fn chroot_into(rootfs: &Path) -> Result<()> {
    nix::unistd::chroot(rootfs).map_err(|e| {
        SandboxError::new(
            ErrorKind::Mount,
            format!("chroot into sandbox at {}: {e}", rootfs.display()),
        )
    })?;
    std::env::set_current_dir("/").ok();
    Ok(())
}

/// Set up a full mount namespace with a rootfs: bind the rootfs, apply mounts
/// + tmpfs + procfs, then establish the new root via [`RootfsMode`].
pub(crate) fn setup_mount_namespace(
    rootfs: &Path,
    mounts: &[Mount],
    tmpfs_mounts: &[(PathBuf, u64)],
    procfs: ProcfsMode,
    rootfs_mode: &RootfsMode,
) -> Result<()> {
    make_mounts_private()?;
    bind_rootfs(rootfs)?;

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

    apply_procfs(&rootfs.join("proc"), procfs)?;

    match rootfs_mode {
        RootfsMode::Pivot { old_root } => {
            let old = old_root.clone().unwrap_or_else(|| rootfs.join("old_root"));
            pivot_into(rootfs, &old)?;
        }
        RootfsMode::Chroot => {
            chroot_into(rootfs)?;
        }
    }

    Ok(())
}

/// Set up bind mounts + tmpfs + procfs without a rootfs (the child stays in
/// the inherited mount namespace, with the listed mounts layered on top).
///
/// Historically misnamed `setup_mount_overlays` — there is no overlayfs here.
pub(crate) fn setup_bind_mounts(
    mounts: &[Mount],
    tmpfs_mounts: &[(PathBuf, u64)],
    procfs: ProcfsMode,
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

    apply_procfs(Path::new("/proc"), procfs)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::MountFlags;

    #[test]
    fn mount_flags_bitor_combines() {
        let f = MountFlags::READ_ONLY | MountFlags::NO_EXEC;
        assert!(f.contains(MountFlags::READ_ONLY));
        assert!(f.contains(MountFlags::NO_EXEC));
        assert!(!f.contains(MountFlags::NO_SUID));
    }

    #[test]
    fn mount_flags_debug_lists_set_bits() {
        let f = MountFlags::READ_ONLY | MountFlags::NO_DEV;
        let s = format!("{f:?}");
        assert!(s.contains("READ_ONLY"));
        assert!(s.contains("NO_DEV"));
        assert!(!s.contains("NO_EXEC"));
    }
}
