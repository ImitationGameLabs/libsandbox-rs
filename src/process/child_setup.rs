//! Child-side toolbox.
//!
//! The sandbox spawn pipeline is split into a parent-side *protocol* (see
//! [`crate::process::protocol`]) and this child-side *toolbox*. The toolbox
//! provides:
//!
//! - **`prepare_*` / `install_*` pairs** for the post-fork steps that a caller
//!   can realistically re-wire (seccomp, rlimits). `prepare_*` runs in the
//!   parent and may allocate; `install_*` runs in the child and is
//!   async-signal-safe (raw syscalls only).
//! - **[`ChildPayload`]** + **[`exec_sandboxed`]**: the pre-computed,
//!   move-into-child bundle and the single child entrypoint that runs the
//!   fixed post-fork sequence.
//! - **[`ChildSetup`]**: a caller-supplied hook run after seccomp install and
//!   before `exec`, so consumers (e.g. an agent runtime) can layer their own
//!   setup (landlock, privilege drop, custom mounts) onto a sandboxed child.
//!
//! # Async-signal-safety
//!
//! `install_rlimits` and [`SeccompFilter::install`](crate::seccomp::SeccompFilter::install)
//! are async-signal-safe. `exec_sandboxed` as a whole is **not** — the mount
//! step (`create_dir_all`, path joins) and error-message formatting allocate.
//! This is acceptable in the `clone()` child context (a fresh process context,
//! not a signal handler) and matches the historical SAFETY rationale. The
//! crate's own spawn always uses the `clone()` path.

use crate::config::{FilesystemConfig, ResourceConfig, SeccompProfile};
use crate::error::{ChildStage, Result};
use crate::seccomp::SeccompFilter;
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

use super::fd::{close_raw, read_raw, write_all_raw};

/// Caller-supplied child setup hook.
///
/// Run inside the sandboxed child **after** rlimits and seccomp are installed
/// and **before** `exec` (see `exec_sandboxed`). This is the extensibility
/// seam for consumers that need to layer their own setup (landlock, privilege
/// drop, additional mounts) onto a sandboxed child.
///
/// A closure (not a trait) is used deliberately: there is a single hook point
/// with no multi-method protocol, so a `Box<dyn Fn>` is less ceremony than a
/// trait and composes naturally with `move |ctx| { ... }` capturing owned
/// handles.
///
/// # Timing constraints
///
/// The hook runs *post-seccomp*. It **cannot** influence `uid_map`, `gid_map`,
/// or cgroup attachment (those are parent-side and already locked in by the
/// time the child unblocks). If the hook drops privileges via
/// `setuid`/`setresuid`/`setgid`, the configured seccomp profile **must not**
/// block those syscalls or the hook will trap.
///
/// `ctx.uid` / `ctx.gid` reflect the *mapped* identity (default 0, root inside
/// the user namespace) — not an identity the hook may transition to.
///
/// To report failure, return `Err(...)`; do **not** write file descriptors
/// directly. The framework translates the error into the spawn error-pipe
/// frame and surfaces it to the parent as a [`SandboxError`](crate::error::SandboxError)
/// at stage [`ChildStage::Hook`].
pub type ChildSetup = Box<dyn Fn(&ChildCtx) -> Result<()> + Send + Sync>;

/// Read-only context handed to a [`ChildSetup`] hook.
///
/// Describes the child's resolved identity and which namespaces were unshared,
/// so a hook can branch (e.g. skip mount operations when no mount namespace
/// exists).
#[derive(Clone, Copy, Debug)]
pub struct ChildCtx {
    /// Mapped UID inside the user namespace (default 0).
    pub uid: u32,
    /// Mapped GID inside the user namespace (default 0).
    pub gid: u32,
    /// Whether a user namespace was unshared.
    pub has_user_ns: bool,
    /// Whether a mount namespace was unshared.
    pub has_mount_ns: bool,
    /// Whether a PID namespace was unshared.
    pub has_pid_ns: bool,
    /// Whether an isolated network namespace was created.
    pub has_net_ns: bool,
}

// ---------------------------------------------------------------------------
// rlimit pair
// ---------------------------------------------------------------------------

/// Pre-computed rlimits: a plain-data transform of [`ResourceConfig`] with no
/// libc calls. Built by [`prepare_rlimits`] in the parent; consumed by
/// [`install_rlimits`] in the child.
#[derive(Clone, Copy, Debug, Default)]
pub struct PreparedRlimits {
    /// `RLIMIT_NOFILE` (max open file descriptors), if requested.
    pub nofile: Option<u64>,
    /// `RLIMIT_FSIZE` (max file size in bytes), if requested.
    pub fsize: Option<u64>,
    /// `RLIMIT_CPU` (CPU time in seconds), if requested and non-zero.
    pub cpu_secs: Option<u64>,
}

/// Parent-side: derive the rlimit settings from the resource config.
pub fn prepare_rlimits(config: &ResourceConfig) -> PreparedRlimits {
    PreparedRlimits {
        nofile: config.max_open_files.map(|n| n as u64),
        fsize: config.max_file_size,
        cpu_secs: config
            .cpu_time_limit
            .map(|d| d.as_secs())
            .filter(|&s| s > 0),
    }
}

/// Child-side: apply the prepared rlimits via `setrlimit(2)`.
///
/// Best-effort (mirrors the historical behavior): `setrlimit` failures are
/// silently ignored. Async-signal-safe.
pub fn install_rlimits(p: &PreparedRlimits) {
    fn setrlimit(resource: libc::__rlimit_resource_t, value: u64) {
        let rlim = libc::rlimit {
            rlim_cur: value as libc::rlim_t,
            rlim_max: value as libc::rlim_t,
        };
        // SAFETY: setrlimit with a stack-local rlimit and a constant resource
        // id. Errors are intentionally ignored (best-effort limits).
        unsafe {
            libc::setrlimit(resource, &rlim);
        }
    }
    if let Some(v) = p.nofile {
        setrlimit(libc::RLIMIT_NOFILE, v);
    }
    if let Some(v) = p.fsize {
        setrlimit(libc::RLIMIT_FSIZE, v);
    }
    if let Some(v) = p.cpu_secs {
        setrlimit(libc::RLIMIT_CPU, v);
    }
}

// ---------------------------------------------------------------------------
// seccomp pair
// ---------------------------------------------------------------------------

/// Parent-side: compile a [`SeccompProfile`] into a [`SeccompFilter`] blob.
///
/// Returns `Ok(None)` for [`SeccompProfile::Disabled`]. The returned filter is
/// a plain, serializable BPF program with no kernel state; load it in the
/// child via [`install_seccomp`].
pub fn prepare_seccomp(profile: &SeccompProfile) -> Result<Option<SeccompFilter>> {
    use crate::seccomp::SeccompFilterBuilder;
    match profile {
        SeccompProfile::Disabled => Ok(None),
        SeccompProfile::Strict => Ok(Some(SeccompFilterBuilder::strict().build()?)),
        SeccompProfile::Standard => Ok(Some(SeccompFilterBuilder::standard().build()?)),
        SeccompProfile::Permissive => Ok(Some(SeccompFilterBuilder::permissive().build()?)),
        SeccompProfile::Custom(f) => Ok(Some(f.clone())),
    }
}

/// Child-side: install a compiled seccomp filter in the current process.
///
/// Sets `PR_SET_NO_NEW_PRIVS`, then loads the BPF program via `seccomp(2)`
/// (falling back to `prctl(PR_SET_SECCOMP, ...)`). Allocation-free and
/// async-signal-safe (raw syscalls only) — call it inside the sandboxed child,
/// after `clone`, before `exec`.
///
/// This is the `install_*` half of the seccomp prepare/install pair, symmetric
/// with [`install_rlimits`].
pub fn install_seccomp(filter: &SeccompFilter) -> Result<()> {
    filter.install()
}

// ---------------------------------------------------------------------------
// Child payload + entrypoint
// ---------------------------------------------------------------------------

/// Everything the child needs, pre-computed by the parent and moved across
/// `clone()`. Every field is allocated in the parent; the child only borrows.
pub struct ChildPayload {
    /// Ready-pipe read end: the child blocks here until the parent signals.
    pub ready_read_fd: RawFd,
    /// Error-pipe write end: the child reports setup failures here.
    pub error_write_fd: RawFd,
    /// Parent's ready-pipe write end (child must close its inherited copy).
    pub parent_ready_write_fd: RawFd,
    /// Parent's error-pipe read end (child must close its inherited copy).
    pub parent_error_read_fd: RawFd,
    /// Parent-end stdio fds the child must close so pipes see EOF.
    pub stdin_close_in_child: Option<RawFd>,
    pub stdout_close_in_child: Option<RawFd>,
    pub stderr_close_in_child: Option<RawFd>,
    /// Child-side stdio fds to `dup2` onto 0/1/2 (`None` = leave inherited).
    pub stdio_fds: [Option<RawFd>; 3],
    /// Hostname to set in the UTS namespace (`None` = leave unchanged).
    pub hostname: Option<String>,
    /// Filesystem config (rootfs, bind mounts, tmpfs) for mount-namespace setup.
    pub filesystem: FilesystemConfig,
    /// Working directory to `chdir` into if it exists.
    pub working_dir: PathBuf,
    /// Pre-computed rlimits.
    pub rlimits: PreparedRlimits,
    /// Compiled seccomp filter (`None` = no filter).
    pub seccomp: Option<SeccompFilter>,
    /// Caller-supplied post-seccomp hook.
    pub child_hook: Option<ChildSetup>,
    /// Read-only identity/ns context for the hook.
    pub ctx: ChildCtx,
    /// `argv`, with `argv[0]` already set to the command.
    pub argv: Vec<CString>,
    /// `envp`, as `KEY=VALUE` CStrings.
    pub envp: Vec<CString>,
}

/// Run the fixed post-fork child sequence and `exec` the target program.
///
/// Order (a correctness invariant; do not reorder):
/// close inherited parent fds → `setpgid(0,0)` → block on the ready-pipe →
/// `dup2` stdio → `sethostname` → mount-namespace setup → `chdir` →
/// `install_rlimits` → seccomp install → `child_hook` → close error-pipe
/// (success signal) → `execvpe`.
///
/// Returns `1` on a setup failure (reported over the error-pipe first) or
/// `127` if `execvpe` itself fails. Never returns normally on success.
pub fn exec_sandboxed(payload: &ChildPayload) -> isize {
    use nix::unistd::execvpe;

    // Close the parent's ends of every pipe so EOF propagates correctly.
    let _ = close_raw(payload.parent_ready_write_fd);
    let _ = close_raw(payload.parent_error_read_fd);
    if let Some(fd) = payload.stdin_close_in_child {
        let _ = close_raw(fd);
    }
    if let Some(fd) = payload.stdout_close_in_child {
        let _ = close_raw(fd);
    }
    if let Some(fd) = payload.stderr_close_in_child {
        let _ = close_raw(fd);
    }

    // New process group with this process as leader (used by the kill fallback).
    // SAFETY: setpgid(0,0) moves the caller into a new PGID; no pointers.
    unsafe {
        libc::setpgid(0, 0);
    }

    // Block until the parent has written uid/gid maps and attached the cgroup.
    let mut buf = [0u8; 1];
    match read_raw(payload.ready_read_fd, &mut buf) {
        Ok(1) if buf[0] == 0 => {}
        _ => {
            let _ = close_raw(payload.ready_read_fd);
            return 1;
        }
    }
    let _ = close_raw(payload.ready_read_fd);

    // Report a tagged setup failure to the parent and abort.
    // Writes the wire frame [tag:u8][msg:bytes] consumed by the parent drain.
    fn child_abort(error_write: RawFd, stage: ChildStage, msg: &str) -> isize {
        let _ = write_all_raw(error_write, std::slice::from_ref(&(stage as u8)));
        let _ = write_all_raw(error_write, msg.as_bytes());
        let _ = close_raw(error_write);
        1
    }
    let err = payload.error_write_fd;

    // dup2 stdio fds onto STDIN/STDOUT/STDERR.
    for (slot, target) in [
        (payload.stdio_fds[0], libc::STDIN_FILENO),
        (payload.stdio_fds[1], libc::STDOUT_FILENO),
        (payload.stdio_fds[2], libc::STDERR_FILENO),
    ] {
        if let Some(fd) = slot {
            // SAFETY: dup2(fd, target) duplicates the fd onto the standard fd.
            if unsafe { libc::dup2(fd, target) } < 0 {
                return child_abort(err, ChildStage::Dup2, "dup2 stdio failed");
            }
            let _ = close_raw(fd);
        }
    }

    // UTS hostname.
    if let Some(hostname) = &payload.hostname {
        if let Err(e) = nix::unistd::sethostname(hostname) {
            return child_abort(err, ChildStage::Sethostname, &format!("set hostname: {e}"));
        }
    }

    // Mount-namespace setup.
    if let Some(rootfs) = &payload.filesystem.rootfs {
        if let Err(e) = setup_mount_namespace(
            rootfs,
            &payload.filesystem.mounts,
            &payload.filesystem.tmpfs_mounts,
            payload.filesystem.procfs,
            &payload.filesystem.rootfs_mode,
        ) {
            return child_abort(err, ChildStage::Mount, &format!("mount namespace: {e}"));
        }
    } else if let Err(e) = setup_bind_mounts(
        &payload.filesystem.mounts,
        &payload.filesystem.tmpfs_mounts,
        payload.filesystem.procfs,
    ) {
        return child_abort(err, ChildStage::Mount, &format!("mount setup: {e}"));
    }

    // Working directory. Failing to enter an existing working dir is a real
    // setup failure (the child would exec in the wrong cwd) — report it rather
    // than silently continuing, like the dup2/mount/seccomp steps above. A
    // non-existent working dir still falls through (best-effort skip).
    if payload.working_dir.exists() {
        if let Err(e) = std::env::set_current_dir(&payload.working_dir) {
            return child_abort(err, ChildStage::Chdir, &format!("chdir: {e}"));
        }
    }

    // rlimits (async-signal-safe).
    install_rlimits(&payload.rlimits);

    // seccomp (async-signal-safe).
    if let Some(filter) = &payload.seccomp {
        if let Err(e) = install_seccomp(filter) {
            return child_abort(err, ChildStage::Seccomp, &format!("seccomp: {e}"));
        }
    }

    // Caller hook (post-seccomp, pre-exec).
    if let Some(hook) = &payload.child_hook {
        if let Err(e) = hook(&payload.ctx) {
            return child_abort(err, ChildStage::Hook, &format!("{e}"));
        }
    }

    // Close the error pipe — signals successful setup to the parent.
    let _ = close_raw(err);

    // Execute the target program. On failure, exit code 127 (the parent won't
    // see this via the error pipe since the write end was just closed).
    let _ = execvpe(&payload.argv[0], &payload.argv, &payload.envp);
    127
}

// Imported for the no-rootfs mount path; kept here to localize the child's
// mount dependencies.
use crate::mount::ops::{setup_bind_mounts, setup_mount_namespace};
