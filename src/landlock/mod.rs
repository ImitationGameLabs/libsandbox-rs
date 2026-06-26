//! Landlock filesystem-access enforcement — the mechanism half of a sandbox.
//!
//! Linux-only, behind the `landlock` feature. This is **not** a full sandbox — no
//! network, resource, or seccomp isolation (those live in their own modules and are
//! composed by the caller). Given an [`AccessDecision`], landlock restricts a spawned
//! process so it may read per the decision's read policy and write only to the listed
//! paths (plus a small baseline of scratch/devices every program needs to function).
//!
//! # Toolbox split
//!
//! Mirroring `prepare_seccomp` / `install_seccomp`, landlock is split into a
//! parent-side [`prepare_landlock`] (builds the ruleset fd; may allocate) and a
//! child-side [`install_landlock`] (calls `landlock_restrict_self`; async-signal-safe,
//! raw syscalls only). The ruleset fd crosses `clone()` inside a [`ChildSetup`] hook
//! captured by [`landlock_hook`].
//!
//! # Where it runs in the spawn pipeline
//!
//! [`install_landlock`] runs from a [`ChildSetup`] hook — i.e. **after** seccomp is
//! installed and **before** `exec` (see `crate::process::child_setup`). The child is
//! created fork-like via `clone(2)` (no `CLONE_VM` / `CLONE_FILES`), so the captured
//! [`PreparedLandlock`] fd is inherited by the child, and there is no fd-sanitizing loop
//! before the hook — the ruleset fd survives until `FD_CLOEXEC` closes it on `exec`.
//!
//! # Seccomp contract
//!
//! Because the hook runs *after* seccomp is installed, `landlock_restrict_self` is issued
//! **under** the active seccomp filter. The crate's `Standard` and `Strict` profiles
//! allow it when the `landlock` feature is on (see `seccomp/presets.rs`). A `Custom`
//! profile that denies `landlock_restrict_self` will trap the child at
//! [`ChildStage::Hook`]. `Disabled` and `Permissive` are unaffected.
//!
//! # Fail-closed
//!
//! Two gates ensure a process never runs unrestricted by accident:
//! 1. [`prepare_landlock`] builds the ruleset with `CompatLevel::HardRequirement` — if
//!    the kernel lacks landlock (or it is disabled at boot), ruleset creation errors and
//!    the spawn is aborted (`ensure_supported` caches this probe process-wide).
//! 2. [`install_landlock`] runs `prctl(PR_SET_NO_NEW_PRIVS)` +
//!    `landlock_restrict_self(2)` in the child; if either fails it returns `Err`, which
//!    the spawn pipeline translates into a [`ChildStage::Hook`] abort.
//!
//! [`ChildStage::Hook`]: crate::error::ChildStage::Hook

#![cfg(all(target_os = "linux", feature = "landlock"))]

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};

use crate::error::{ErrorKind, Result, SandboxError};
use crate::{ChildCtx, ChildSetup};

mod decision;

pub use decision::{AccessDecision, ReadPolicy};

/// Scratch/device paths every landlocked process needs regardless of its writable set:
/// temp dirs (`$TMPDIR` or `/tmp`, plus `/var/tmp`) and the character devices a shell
/// touches (`/dev/null` for redirects, `/dev/tty`, etc.). Only paths that actually exist
/// on the host are returned — landlock path rules require it.
///
/// Private: merged inside [`prepare_landlock`], callers never compose it. (The asymmetry
/// with the public [`baseline_readable`] is intentional — `Narrow` callers must assemble
/// `baseline_readable()` into their read allowlist themselves, whereas the write baseline
/// is always merged here because every landlocked program unconditionally needs it.)
fn baseline_writable() -> Vec<PathBuf> {
    let mut out = Vec::new();

    out.push(std::env::temp_dir()); // $TMPDIR or /tmp
    out.push(PathBuf::from("/var/tmp"));
    for dev in ["/dev/null", "/dev/zero", "/dev/urandom", "/dev/tty"] {
        out.push(PathBuf::from(dev));
    }
    // Drop anything that doesn't exist (PathFd::new would otherwise error).
    out.retain(|p| p.exists());
    out
}

/// System paths a narrow-read process needs to read+execute to function: the program
/// itself, coreutils, shared libs, the dynamic linker, procfs/sysfs, and devices.
/// Deliberately EXCLUDES `/etc` and `$HOME` — those are where secrets live
/// (`/etc/secrets`, `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config` tokens), so a narrow-read
/// process gets clean zero-access to them.
///
/// Only paths that exist on the host are returned (landlock requires it). The caller
/// composes this with the workspace to form the narrow read allowlist.
pub fn baseline_readable() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = [
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32", "/proc", "/sys", "/dev",
        "/opt",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    // Temp dirs are read too (they're writable via baseline_writable).
    out.push(std::env::temp_dir());
    out.push(PathBuf::from("/var/tmp"));
    out.retain(|p| p.exists());
    out
}

/// Grant mask for [`build_ruleset_from_grants`].
#[derive(Clone, Copy, Debug)]
enum Grant {
    /// read+execute only (the path is read-only within this ruleset).
    Read,
    /// full read+write+execute.
    Write,
}

/// Flatten any landlock-crate error into a [`SandboxError`] classified as
/// [`ErrorKind::Landlock`] (carries its `Display`).
fn ll_error<E: std::error::Error + Send + Sync + 'static>(e: E) -> SandboxError {
    SandboxError::new(ErrorKind::Landlock, e.to_string())
}

/// Build a ruleset from an explicit list of `(path, grant)` rules — the caller controls
/// exactly what is granted, including `/`. Shared engine behind both policies: the broad
/// policy grants `/` Read + each writable Write; the narrow policy grants only a read
/// allowlist + writable Write, so `$HOME` and secrets are denied by default
/// (`handle_access(full)` is deny-default).
///
/// Non-existent and duplicate paths are skipped (a path may have been removed after it
/// was added to the decision). `HardRequirement` fails closed on an unsupported kernel
/// — gate #1.
///
/// # ABI pin
///
/// Pinned to [`ABI::V1`] (the ported baseline). On kernels ≥5.19 (ABI V2/V3) the
/// `Refer`/`Truncate`/`IoctlDev` access types are not handled and therefore unrestricted
/// by the domain — e.g. certain device ioctls are not confined. Upgrading the ABI is
/// tracked separately.
fn build_ruleset_from_grants(grants: &[(PathBuf, Grant)]) -> Result<OwnedFd> {
    let abi = ABI::V1;
    let read_exec = AccessFs::from_read(abi); // includes Execute for V1+
    let full = AccessFs::from_all(abi);

    let mut created = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(full)
        .map_err(ll_error)?
        .create()
        .map_err(ll_error)?;
    let mut seen: std::collections::HashSet<&Path> = std::collections::HashSet::new();
    for (path, grant) in grants {
        if !path.exists() || !seen.insert(path.as_path()) {
            continue;
        }
        let mask = match grant {
            Grant::Read => read_exec,
            Grant::Write => full,
        };
        created = created
            .add_rule(PathBeneath::new(PathFd::new(path).map_err(ll_error)?, mask))
            .map_err(ll_error)?;
    }

    // `RulesetCreated` keeps its fd private; the only way out is clone-then-consume.
    let cloned = created.try_clone().map_err(ll_error)?;
    let fd_opt: Option<OwnedFd> = cloned.into();
    let fd = fd_opt.ok_or_else(|| SandboxError::new(ErrorKind::Landlock, "ruleset has no fd"))?;
    set_cloexec(&fd)?;
    Ok(fd)
}

/// Mark `fd` close-on-exec so the child does not inherit it past `execve` (the fd is
/// still available inside the [`ChildSetup`] hook, before exec, which is all we need).
fn set_cloexec(fd: &OwnedFd) -> Result<()> {
    // SAFETY: fcntl(F_SETFD, FD_CLOEXEC) on a valid fd; no pointers.
    let r = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    if r != 0 {
        return Err(SandboxError::new(
            ErrorKind::Landlock,
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// prepare / install pair
// ---------------------------------------------------------------------------

/// A built landlock ruleset ready to be applied in the child by [`install_landlock`].
///
/// Owns the ruleset fd; the [`ChildSetup`] hook produced by [`landlock_hook`] captures it
/// and carries it across `clone()`.
#[derive(Debug)]
pub struct PreparedLandlock {
    fd: OwnedFd,
}

impl PreparedLandlock {
    /// Raw ruleset fd. Test-only helper for driving a raw `pre_exec`; the public API is
    /// [`install_landlock`] / [`landlock_hook`].
    #[cfg(test)]
    pub(crate) fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Parent-side: build a landlock ruleset from an [`AccessDecision`]. May allocate; does
/// not touch kernel state beyond the (cached) support probe and ruleset creation.
///
/// - **Broad** ([`ReadPolicy::Broad`]): grant `/` read+exec + each writable path full
///   access.
/// - **Narrow** ([`ReadPolicy::Narrow`]): grant only the read allowlist + writable full
///   access — `$HOME`/secrets are denied by default.
///
/// The writable set is merged with the always-included `baseline_writable` scratch/
/// devices (non-configurable; a landlocked program requires these to function). Apply the
/// result in the child via [`install_landlock`] (or use [`landlock_hook`] to compose
/// both).
pub fn prepare_landlock(decision: &AccessDecision) -> Result<PreparedLandlock> {
    ensure_supported()?;

    // Writable = the decision's set + the baseline every program needs, de-duped.
    let mut writable = decision.writable.clone();
    writable.extend(baseline_writable());
    writable.sort();
    writable.dedup();

    let mut grants: Vec<(PathBuf, Grant)> =
        writable.into_iter().map(|p| (p, Grant::Write)).collect();
    match &decision.read {
        ReadPolicy::Broad => grants.push((PathBuf::from("/"), Grant::Read)),
        ReadPolicy::Narrow { paths } => {
            for p in paths {
                grants.push((p.clone(), Grant::Read));
            }
            // Deliberately no `/` grant: anything not listed is unreadable.
        }
    }

    let fd = build_ruleset_from_grants(&grants)?;
    Ok(PreparedLandlock { fd })
}

/// Child-side: apply the prepared landlock domain to the current process.
///
/// Sets `PR_SET_NO_NEW_PRIVS` then calls `landlock_restrict_self(2)`. Async-signal-safe
/// (raw syscalls only — see `restrict_self_raw`); safe to call from a [`ChildSetup`]
/// hook or a raw `pre_exec`. Returning `Err` aborts the exec via the spawn error-pipe —
/// the fail-closed gate #2.
///
/// Keeps `NO_NEW_PRIVS` even though [`SeccompFilter::install`](crate::seccomp::SeccompFilter::install)
/// already sets it — required when seccomp is `Disabled`, and harmless otherwise.
pub fn install_landlock(prepared: &PreparedLandlock) -> Result<()> {
    restrict_self_raw(prepared.fd.as_raw_fd())
        .map_err(|e| SandboxError::new(ErrorKind::Landlock, e.to_string()))
}

/// Build a [`ChildSetup`] hook that applies an [`AccessDecision`] in the child.
///
/// The primary composition entry point: pass the result to
/// [`SpawnBuilder::child_setup`](crate::SpawnBuilder::child_setup). The returned hook
/// captures the [`PreparedLandlock`] (owning the ruleset fd) and calls
/// [`install_landlock`] post-seccomp, pre-exec.
///
/// Callers that drive their own `clone`/`pre_exec` pipeline may instead call
/// [`prepare_landlock`] + [`install_landlock`] directly.
pub fn landlock_hook(decision: &AccessDecision) -> Result<ChildSetup> {
    let prepared = prepare_landlock(decision)?;
    Ok(Box::new(move |_ctx: &ChildCtx| -> Result<()> {
        install_landlock(&prepared)
    }))
}

/// `pre_exec` body: apply `PR_SET_NO_NEW_PRIVS` then `landlock_restrict_self`.
///
/// The raw async-signal-safe core shared by [`install_landlock`]. Private — the public
/// surface is [`install_landlock`] / [`landlock_hook`]; the in-module tests reach this
/// directly via `use super::*` to drive a raw `pre_exec`.
///
/// # Safety
///
/// Issues only async-signal-safe `libc` syscalls; no Rust allocator, no locks. Safe to
/// call post-fork/pre-exec in a multithreaded process.
fn restrict_self_raw(ruleset_fd: RawFd) -> std::io::Result<()> {
    // SAFETY: both calls take well-typed args and issue a single raw syscall.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

// Process-wide cache of whether landlock is usable, probed once on first use. Failure
// here (unsupported kernel) is permanent for the process. Stored as a String because
// `SandboxError` is not `Clone`. Uses `std::result::Result` because `crate::Result` is
// shadowed by the `crate::error::Result` import above.
static SUPPORT: OnceLock<std::result::Result<(), String>> = OnceLock::new();

/// Probe landlock support exactly once (process-wide cached). The probe builds a trivial
/// ruleset with `CompatLevel::HardRequirement`; on an unsupported/disabled kernel this
/// errors and is cached so subsequent [`prepare_landlock`] calls fail fast with a clear
/// message instead of aborting every spawn.
///
/// `pub(crate)` rather than `pub`: the cache is process-global mutable state (an
/// implementation detail) that should not be triggered by external callers.
pub(crate) fn ensure_supported() -> Result<()> {
    let cached = SUPPORT.get_or_init(|| probe_support().map_err(|e| e.to_string()));
    match cached {
        Ok(()) => Ok(()),
        Err(msg) => Err(SandboxError::new(
            ErrorKind::Landlock,
            format!("landlock unavailable: {msg}"),
        )),
    }
}

/// The actual probe: build + create a minimal read-only ruleset. `create()` issues
/// `landlock_create_ruleset(2)`, surfacing `ENOSYS`/`EOPNOTSUPP` on an unsupported or
/// boot-disabled kernel.
fn probe_support() -> Result<()> {
    let abi = ABI::V1;
    let created = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(ll_error)?
        .create()
        .map_err(ll_error)?;
    drop(created);
    Ok(())
}

#[cfg(test)]
mod tests;
