//! Landlock filesystem-access enforcement — the mechanism half of a sandbox.
//!
//! Linux-only, behind the `landlock` feature. The [`prepare_landlock`] preset requires
//! **kernel ≥ 6.2 (landlock ABI V3)** — `Refer` (V2) is mandatory for cross-directory
//! `link`/`rename`, without which build tools fail mid-compile with `EXDEV`, and `Truncate`
//! (V3) closes the `ftruncate`/`O_TRUNC` gap. The preset deliberately stops at V3: handling
//! `IoctlDev` (V5) would deny device ioctls (`/dev/tty` terminal control) by default. The
//! [`build_ruleset`] mechanism follows whatever [`ABI`] the caller passes — V1 on older
//! kernels (at the cost of that `EXDEV`), or V5+ for callers that want `IoctlDev`
//! confinement and grant the needed devices themselves. This is **not** a full sandbox
//! — no network, resource, or seccomp isolation (those live in their own modules and are
//! composed by the caller). Given an [`AccessDecision`], landlock restricts a spawned
//! process so it may read per the decision's read policy and write only to the listed
//! paths.
//!
//! # Mechanism vs policy
//!
//! The module is split in two layers:
//! - **Mechanism floor** ([`build_ruleset`]): builds a ruleset from explicit
//!   `(path, access-mask)` rules. It owns exactly one invariant — a non-directory path
//!   must not carry directory-only access-rights — so directories, device files, and
//!   regular files may be freely mixed. Callers wanting full control (custom masks, their
//!   own baseline, no [`AccessDecision`]) start here.
//! - **Policy preset** ([`prepare_landlock`] + [`baseline_readable`] /
//!   [`baseline_writable`]): an opinionated mapping from [`AccessDecision`] onto the
//!   floor, plus opt-in baseline presets a caller composes itself. Neither baseline is
//!   forced; both are building blocks.
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
//! `ChildStage::Hook`. `Disabled` and `Permissive` are unaffected.
//!
//! # Fail-closed
//!
//! Two gates ensure a process never runs unrestricted by accident:
//! 1. [`build_ruleset`] (the floor; [`prepare_landlock`] inherits this by delegation)
//!    probes kernel support up front via `ensure_supported` (cached process-wide) and
//!    builds the ruleset with `CompatLevel::HardRequirement` — if the kernel lacks
//!    landlock (or it is disabled at boot), the build errors and the spawn is aborted.
//! 2. [`install_landlock`] runs `prctl(PR_SET_NO_NEW_PRIVS)` +
//!    `landlock_restrict_self(2)` in the child; if either fails it returns `Err`, which
//!    the spawn pipeline translates into a `ChildStage::Hook` abort.

#![cfg(all(target_os = "linux", feature = "landlock"))]

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use landlock::{
    Access, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
};

// Re-export the mask vocabulary so callers can compose raw `(path, mask)` rules for
// [`build_ruleset`] without depending on landlock / enumflags2 themselves.
pub use landlock::{AccessFs, BitFlags, ABI};

use crate::error::{ErrorKind, Result, SandboxError};
use crate::{ChildCtx, ChildSetup};

mod decision;

pub use decision::{AccessDecision, ReadPolicy};

/// A convenient writable-set **preset**: scratch dirs (`$TMPDIR` or `/tmp`, plus
/// `/var/tmp`) and the character devices a shell touches (`/dev/null` for redirects,
/// `/dev/tty`, etc.). Only paths that actually exist on the host are returned.
///
/// This is an **opt-in** building block, symmetric with [`baseline_readable`]: compose
/// it into [`AccessDecision::writable`] yourself (`writable.extend(baseline_writable())`)
/// when you want these defaults, or skip it and construct your own set entirely. Unlike a
/// forced merge, that keeps the writable input visible — to you and to tests.
///
/// The `/dev/*` device entries are character special files (non-directories). They are
/// safe to pass to [`build_ruleset`] precisely because it narrows any non-directory path
/// to file-level rights (the file-type invariant it owns). A caller that bypasses
/// [`build_ruleset`] and hand-rolls landlock rules with directory-only bits on these
/// devices re-hits the `PathBeneathError::DirectoryAccess` rejection.
pub fn baseline_writable() -> Vec<PathBuf> {
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

/// A convenient read-allowlist **preset**: system paths a narrow-read process needs to
/// read+execute to function — the program itself, coreutils, shared libs, the dynamic
/// linker, procfs/sysfs, and devices. Deliberately EXCLUDES `/etc` and `$HOME` — those
/// are where secrets live (`/etc/secrets`, `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config`
/// tokens), so a narrow-read process gets clean zero-access to them.
///
/// Opt-in and composable, like [`baseline_writable`]: the caller assembles this with the
/// workspace to form the narrow read allowlist (see [`ReadPolicy::Narrow`]). Only paths
/// that exist on the host are returned (landlock requires it).
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

/// Flatten any landlock-crate error into a [`SandboxError`] classified as
/// [`ErrorKind::Landlock`] (carries its `Display`).
fn ll_error<E: std::error::Error + Send + Sync + 'static>(e: E) -> SandboxError {
    SandboxError::new(ErrorKind::Landlock, e.to_string())
}

/// Wrap a ruleset-creation error (`handle_access` / `create`) with the requested
/// [`ABI`]. On a too-old kernel landlock-rs returns a raw bitmask dump (e.g.
/// `partially incompatible access-rights: Refer`); this rewrites it into an actionable
/// message naming the requested ABI. Abi-neutral for any caller-chosen ABI, except it
/// appends the preset's kernel floor when `abi == REQUIRED_ABI` (the common path) — see
/// the conditional below. Scoped to the creation phase — per-rule `add_rule` errors keep
/// their own (path-specific) context via [`ll_error`].
fn abi_ctx_err<E: std::error::Error + Send + Sync + 'static>(abi: ABI, e: E) -> SandboxError {
    // Enrich with the preset's kernel floor only on the preset path (abi == REQUIRED_ABI);
    // for any other caller-chosen ABI the message stays neutral — the mechanism does not
    // own a kernel-version table for arbitrary ABIs.
    let floor = if abi == REQUIRED_ABI {
        format!(" (the prepare_landlock preset requires kernel >= {REQUIRED_ABI_KERNEL})")
    } else {
        String::new()
    };
    SandboxError::new(
        ErrorKind::Landlock,
        format!(
            "failed to create landlock ruleset at ABI {abi:?}: the running kernel's landlock ABI \
             does not support it{floor}: {e}"
        ),
    )
}

/// Narrow `desired` to the access-rights landlock will accept for `path`'s file type —
/// the one invariant the mechanism owns.
///
/// A non-directory fd (character/block device, regular file, fifo, socket, symlink, ...)
/// must drop the directory-only bits (`ReadDir` / `Make*` / `Remove*`), else `add_rule`
/// rejects the whole ruleset with `PathBeneathError::DirectoryAccess`. This is the root
/// cause of the device-file bug (`/dev/null` granted directory bits), fixed once here for
/// every non-directory file type.
///
/// `from_file(abi)` (rather than a hardcoded bit set) is `from_all(abi) & ACCESS_FILE`,
/// so it tracks the requested [`ABI`] and drops exactly the directory-only bits — never a
/// file-applicable bit the caller asked for (no silent under-grant).
///
/// Pure: no kernel, no fd — unit-testable without landlock support.
fn legal_mask(desired: BitFlags<AccessFs>, path: &Path, abi: ABI) -> BitFlags<AccessFs> {
    if path.is_dir() {
        desired
    } else {
        desired & AccessFs::from_file(abi)
    }
}

/// Mechanism floor: build a ruleset from explicit `(path, desired-mask)` rules at a
/// caller-chosen [`ABI`].
///
/// The caller controls two things:
/// - **`abi`** — the ruleset's handled-access *universe* (`from_all(abi)`): the set of
///   rights this domain can possibly grant. Each rule's mask below must be a subset of
///   it; a mask carrying a bit `abi` does not handle surfaces as an `UnhandledAccess`
///   `add_rule` error.
/// - **`rules`** — exactly what is granted (including `/`) via raw [`AccessFs`] masks
///   (e.g. [`AccessFs::from_read`] for a read-only rule, [`AccessFs::from_all`] for full
///   read+write). [`prepare_landlock`] is the opinionated policy built on top of this;
///   callers wanting full control (custom masks, their own baseline, no
///   [`AccessDecision`]) call this directly.
///
/// `abi` is a re-exported `landlock::ABI` (`#[non_exhaustive]`, grows over time);
/// [`prepare_landlock`] / [`REQUIRED_ABI`] is the version-stable entry point.
///
/// Owns the file-type invariant: non-directory paths are automatically narrowed to
/// file-level rights, so directories, device files, and regular files may be freely
/// mixed without the caller branching on file type. Non-existent paths are skipped (a
/// path may have been removed after it was added); duplicate paths are skipped too, with
/// the first mask winning. `HardRequirement` fails closed on a kernel that does not
/// support `abi` — gate #1.
///
/// # ABI
///
/// Each tier adds access rights cumulatively (kernel versions per the landlock-rs `ABI`
/// enum; V4/V6/V7 add **no** `AccessFs` right over their predecessor — their new features
/// are non-filesystem, which a pure-FS ruleset does not handle):
///
/// | ABI | Kernel | Adds (`AccessFs`, cumulative) |
/// |-----|--------|-------------------------------|
/// | V1  | 5.13   | base filesystem rights |
/// | V2  | 5.19   | `Refer` (cross-directory `link`/`rename`) |
/// | V3  | 6.2    | `Truncate` |
/// | V4  | 6.7    | *(no new `AccessFs` right)* |
/// | V5  | 6.10   | `IoctlDev` |
/// | V6  | 6.12   | *(no new `AccessFs` right)* |
/// | V7  | 6.15   | *(no new `AccessFs` right)* |
///
/// `Refer` is special: a ruleset that does **not** handle it (i.e. `abi` < V2) makes
/// cross-directory `link`/`rename`/`renameat2` return **`EXDEV`** — not permitted, and
/// not `EACCES`. By contrast, `Truncate`/`IoctlDev` *are* genuinely unrestricted when
/// unhandled (the domain simply does not confine them) — but `IoctlDev` in particular is
/// a footgun as a default: handling it makes device ioctls deny-by-default, so
/// [`prepare_landlock`] stops at V3 and leaves `IoctlDev` to callers who grant the needed
/// devices (`/dev/tty`, …) themselves.
///
/// # Warning
///
/// [`ABI::V1`] reintroduces the `EXDEV` failure: build tools (cargo, rustc, ninja, make)
/// emit `os error 18` mid-compile on any cross-directory hardlink/rename. The preset floor
/// is [`REQUIRED_ABI`] (V3); pass `ABI::V1` (the escape-hatch) only when the workload
/// provably never crosses directories.
pub fn build_ruleset(
    abi: ABI,
    rules: &[(PathBuf, BitFlags<AccessFs>)],
) -> Result<PreparedLandlock> {
    ensure_supported()?;

    // Handled-access scope for the ruleset (the universe of rights this domain can
    // grant), not a per-rule mask — each rule carries its own mask below.
    let full = AccessFs::from_all(abi);

    let mut created = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(full)
        .map_err(|e| abi_ctx_err(abi, e))?
        .create()
        .map_err(|e| abi_ctx_err(abi, e))?;
    let mut seen: std::collections::HashSet<&Path> = std::collections::HashSet::new();
    for (path, desired) in rules {
        // `exists()` must run before `legal_mask`: it rejects dangling symlinks and
        // missing paths so the mask decision is never made for an absent target. (A
        // dir→file swap between `is_dir` here and landlock's `fstat` on the opened fd is
        // a TOCTOU window only a concurrent *host* process can race; the sandboxed child
        // cannot, running as it does after `restrict_self`.)
        if !path.exists() || !seen.insert(path.as_path()) {
            continue;
        }
        let mask = legal_mask(*desired, path, abi);
        created = created
            .add_rule(PathBeneath::new(PathFd::new(path).map_err(ll_error)?, mask))
            .map_err(ll_error)?;
    }

    // `RulesetCreated` keeps its fd private; the only way out is clone-then-consume.
    let cloned = created.try_clone().map_err(ll_error)?;
    let fd_opt: Option<OwnedFd> = cloned.into();
    let fd = fd_opt.ok_or_else(|| SandboxError::new(ErrorKind::Landlock, "ruleset has no fd"))?;
    set_cloexec(&fd)?;
    Ok(PreparedLandlock { fd })
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

/// The landlock [`ABI`] the [`prepare_landlock`] preset requires.
///
/// Pinned to [`ABI::V3`] (kernel ≥ 6.2): `Refer` (V2) is the floor for any real workload —
/// without it cross-directory `link`/`rename` are rejected with `EXDEV` and build tools
/// (cargo, rustc, …) crash mid-compile — and `Truncate` (V3) closes the `ftruncate` /
/// `O_TRUNC` gap. The preset stops at V3 rather than going higher because handling
/// `IoctlDev` (V5) would deny device ioctls (`/dev/tty` terminal control) unless each
/// device is granted explicitly; callers who want that confinement pass `ABI::V5` (or
/// higher) to [`build_ruleset`] directly and grant the devices themselves. Exposed so
/// callers driving [`build_ruleset`] can stay in lockstep with the preset by referencing
/// this constant rather than hardcoding `ABI::V3`.
///
/// Bumping this is a coordinated change: the **runtime** kernel-floor string is centralized
/// in `REQUIRED_ABI_KERNEL` (interpolated by `abi_ctx_err`, test-guarded), but the **prose**
/// "6.2" / "V3" mentions in the module/README/Cargo.toml docs are hand-maintained and
/// unguarded — grep for them when bumping.
pub const REQUIRED_ABI: ABI = ABI::V3;

/// Kernel floor for [`REQUIRED_ABI`] (`ABI::V3` -> Linux 6.2). The single source for this
/// version string: [`abi_ctx_err`] interpolates it, and a unit test asserts the
/// interpolation stays in lockstep. There is no public `ABI` -> kernel-version table in
/// landlock-rs to derive this from, so it is a manual const — bump it together with
/// [`REQUIRED_ABI`].
const REQUIRED_ABI_KERNEL: &str = "6.2";

/// Parent-side: build a landlock ruleset from an [`AccessDecision`]. May allocate; does
/// not touch kernel state beyond the (cached) support probe and ruleset creation.
///
/// - **Broad** ([`ReadPolicy::Broad`]): grant `/` read+exec + each writable path full
///   access.
/// - **Narrow** ([`ReadPolicy::Narrow`]): grant only the read allowlist + writable full
///   access — `$HOME`/secrets are denied by default.
///
/// `decision.writable` is granted **verbatim** — no baseline is silently merged. Compose
/// [`baseline_writable`] into it yourself (`writable.extend(baseline_writable())`) when
/// you want the scratch/device defaults; this mirrors how [`ReadPolicy::Narrow`] requires
/// composing [`baseline_readable`] into the read allowlist. Keeping the writable input
/// literal makes it a visible decision (and a visible test dimension) rather than an
/// invisible one. Apply the result in the child via [`install_landlock`] (or use
/// [`landlock_hook`] to compose both).
///
/// Pinned to [`REQUIRED_ABI`] (V3); see its doc for the V3-vs-`IoctlDev` rationale. A
/// too-old kernel fails loud at ruleset creation.
pub fn prepare_landlock(decision: &AccessDecision) -> Result<PreparedLandlock> {
    let abi = REQUIRED_ABI;
    let read = AccessFs::from_read(abi); // Execute is included for every supported ABI
                                         // Per-rule mask granted to each writable path (narrowed to file-level rights by the
                                         // floor for non-directories). Distinct from build_ruleset's handled-access scope.
    let full = AccessFs::from_all(abi);

    let mut rules: Vec<(PathBuf, BitFlags<AccessFs>)> = Vec::new();
    // writable is taken verbatim — caller composes `baseline_writable()` if it wants it.
    for p in &decision.writable {
        rules.push((p.clone(), full));
    }
    match &decision.read {
        ReadPolicy::Broad => rules.push((PathBuf::from("/"), read)),
        ReadPolicy::Narrow { paths } => {
            for p in paths {
                rules.push((p.clone(), read));
            }
            // Deliberately no `/` grant: anything not listed is unreadable.
        }
    }

    build_ruleset(abi, &rules)
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
/// V1 ruleset with `CompatLevel::HardRequirement`; on a kernel without landlock (or with
/// it boot-disabled) this errors and is cached so subsequent calls fail fast instead of
/// aborting every spawn.
///
/// This is a **presence** gate only ("is landlock usable at all"), not an ABI gate: a V1
/// kernel passes it, then the per-request ABI floor in [`build_ruleset`] (via
/// `HardRequirement` + the caller's `abi`) catches a too-low ABI with a clear message.
/// Two layers, both fail-closed.
///
/// `pub(crate)` rather than `pub`: the cache is process-global mutable state (an
/// implementation detail) that should not be triggered by external callers.
pub(crate) fn ensure_supported() -> Result<()> {
    let cached = SUPPORT.get_or_init(|| probe_support().map_err(|e| e.to_string()));
    match cached {
        Ok(()) => Ok(()),
        Err(msg) => Err(SandboxError::new(
            ErrorKind::Landlock,
            format!("unavailable: {msg}"),
        )),
    }
}

/// The actual probe: build + create a minimal read-only ruleset. `create()` issues
/// `landlock_create_ruleset(2)`, surfacing `ENOSYS`/`EOPNOTSUPP` on an unsupported or
/// boot-disabled kernel.
///
/// Intentionally `ABI::V1`: this is a presence check, not an ABI check. Bumping it to
/// the preset's `REQUIRED_ABI` would re-couple the presence gate to one policy and make
/// a legitimate `build_ruleset(ABI::V1, …)` escape-hatch call fail here for the wrong
/// reason. The ABI floor is enforced per-request in [`build_ruleset`].
fn probe_support() -> Result<()> {
    // Presence-only: V1 is the cheapest "is landlock here?" test.
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
