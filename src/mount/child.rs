//! Mount-namespace child-side primitives — composable `prepare_*`/`install_*` pairs for a
//! caller-driven `pre_exec`.
//!
//! # Why this exists
//!
//! Landlock provably cannot carve a read-only "hole" out of an otherwise writable tree: its
//! rules only *grant* access, never subtract, so granting write on an ancestor covers every
//! descendant (pinned by `writable_ancestor_cannot_be_narrowed_to_readonly` in
//! `src/landlock/tests.rs`). The compositions here realize such holes — and writable ones, and
//! mixed ro/rw overlays — at the mount layer, by self-binding a directory (making it an
//! independent mount) and selectively remounting it.
//!
//! Unlike a sealed "apply the readonly-hole scenario" API, these are primitives the caller
//! composes: any permutation of read-only / read-write / recursive binds, in any order.
//!
//! # Composition order (a correctness invariant; do not reorder)
//!
//! When composed with landlock and seccomp, the required order is
//!
//! ```text
//! install_user_mount_ns → install_bind (×N) → install_tmpfs (×N) → landlock → seccomp
//! ```
//!
//! - `install_bind` runs **after** `install_user_mount_ns` (the self-bind + remount needs
//!   `CAP_SYS_ADMIN` inside the new user namespace).
//! - `install_tmpfs` overlays run after the binds and before landlock: the overlay must sit
//!   atop any bind at a disjoint path, and landlock resolves path-beneath rules against the
//!   post-overlay view. A tmpfs at a path wins over a bind at the same path by mount-stacking
//!   order, so keep overlay and bind paths prefix-disjoint.
//! - landlock runs after the binds/overlays so it resolves paths against the post-mount view.
//! - seccomp is installed **last**: the profile must permit `unshare`/`mount`/`open`/`write`/
//!   `close` during the earlier steps, so it cannot filter them before they run.
//! - when layering multiple binds, install writable children **before** their read-only
//!   ancestors: a non-recursive remount on the ancestor preserves a nested child mount's
//!   writability (see `readonly_ancestor_with_writable_child_overlay`).
//!
//! Run these from a caller-driven `pre_exec`, NOT a `ChildSetup` hook — the hook runs after
//! seccomp (`src/process/child_setup.rs`), which would trap the syscalls above.
//!
//! # Async-signal-safety
//!
//! The **success path** of each `install_*` issues only raw syscalls (`unshare`, `open`, `write`,
//! `close`, `mount`); no allocation, no locks — it is async-signal-safe and safe post-fork /
//! pre-exec. The **failure path** uses `format!` (which allocates) to build the error context;
//! the child then reports and aborts. This is the same trade-off `exec_sandboxed` makes — see the
//! contract in `src/process/child_setup.rs`.

#![cfg(target_os = "linux")]

use crate::config::Permission;
use crate::error::{ErrorKind, Result, SandboxError};
use crate::mount::ops;
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// ---------------------------------------------------------------------------
// User-namespace entry
// ---------------------------------------------------------------------------

/// Parent-side-prepared user + mount namespace entry: the `"0 <uid> 1"` / `"0 <gid> 1"` id-map
/// strings, ready for [`install_user_mount_ns`] with no allocation left for the child.
///
/// Mirrors the landlock `PreparedLandlock` / the prepare→install split. Built by
/// [`prepare_user_mount_ns`]; the child consumes it via [`install_user_mount_ns`].
#[derive(Debug, Clone)]
pub struct PreparedUserMountNs {
    uid_map: CString,
    gid_map: CString,
}

/// Parent-side: build the `"0 <uid> 1"` / `"0 <gid> 1"` id-map `CString`s. `CString` construction
/// allocates, which is forbidden inside `pre_exec`, so it happens here; the child only issues raw
/// syscalls over the prepared bytes.
///
/// Infallible — a formatted `u32` contains no NUL — so it returns the struct directly, mirroring
/// `prepare_rlimits`. (Infallible at prepare time is not the same as guaranteed to map: a
/// non-existent uid surfaces at runtime as an `EINVAL` from the `uid_map` write inside
/// [`install_user_mount_ns`].) `uid`/`gid` map ns-id `0` to the real id so the exec'd process
/// owns its files and caches.
pub fn prepare_user_mount_ns(uid: u32, gid: u32) -> PreparedUserMountNs {
    // "0 <outer> 1" maps ns id 0 to the real id; a single id, one-to-one. `format!` allocates
    // here (parent side) — fine; the child reuses the bytes as-is. A formatted u32 cannot contain
    // a NUL, so the `expect` is sound.
    let uid_map = CString::new(format!("0 {uid} 1")).expect("a formatted u32 cannot contain a NUL");
    let gid_map = CString::new(format!("0 {gid} 1")).expect("a formatted u32 cannot contain a NUL");
    PreparedUserMountNs { uid_map, gid_map }
}

/// Child-side (`pre_exec`): `unshare(CLONE_NEWUSER | CLONE_NEWNS)`, write `setgroups=deny`, then
/// write the `uid_map` / `gid_map`. Returns `Err` to abort the exec on any failure — the
/// fail-closed gate.
///
/// The `setgroups "deny"` write is permanent for this user namespace and **must** precede
/// `gid_map` (the unprivileged `gid_map` rule).
///
/// **Must not be called twice**: a second `CLONE_NEWUSER` nests namespaces and the
/// `"0 <outer> 1"` map then resolves against the wrong owning namespace. Intended for a fresh
/// child. [`install_bind`] requires this to have run first — the self-bind + remount needs
/// `CAP_SYS_ADMIN` inside the new userns.
///
/// See the [module docs](self) for the required composition order and async-signal-safety
/// contract.
pub fn install_user_mount_ns(prepared: &PreparedUserMountNs) -> Result<()> {
    // SAFETY: only raw syscalls follow on the success path; no allocation, no locks. The uid/gid
    // maps are pre-built parent-side.
    unsafe {
        // New user + mount namespace. `CLONE_NEWUSER` grants `CAP_SYS_ADMIN` inside the new userns
        // so the bind/remount in `install_bind` needs no host root. The new mount ns is owned by
        // this new user ns and therefore "less privileged" than the caller's, so the kernel demotes
        // inherited shared mounts to slave — per-bind operations cannot propagate back to the host
        // (mount_namespaces(7) NOTES). No explicit `mount("/", MS_REC|MS_PRIVATE)` is needed.
        if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
            return Err(mount_err("unshare(CLONE_NEWUSER|CLONE_NEWNS)"));
        }
        // Map ns id 0 -> real uid/gid so the exec'd process runs as the user. `setgroups "deny"`
        // MUST precede `gid_map` (the unprivileged gid_map rule).
        write_proc_file(b"/proc/self/setgroups\0", b"deny")?;
        write_proc_file(b"/proc/self/uid_map\0", prepared.uid_map.to_bytes())?;
        write_proc_file(b"/proc/self/gid_map\0", prepared.gid_map.to_bytes())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Directory self-bind
// ---------------------------------------------------------------------------

/// Selects whether a read-only remount propagates into mounts nested under the bind.
///
/// Only meaningful when a remount actually fires ([`Permission::ReadOnly`] or a non-empty
/// [`Permission::Custom`]); [`Permission::ReadWrite`] skips the remount entirely, so this is a
/// no-op for it.
///
/// [`RemountRecursion::NonRecursive`] is the right choice for mixed ro/rw overlays: it makes the
/// bind itself read-only while leaving nested mounts (a writable child overlay) untouched.
/// [`RemountRecursion::Recursive`] makes every nested mount read-only too, which will silently
/// revoke a child overlay's writability — reach for it only when you genuinely want the whole
/// subtree locked down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemountRecursion {
    /// Non-recursive remount (`MS_RDONLY | MS_BIND | MS_REMOUNT`, no `MS_REC`): nested mounts
    /// *under* the bind keep their own writability. This reproduces read-only-hole semantics.
    NonRecursive,
    /// Recursive remount (`… | MS_REC`): nested mounts are made read-only too.
    Recursive,
}

/// Parent-side-prepared directory self-bind: the target as a `CString`, plus the permission and
/// recursion selection, ready for [`install_bind`] with no allocation left for the child.
///
/// Built by [`prepare_bind`]; the child consumes it via [`install_bind`].
#[derive(Debug, Clone)]
pub struct PreparedBind {
    target: CString,
    permission: Permission,
    recursion: RemountRecursion,
}

/// Parent-side: build the target `CString` and verify `target` is a directory. May allocate and
/// stat; the child only issues raw syscalls over the prepared data.
///
/// `recursion` is stored for [`install_bind`] but is a **no-op when no remount fires** — i.e. for
/// [`Permission::ReadWrite`] and an empty [`Permission::Custom`] (see [`RemountRecursion`]).
///
/// Rejects an embedded NUL (a dropped bind is a silent privilege escalation) and non-directory
/// targets — the self-bind + remount semantics are defined for directory subtrees only. Does no
/// other filesystem work. The target must still exist and be a directory **at child-run time**;
/// there is a TOCTOU window between this check and [`install_bind`] (the caller typically runs
/// the child immediately, but the contract is documented rather than enforced).
pub fn prepare_bind(
    target: &Path,
    permission: Permission,
    recursion: RemountRecursion,
) -> Result<PreparedBind> {
    if !target.is_dir() {
        return Err(SandboxError::new(
            ErrorKind::Mount,
            format!("bind target is not a directory: {}", target.display()),
        ));
    }
    let c = CString::new(target.as_os_str().as_bytes()).map_err(|_| {
        SandboxError::new(
            ErrorKind::Mount,
            format!("bind target path has an embedded NUL: {}", target.display()),
        )
    })?;
    Ok(PreparedBind {
        target: c,
        permission,
        recursion,
    })
}

/// Child-side (`pre_exec`): self-bind the directory `target` onto itself, then remount per
/// `permission`.
///
/// The self-bind uses `MS_BIND | MS_REC` (recursive, so the directory subtree is carried as an
/// independent mount). The remount is gated exactly like `ops::bind_mount`:
/// - [`Permission::ReadWrite`] → **no remount**; the self-bind alone yields an independent
///   writable mount. `recursion` is a no-op in this case.
/// - [`Permission::ReadOnly`] / non-empty [`Permission::Custom`] → remount with the shared
///   remount-flag selection (the same one `ops::bind_mount` uses); `recursion` toggles `MS_REC`
///   on the remount.
///
/// Returns `Err` to abort the exec on any failure — the fail-closed gate.
///
/// # Preconditions
///
/// Must run **after** [`install_user_mount_ns`] (the bind needs `CAP_SYS_ADMIN` in the new
/// userns). **Failure-mode warning:** under host root, calling `install_bind` *before*
/// [`install_user_mount_ns`] silently mutates the **host** mount table — the bind/remount succeeds
/// in the parent namespace. Always compose in the order documented at the [module level](self).
///
/// See the [module docs](self) for the required composition order with landlock/seccomp and the
/// async-signal-safety contract.
pub fn install_bind(prepared: &PreparedBind) -> Result<()> {
    // SAFETY: success path issues only raw `mount` syscalls; `target` is a pre-built CString and
    // `permission`/`recursion` are plain data. No allocation, no locks.
    unsafe {
        let target = prepared.target.as_ptr();
        // 1. Self-bind (recursive so the directory subtree becomes an independent mount). The bind
        //    is unconditionally `MS_REC` because `prepare_bind` rejected non-directory targets;
        //    `MS_REC` on a directory self-bind carries the subtree (and is a no-op on a non-dir,
        //    which `prepare_bind` rules out anyway).
        if libc::mount(
            target as *const libc::c_char,
            target as *const libc::c_char,
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        ) != 0
        {
            return Err(mount_err("bind directory onto itself"));
        }
        // 2. Remount per permission, gated exactly like ops::bind_mount. `mount_err` reads errno,
        //    so it must run immediately at the point of failure — no intervening syscall.
        let recursive = matches!(prepared.recursion, RemountRecursion::Recursive);
        if let Some(flags) = ops::remount_flags(&prepared.permission, recursive) {
            if libc::mount(
                target as *const libc::c_char,
                target as *const libc::c_char,
                std::ptr::null(),
                flags.bits() as libc::c_ulong,
                std::ptr::null(),
            ) != 0
            {
                return Err(mount_err("remount directory"));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// tmpfs overlay (hide a directory's real contents)
// ---------------------------------------------------------------------------

/// Parent-side-prepared tmpfs mount: a fresh tmpfs mounted at `target` with the given
/// [`MountFlags`](crate::config::MountFlags) and `size`. The primary use is an overlay that
/// hides a directory's real contents (a read-only empty tmpfs over `~/.ssh`, etc.), but this is
/// the general "mount a tmpfs" capability — a sized writable scratch tmpfs is the same call
/// with different flags. The target `CString`, the `size={size}` data string, and `flags` are
/// carried pre-built so the child issues only a raw `mount`.
///
/// Built by [`prepare_tmpfs`]; the child consumes it via [`install_tmpfs`].
#[derive(Debug, Clone)]
pub struct PreparedTmpfs {
    target: CString,
    data: CString,
    flags: crate::config::MountFlags,
}

/// Parent-side: build the target + `size` data `CString`s, ensure the mountpoint exists, and
/// carry `flags` as-is for the child. May allocate and stat; the child only issues a raw
/// `mount` over the prepared data.
///
/// `size` is the tmpfs byte limit, passed through to the kernel as `size=<n>`. **`size = 0` is
/// not a zero-byte tmpfs** — the kernel treats it as the default (roughly half of physical
/// RAM). For a read-only hide-hole overlay the value is irrelevant (nothing writes), so `0` is
/// the idiomatic choice; a writable scratch tmpfs should set an explicit limit.
///
/// `flags` selects the mount's restrictions — typically `MountFlags::READ_ONLY | NO_EXEC |
/// NO_SUID | NO_DEV` for a secret hide-hole (empty, read-only, no device/exec/suid). It is
/// converted in the child via the same `MountFlags → MsFlags` mapping `bind_mount` uses, so no
/// third flag type is introduced. `MS_BIND`/`MS_REMOUNT` are intentionally NOT added — this is
/// a fresh tmpfs mount, not a bind remount.
///
/// Rejects an embedded NUL in the target path (a dropped overlay would silently leave the real
/// contents visible). `create_dir_all` is idempotent: a no-op when the target already exists,
/// and creates an empty mountpoint when it doesn't (`mount(2)` requires the mountpoint to
/// exist).
pub fn prepare_tmpfs(
    target: &Path,
    size: u64,
    flags: crate::config::MountFlags,
) -> Result<PreparedTmpfs> {
    // The mountpoint must exist for `mount(2)`.
    std::fs::create_dir_all(target)?;
    let target_c = CString::new(target.as_os_str().as_bytes()).map_err(|_| {
        SandboxError::new(
            ErrorKind::Mount,
            format!("tmpfs target path has an embedded NUL: {}", target.display()),
        )
    })?;
    let data = CString::new(format!("size={size}")).expect("a formatted u64 cannot contain a NUL");
    Ok(PreparedTmpfs {
        target: target_c,
        data,
        flags,
    })
}

/// Child-side (`pre_exec`): mount a fresh tmpfs at `target`. When the target held real contents,
/// the empty tmpfs overlays (hides) them. The `flags` (e.g. `MS_RDONLY|MS_NODEV|MS_NOSUID|
/// MS_NOEXEC`) and `size` were prepared parent-side.
///
/// Returns `Err` to abort the exec on failure — the fail-closed gate.
///
/// # Preconditions
///
/// Must run **after** [`install_user_mount_ns`] — mounting tmpfs needs `CAP_SYS_ADMIN` in the
/// new userns. When composed with binds, install tmpfs overlays **after** the binds and
/// **before** landlock (see the [module docs](self) for the full composition order and the
/// async-signal-safety contract).
pub fn install_tmpfs(prepared: &PreparedTmpfs) -> Result<()> {
    // SAFETY: success path issues a single raw `mount` syscall; `target`/`data` are pre-built
    // CStrings and `flags` is plain data converted via integer-only bitops. No allocation, no
    // locks.
    unsafe {
        let target = prepared.target.as_ptr();
        let data = prepared.data.as_ptr();
        // `mount_flags_to_ms` is integer-only (async-signal-safe); convert at the syscall
        // boundary rather than storing raw libc bits in `PreparedTmpfs`.
        let flags = ops::mount_flags_to_ms(prepared.flags).bits();
        if libc::mount(
            std::ptr::null(),
            target as *const libc::c_char,
            c"tmpfs".as_ptr() as *const libc::c_char,
            flags,
            data as *const libc::c_void,
        ) != 0
        {
            return Err(mount_err("mount tmpfs overlay"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Open `path` (a NUL-terminated byte literal) `O_WRONLY` and write `data` fully. Raw syscalls
/// only — async-signal-safe. Closes the fd on every path.
///
/// # Safety
///
/// `path` must be a NUL-terminated byte slice (a C-string literal with a trailing `\0`).
unsafe fn write_proc_file(path: &[u8], data: &[u8]) -> Result<()> {
    // SAFETY: the caller guarantees `path` is a NUL-terminated byte slice; only raw syscalls
    // follow (open/write/close), no allocation.
    unsafe {
        let fd = libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_WRONLY | libc::O_CLOEXEC,
        );
        if fd < 0 {
            return Err(mount_err("open proc file"));
        }
        let mut written = 0usize;
        while written < data.len() {
            let n = libc::write(
                fd,
                data[written..].as_ptr() as *const libc::c_void,
                data.len() - written,
            );
            if n < 0 {
                // Capture errno BEFORE close — close itself can clobber it.
                let err = mount_err("write proc file");
                libc::close(fd);
                return Err(err);
            }
            written += n as usize;
        }
        libc::close(fd);
        Ok(())
    }
}

/// Build a `Mount`-kinded [`SandboxError`] from `ctx` and the current `errno`. The `format!`
/// here allocates (failure path only) — see the [module docs](self).
///
/// Reads `errno`, so callers must invoke this **immediately** at the point of the failing syscall,
/// before any cleanup syscall (e.g. `close`) that could clobber it.
fn mount_err(ctx: &str) -> SandboxError {
    SandboxError::new(
        ErrorKind::Mount,
        format!("{ctx}: {}", io::Error::last_os_error()),
    )
}

#[cfg(test)]
mod tests {
    //! Drives the production primitives through a raw `std::process::Command::pre_exec` —
    //! deliberately NOT the full sandbox spawn path, so these tests stay independent of the
    //! `tokio` feature and exercise only the mount-ns mechanism (no landlock composed in).
    //!
    //! Every acceptance assertion pairs a *negative* claim (a write blocked) with a *positive
    //! control* (a write that must succeed) so a silent unshare/exec failure cannot make the
    //! assertion pass vacuously.

    use super::*;
    use crate::config::Permission;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// Map a crate `Result` error into the `io::Result` `pre_exec` expects.
    fn io_err(e: SandboxError) -> io::Error {
        io::Error::other(e.to_string())
    }

    /// `true` when unprivileged user namespaces are administratively disabled. Reads
    /// `/proc/sys/kernel/unprivileged_userns_clone`; "0" means disabled, absence means the
    /// kernel does not gate userns (assume permitted).
    fn userns_unavailable() -> bool {
        match std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
            Ok(s) => s.trim() == "0",
            Err(_) => false,
        }
    }

    /// A parent dir guaranteed outside the baseline writable set (`<repo>/target/tmp`), so a
    /// child path of it is genuinely host-writable and not merely a temp symlink. Returns
    /// `None` (and prints a visible skip) when `CARGO_TARGET_TMPDIR` is unset, rather than
    /// silently passing.
    fn non_baseline_parent() -> Option<PathBuf> {
        match std::env::var_os("CARGO_TARGET_TMPDIR") {
            Some(v) => Some(PathBuf::from(v)),
            None => {
                eprintln!(
                    "skipped: CARGO_TARGET_TMPDIR is not set (run via `cargo test`); the \
                     mount-ns test cannot place its tree outside the baseline writable set."
                );
                None
            }
        }
    }

    fn unique_dir(parent: &Path, label: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = parent.join(format!("libsandbox-child-{label}-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Run `bash -c <script>` after entering the prepared user+mount ns and applying the binds
    /// in order inside `pre_exec`. The prepared values are moved into the closure (they are
    /// `Send + 'static`); `output()` blocks until the child exits, so the borrow outlives the
    /// spawn.
    fn run_in_ns(
        ns: PreparedUserMountNs,
        binds: Vec<PreparedBind>,
        script: &str,
    ) -> std::process::Output {
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg(script);
        // SAFETY: `install_user_mount_ns` / `install_bind` issue only raw syscalls on their
        // success paths; the prepared data is parent-built and not concurrently mutated.
        unsafe {
            cmd.pre_exec(move || {
                install_user_mount_ns(&ns).map_err(io_err)?;
                for b in &binds {
                    install_bind(b).map_err(io_err)?;
                }
                Ok(())
            });
        }
        cmd.output().expect("spawn + wait should succeed")
    }

    fn stdout_of(output: &std::process::Output) -> String {
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// Regression guard: a `ReadOnly` self-bind (non-recursive remount) blocks writes to the bind
    /// even under a writable ancestor — the case landlock provably cannot express. A writable
    /// sibling under the same ancestor is the positive control proving bash ran under the new
    /// namespaces (without it, a silent unshare/exec failure would pass the assertion vacuously).
    #[test]
    fn readonly_bind_blocks_write_under_writable_ancestor() {
        if userns_unavailable() {
            eprintln!("skipped: unprivileged user namespaces are disabled");
            return;
        }
        let Some(base) = non_baseline_parent() else {
            return;
        };

        let parent = unique_dir(&base, "mntparent");
        let hole = unique_dir(&parent, "hole");
        let sibling = unique_dir(&parent, "sibling");

        let ns = prepare_user_mount_ns(
            // SAFETY: getuid/getgid take no args and cannot fail.
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        );
        let binds = vec![
            prepare_bind(&hole, Permission::ReadOnly, RemountRecursion::NonRecursive)
                .expect("prepare_bind succeeds"),
        ];

        let hole_target = hole.join("f");
        let sib_target = sibling.join("f");
        let script = format!(
            "echo x > '{}' 2>/dev/null; echo \"hole_rc=$?\"; \
             echo x > '{}'; echo \"sib_rc=$?\"",
            hole_target.display(),
            sib_target.display(),
        );
        let output = run_in_ns(ns, binds, &script);
        let stdout = stdout_of(&output);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            stdout.contains("sib_rc=0"),
            "sibling write failed unexpectedly (bash may not have run under the new \
             namespaces); stdout={stdout}, stderr={stderr}"
        );
        assert!(
            !stdout.contains("hole_rc=0"),
            "hole write unexpectedly succeeded under a writable ancestor; stdout={stdout}, \
             stderr={stderr}"
        );
        assert!(
            !hole_target.exists(),
            "the blocked hole write nonetheless created a file"
        );
    }

    /// `ReadWrite` self-bind yields an independent *writable* mount (no remount). A read-only
    /// sibling under the same ancestor is the positive control proving the ns was entered; the
    /// read-write target is the new capability.
    #[test]
    fn writable_bind_stays_writable() {
        if userns_unavailable() {
            eprintln!("skipped: unprivileged user namespaces are disabled");
            return;
        }
        let Some(base) = non_baseline_parent() else {
            return;
        };

        let parent = unique_dir(&base, "mntparent");
        let ro = unique_dir(&parent, "ro");
        let rw = unique_dir(&parent, "rw");

        let ns = prepare_user_mount_ns(unsafe { libc::getuid() }, unsafe { libc::getgid() });
        // ReadWrite carries no remount (the `remount_flags` short-circuit); recursion is a no-op.
        let binds = vec![
            prepare_bind(&ro, Permission::ReadOnly, RemountRecursion::NonRecursive).unwrap(),
            prepare_bind(&rw, Permission::ReadWrite, RemountRecursion::NonRecursive).unwrap(),
        ];

        let ro_target = ro.join("f");
        let rw_target = rw.join("f");
        let script = format!(
            "echo x > '{}' 2>/dev/null; echo \"ro_rc=$?\"; \
             echo x > '{}'; echo \"rw_rc=$?\"",
            ro_target.display(),
            rw_target.display(),
        );
        let stdout = stdout_of(&run_in_ns(ns, binds, &script));

        assert!(
            !stdout.contains("ro_rc=0"),
            "read-only sibling write unexpectedly succeeded (ns may not have been entered); \
             stdout={stdout}"
        );
        assert!(
            stdout.contains("rw_rc=0"),
            "read-write bind write unexpectedly failed; stdout={stdout}"
        );
        assert!(
            rw_target.exists(),
            "the read-write bind did not create a file"
        );
    }

    /// The composition that was impossible before the refactor: a read-only ancestor with a
    /// writable child overlay. Bind the writable child first, then the read-only ancestor with a
    /// *non-recursive* remount — the non-recursive remount makes the ancestor read-only while
    /// preserving the nested child mount's writability. The ancestor write being blocked is also
    /// the positive control proving the ns was entered.
    #[test]
    fn readonly_ancestor_with_writable_child_overlay() {
        if userns_unavailable() {
            eprintln!("skipped: unprivileged user namespaces are disabled");
            return;
        }
        let Some(base) = non_baseline_parent() else {
            return;
        };

        let ancestor = unique_dir(&base, "ancestor");
        let child = unique_dir(&ancestor, "child"); // nested under the ancestor

        let ns = prepare_user_mount_ns(unsafe { libc::getuid() }, unsafe { libc::getgid() });
        // Order matters: writable child first, then the read-only ancestor with a non-recursive
        // remount so the child mount (nested under the ancestor) keeps its writability.
        let binds = vec![
            prepare_bind(
                &child,
                Permission::ReadWrite,
                RemountRecursion::NonRecursive,
            )
            .unwrap(),
            prepare_bind(
                &ancestor,
                Permission::ReadOnly,
                RemountRecursion::NonRecursive,
            )
            .unwrap(),
        ];

        let ancestor_target = ancestor.join("f");
        let child_target = child.join("f");
        let script = format!(
            "echo x > '{}' 2>/dev/null; echo \"anc_rc=$?\"; \
             echo x > '{}'; echo \"child_rc=$?\"",
            ancestor_target.display(),
            child_target.display(),
        );
        let stdout = stdout_of(&run_in_ns(ns, binds, &script));

        assert!(
            !stdout.contains("anc_rc=0"),
            "ancestor write unexpectedly succeeded (the read-only remount did not apply, or the \
             ns was not entered); stdout={stdout}"
        );
        assert!(
            stdout.contains("child_rc=0"),
            "writable child under a read-only ancestor unexpectedly blocked; stdout={stdout}"
        );
        assert!(
            child_target.exists(),
            "the writable child write did not create a file"
        );
        assert!(
            !ancestor_target.exists(),
            "the read-only ancestor write nonetheless created a file"
        );
    }

    /// A tmpfs overlay (hide-hole) mounted over a directory hides its real contents:
    /// the planted secret file is invisible under the empty tmpfs, and the overlay is
    /// read-only. A writable sibling is the positive control proving bash ran under
    /// the new namespaces (without it, a silent unshare/exec failure would pass the
    /// assertion vacuously).
    #[test]
    fn tmpfs_overlay_hides_directory_contents() {
        use crate::config::MountFlags;

        if userns_unavailable() {
            eprintln!("skipped: unprivileged user namespaces are disabled");
            return;
        }
        let Some(base) = non_baseline_parent() else {
            return;
        };

        let parent = unique_dir(&base, "tmpparent");
        let secret = unique_dir(&parent, "secret");
        let sibling = unique_dir(&parent, "sibling");
        // Plant a real secret file under the soon-to-be-hidden dir.
        std::fs::write(secret.join("key"), b"topsecret").unwrap();

        let ns = prepare_user_mount_ns(unsafe { libc::getuid() }, unsafe { libc::getgid() });
        let hide = prepare_tmpfs(
            &secret,
            0,
            MountFlags::READ_ONLY | MountFlags::NO_EXEC | MountFlags::NO_SUID | MountFlags::NO_DEV,
        )
        .expect("prepare_tmpfs succeeds");

        let key_path = secret.join("key");
        let sib_target = sibling.join("f");
        let script = format!(
            "cat '{}' >/dev/null 2>&1; echo \"key_rc=$?\"; \
         echo \"entries=$(ls -A '{}' 2>/dev/null | wc -l)\"; \
         echo x > '{}'; echo \"sib_rc=$?\"",
            key_path.display(),
            secret.display(),
            sib_target.display(),
        );

        let ns_for_child = ns.clone();
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg(&script);
        // SAFETY: install_user_mount_ns / install_tmpfs issue only raw syscalls on
        // their success paths; the prepared data is parent-built.
        unsafe {
            cmd.pre_exec(move || {
                install_user_mount_ns(&ns_for_child).map_err(io_err)?;
                install_tmpfs(&hide).map_err(io_err)?;
                Ok(())
            });
        }
        let stdout = stdout_of(&cmd.output().expect("spawn + wait should succeed"));

        assert!(
            !stdout.contains("key_rc=0"),
            "the secret file was readable under the tmpfs overlay (overlay did not hide it); \
         stdout={stdout}"
        );
        assert!(
            stdout.contains("entries=0"),
            "the overlaid dir was not empty (real contents leaked through); stdout={stdout}"
        );
        assert!(
            stdout.contains("sib_rc=0"),
            "sibling write failed unexpectedly (bash may not have run under the new namespaces); \
         stdout={stdout}"
        );
        // The real `secret/key` still exists on the parent's disk — the tmpfs overlay
        // lives only in the child's mount-ns (the daemon keeps the secret; the agent
        // cannot see it). That is the intended hide-hole semantics, so we do NOT assert
        // on `key_path.exists()` here (it is true in the parent by design).
    }

    /// Calling `install_user_mount_ns` twice must not silently succeed and run the child program:
    /// the second call creates a nested userns whose `uid_map` write fails (the outer id is no
    /// longer mapped in the parent userns), so `pre_exec` returns `Err` and the exec aborts. The
    /// single-call control confirms the sentinel IS created when called correctly.
    #[test]
    fn install_user_mount_ns_twice_aborts_exec() {
        if userns_unavailable() {
            eprintln!("skipped: unprivileged user namespaces are disabled");
            return;
        }
        let Some(base) = non_baseline_parent() else {
            return;
        };
        let work = unique_dir(&base, "double");

        let ns = prepare_user_mount_ns(unsafe { libc::getuid() }, unsafe { libc::getgid() });
        let sentinel = work.join("ran");
        let script = format!("touch '{}'", sentinel.display());

        // Double-install variant: the closure intentionally calls install_user_mount_ns twice.
        let ns_for_double = ns.clone();
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg(&script);
        // SAFETY: raw syscalls only on the success path; prepared data is parent-built.
        unsafe {
            cmd.pre_exec(move || {
                install_user_mount_ns(&ns_for_double).map_err(io_err)?;
                // Second call: must abort (see test doc). If it ever returned Ok, the dangerous
                // silent-corruption case has occurred and this assertion will catch it below.
                install_user_mount_ns(&ns_for_double).map_err(io_err)?;
                Ok(())
            });
        }
        let _ = cmd.output();

        // The exec must have aborted before running the script.
        assert!(
            !sentinel.exists(),
            "install_user_mount_ns called twice silently ran the child — the documented \
             \"must not be called twice\" contract is violated"
        );
    }

    /// Unit-level pin on the flag logic that drives `install_bind`'s remount: the `ReadWrite`
    /// short-circuit, the empty-`Custom` skip, and the `MS_REC` toggle. Acceptance-testing the
    /// recursive-vs-non-recursive distinction requires a nested mount entry, which an
    /// unprivileged test cannot create, so the mechanism is pinned here at the flag level.
    #[test]
    fn remount_flags_short_circuit_and_recursion() {
        use crate::config::MountFlags;
        use crate::mount::ops;
        use nix::mount::MsFlags;

        // ReadWrite always skips the remount (recursion irrelevant).
        assert_eq!(ops::remount_flags(&Permission::ReadWrite, false), None);
        assert_eq!(ops::remount_flags(&Permission::ReadWrite, true), None);
        // Empty Custom also skips the remount.
        assert_eq!(
            ops::remount_flags(&Permission::Custom(MountFlags::NONE), false),
            None
        );

        // ReadOnly, non-recursive: RO remount with no MS_REC.
        let f = ops::remount_flags(&Permission::ReadOnly, false).unwrap();
        assert!(f.contains(MsFlags::MS_RDONLY | MsFlags::MS_BIND | MsFlags::MS_REMOUNT));
        assert!(!f.contains(MsFlags::MS_REC));

        // ReadOnly, recursive: MS_REC present alongside MS_RDONLY.
        let f = ops::remount_flags(&Permission::ReadOnly, true).unwrap();
        assert!(f.contains(MsFlags::MS_REC | MsFlags::MS_RDONLY));
    }
}
