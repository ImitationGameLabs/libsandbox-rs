//! Mount-namespace read-only holes — a child-side mechanism for carving a read-only
//! "hole" out of an otherwise writable tree.
//!
//! landlock provably cannot do this: its rules only *grant* access, never subtract, so
//! granting write on an ancestor covers every descendant (pinned by
//! `writable_ancestor_cannot_be_narrowed_to_readonly` in `src/landlock/tests.rs`). A
//! read-only hole under a writable ancestor must therefore be realized at the mount layer:
//! bind-mount the hole onto itself, then remount that bind read-only.
//!
//! # Mechanism & ordering invariant
//!
//! [`install_mount_holes`] does its own `unshare(CLONE_NEWUSER | CLONE_NEWNS)` and writes
//! the uid/gid maps, so it is a self-contained child-side step — it does **not** depend on
//! libsandbox's parent spawn protocol. It is meant to be called from a caller-driven
//! `pre_exec`. When composed with landlock and seccomp, the required order is
//!
//! ```text
//! mount-holes → landlock → seccomp
//! ```
//!
//! so landlock resolves against the post-remount view and seccomp is installed last.

#![cfg(target_os = "linux")]

use crate::error::{ErrorKind, Result, SandboxError};
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// Parent-side-prepared mount-hole setup: hole paths as `CString`s plus the uid/gid map
/// strings, ready for [`install_mount_holes`] with no allocation left for the child.
///
/// Mirrors [`crate::landlock::PreparedLandlock`] / the prepare→install split. Built by
/// [`prepare_mount_holes`]; the child consumes it via [`install_mount_holes`].
#[derive(Debug)]
pub struct PreparedMountHoles {
    holes: Vec<CString>,
    uid_map: CString,
    gid_map: CString,
}

/// Build the mount-hole setup parent-side. `CString` construction allocates, which is
/// forbidden inside `pre_exec`, so it happens here; the child only issues raw syscalls
/// over the prepared data.
///
/// `uid`/`gid` are mapped ns-id `0` → the real id (`"0 <uid> 1"`) so the exec'd process
/// owns its files/caches. `holes` are the canonical paths to bind+remount-ro.
///
/// Callers must ensure each hole **exists and is a directory** before the child runs
/// [`install_mount_holes`] — otherwise the bind fails with `ENOENT`. This function does
/// no filesystem work (it only builds strings).
pub fn prepare_mount_holes(holes: &[PathBuf], uid: u32, gid: u32) -> Result<PreparedMountHoles> {
    let mut c_holes = Vec::with_capacity(holes.len());
    for p in holes {
        // A path with an embedded NUL cannot be a valid mount target; reject rather than
        // silently skipping (a skipped hole is a silent privilege escalation).
        let c = CString::new(p.as_os_str().as_bytes()).map_err(|_| {
            SandboxError::new(
                ErrorKind::Mount,
                format!("readonly hole path has an embedded NUL: {}", p.display()),
            )
        })?;
        c_holes.push(c);
    }
    // "0 <outer> 1" maps ns id 0 to the real id; a single id, one-to-one. `format!`
    // allocates here (parent side) — fine; the child reuses the bytes as-is. A formatted
    // u32 cannot contain a NUL, so the `expect` is sound.
    let uid_map = CString::new(format!("0 {uid} 1")).expect("a formatted u32 cannot contain a NUL");
    let gid_map = CString::new(format!("0 {gid} 1")).expect("a formatted u32 cannot contain a NUL");
    Ok(PreparedMountHoles {
        holes: c_holes,
        uid_map,
        gid_map,
    })
}

/// `pre_exec` body: unshare user+mount namespaces, write uid/gid maps, then bind+
/// remount-ro each hole. Returns `Err` to abort the exec on any failure — the
/// fail-closed gate.
///
/// # Async-signal-safety
///
/// The **success path** issues only raw syscalls (`unshare`, `open`, `write`, `close`,
/// `mount`); no allocation, no locks — it is async-signal-safe. The **failure path** uses
/// `format!` (which allocates) to build the error context; the child then reports and
/// aborts. This is the same trade-off `exec_sandboxed` makes
/// (`src/process/child_setup.rs`): only `install_rlimits` and `SeccompFilter::install`
/// are certified async-signal-safe across both paths; the mount steps are accepted in the
/// `clone()`-child context. This function follows that precedent — it does **not** claim
/// to be async-signal-safe on the error path.
///
/// # Caller contract
///
/// The caller must ensure `prepared` was built parent-side by [`prepare_mount_holes`] and
/// that the current process has **not** already entered a user namespace (e.g. via
/// `CLONE_NEWUSER` from libsandbox's `SpawnBuilder`). A second `unshare(CLONE_NEWUSER)`
/// would nest namespaces and the `"0 <outer> 1"` map would resolve against the wrong
/// owning namespace. Intended for a fresh child.
///
/// When composing with seccomp, the profile must permit `unshare`/`mount`/`open`/`write`/
/// `close` during `pre_exec` — install mount-holes *before* seccomp.
///
/// # Limitation
///
/// The read-only remount is **non-recursive** (`MS_RDONLY | MS_BIND | MS_REMOUNT`, no
/// `MS_REC`): nested mounts *under* a hole are not made read-only. This matches the
/// reader-view use case (a hole is a workspace with no nested mounts). Do not "improve"
/// it to a recursive remount without revisiting the semantics.
pub fn install_mount_holes(prepared: &PreparedMountHoles) -> Result<()> {
    // SAFETY: only raw syscalls follow on the success path; no allocation, no locks. The
    // uid/gid maps and hole paths are pre-built parent-side.
    unsafe {
        // 1. New user + mount namespace. `CLONE_NEWUSER` grants `CAP_SYS_ADMIN` inside the
        //    new userns so the bind/remount below need no host root. The new mount ns is
        //    owned by this new user ns and therefore "less privileged" than the caller's,
        //    so the kernel demotes inherited shared mounts to slave — the per-hole
        //    bind/RO-remount below CANNOT propagate back to the host (mount_namespaces(7)
        //    NOTES). No explicit `mount("/", MS_REC|MS_PRIVATE)` is needed (that idiom is
        //    what a raw `CLONE_NEWNS` without `CLONE_NEWUSER` would require).
        if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
            return Err(mount_err("unshare(CLONE_NEWUSER|CLONE_NEWNS)"));
        }
        // 2. Map ns id 0 -> real uid/gid so the exec'd process runs as the user.
        //    `setgroups "deny"` MUST precede `gid_map` (the unprivileged gid_map rule).
        write_proc_file(b"/proc/self/setgroups\0", b"deny")?;
        write_proc_file(b"/proc/self/uid_map\0", prepared.uid_map.to_bytes())?;
        write_proc_file(b"/proc/self/gid_map\0", prepared.gid_map.to_bytes())?;
        // 3. Each hole: bind onto itself (making it an independent mount), then remount
        //    that bind read-only. `MS_BIND` is required when remounting a bind mount
        //    (mount(2)). The first bind is recursive (`MS_REC`) so a directory hole's
        //    subtree is bound; the RO remount is deliberately non-recursive (see Limitation).
        for hole in &prepared.holes {
            let target = hole.as_ptr();
            if libc::mount(
                target as *const libc::c_char,
                target as *const libc::c_char,
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            ) != 0
            {
                return Err(mount_err("bind hole"));
            }
            if libc::mount(
                target as *const libc::c_char,
                target as *const libc::c_char,
                std::ptr::null(),
                libc::MS_RDONLY | libc::MS_BIND | libc::MS_REMOUNT,
                std::ptr::null(),
            ) != 0
            {
                return Err(mount_err("remount hole read-only"));
            }
        }
    }
    Ok(())
}

/// Open `path` (a NUL-terminated byte literal) `O_WRONLY` and write `data` fully. Raw
/// syscalls only — async-signal-safe. Closes the fd on every path.
///
/// # Safety
///
/// `path` must be a NUL-terminated byte slice (a C string literal with a trailing `\0`).
unsafe fn write_proc_file(path: &[u8], data: &[u8]) -> Result<()> {
    // SAFETY: the caller guarantees `path` is a NUL-terminated byte slice; only raw
    // syscalls follow (open/write/close), no allocation.
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

/// Build a `Mount`-kinded [`SandboxError`] from `ctx` and the current `errno`. The
/// `format!` here allocates (failure path only) — see [`install_mount_holes`].
fn mount_err(ctx: &str) -> SandboxError {
    SandboxError::new(
        ErrorKind::Mount,
        format!("{ctx}: {}", io::Error::last_os_error()),
    )
}

#[cfg(test)]
mod tests {
    //! Drives the production `prepare_mount_holes` + `install_mount_holes` through a raw
    //! `std::process::Command::pre_exec` — deliberately NOT the full sandbox spawn path,
    //! so these tests stay independent of the `tokio` feature and exercise only the
    //! mount-hole mechanism (no landlock composed in).

    use super::*;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// `true` when unprivileged user namespaces are administratively disabled. Reads
    /// `/proc/sys/kernel/unprivileged_userns_clone`; "0" means disabled, absence means the
    /// kernel does not gate userns (assume permitted).
    fn userns_unavailable() -> bool {
        match std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
            Ok(s) => s.trim() == "0",
            Err(_) => false,
        }
    }

    /// A parent dir guaranteed outside the baseline writable set (`<repo>/target/tmp`),
    /// so a child path of it is genuinely host-writable and not merely a temp symlink.
    /// Returns `None` (and prints a visible skip) when `CARGO_TARGET_TMPDIR` is unset,
    /// rather than silently passing — so a missing harness var surfaces in the output.
    fn non_baseline_parent() -> Option<PathBuf> {
        match std::env::var_os("CARGO_TARGET_TMPDIR") {
            Some(v) => Some(PathBuf::from(v)),
            None => {
                eprintln!(
                    "skipped: CARGO_TARGET_TMPDIR is not set (run via `cargo test`); \
                     mount-hole test cannot place its tree outside the baseline writable set."
                );
                None
            }
        }
    }

    fn unique_dir(parent: &Path, label: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = parent.join(format!("libsandbox-holes-{label}-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Run `bash -c <script>` with `install_mount_holes` in `pre_exec`. The prepared holes
    /// are moved into the closure by value (`CString: Send + 'static`); `output()` blocks
    /// until the child exits, so the borrow outlives the spawn. Taking ownership (rather
    /// than a reference) keeps the soundness from depending on that blocking behavior.
    fn run_with_holes(prepared: PreparedMountHoles, script: &str) -> std::process::Output {
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg(script);
        // SAFETY: `install_mount_holes` issues only raw syscalls on its success path; the
        // prepared data is parent-built and not concurrently mutated.
        unsafe {
            cmd.pre_exec(move || {
                install_mount_holes(&prepared).map_err(|e| io::Error::other(e.to_string()))
            });
        }
        cmd.output().expect("spawn + wait should succeed")
    }

    /// The load-bearing acceptance test for the mount-ns read-only hole: when the hole
    /// sits *under* a writable ancestor (the case landlock provably cannot block — see
    /// `writable_ancestor_cannot_be_narrowed_to_readonly` in `src/landlock/tests.rs`), the
    /// mount-ns bind+remount-ro must block the write regardless. A writable sibling under
    /// the same ancestor serves as the positive control: if it stays writable, bash
    /// genuinely ran under the new namespaces (guarding against a false pass from a silent
    /// unshare/exec failure).
    #[test]
    fn readonly_hole_blocks_write_under_writable_ancestor() {
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

        let prepared = prepare_mount_holes(
            std::slice::from_ref(&hole),
            // SAFETY: getuid/getgid take no args and cannot fail.
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        )
        .expect("prepare succeeds");

        let hole_target = hole.join("f");
        let sib_target = sibling.join("f");
        let script = format!(
            "echo x > '{}' 2>/dev/null; echo \"hole_rc=$?\"; \
             echo x > '{}'; echo \"sib_rc=$?\"",
            hole_target.display(),
            sib_target.display(),
        );
        let output = run_with_holes(prepared, &script);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Positive control first: the sibling write MUST succeed. This confirms bash
        // actually ran under the new userns/mountns — without it, a silent unshare/exec
        // failure would make the hole assertion pass vacuously.
        assert!(
            stdout.contains("sib_rc=0"),
            "sibling write failed unexpectedly (bash may not have run under the new \
             namespaces); stdout={stdout}, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        // The claim: the hole write is blocked by the read-only remount (not hole_rc=0).
        assert!(
            !stdout.contains("hole_rc=0"),
            "hole write unexpectedly succeeded under a writable ancestor \
             (mount-ns read-only did not block); stdout={stdout}, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !hole_target.exists(),
            "the blocked hole write nonetheless created a file"
        );
    }
}
