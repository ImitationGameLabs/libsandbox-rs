//! Landlock mechanism tests.
//!
//! Drives the production `prepare_landlock` + `restrict_self_raw` (or [`build_ruleset`]
//! for the limitation probes) through a raw `std::process::Command::pre_exec` —
//! deliberately NOT the full sandbox spawn path, so these tests stay independent of the
//! `tokio` feature and exercise only landlock.

use super::*;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

/// Landlock may be unavailable (old kernel, CI without it, boot-disabled); a test calls
/// this and returns early (skip) when so, rather than failing. The skip is logged so a
/// vacuous green run is visible in CI output — but note the *primary* regression gates
/// live in [`legal_mask`]-level unit tests, which run with no kernel and never skip.
fn skip_if_unsupported() -> bool {
    if ensure_supported().is_err() {
        eprintln!("skipped: landlock unsupported on this host");
        true
    } else {
        false
    }
}

/// The running kernel's highest supported landlock ABI tier (1-based), or `None` if the
/// probe fails. [`skip_if_unsupported`] is a *presence* gate (passes on any ABI >= 1); this
/// is the *tier* gate some tests need on top of it. Issues the raw
/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` query, which the
/// kernel answers with the highest supported ABI number (0/negative = unsupported).
///
/// `LANDLOCK_CREATE_RULESET_VERSION` is not in the `libc` crate, so its kernel UAPI value
/// (`1`) is mirrored here. landlock-rs exposes no public ABI probe (`ABI::current` / `uapi`
/// are private), so the raw syscall is the only path.
fn host_landlock_abi() -> Option<u32> {
    // Mirrors the kernel UAPI flag (not in libc): queries the highest supported ABI.
    const LANDLOCK_CREATE_RULESET_VERSION: u64 = 1;
    // SAFETY: a pure query — NULL attr, zero size, the version flag; no pointers read.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0u64,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi >= 1 {
        Some(abi as u32)
    } else {
        None
    }
}

/// Skip (returning `true`) when the host's landlock ABI is below `required` (1-based tier).
/// Compose after [`skip_if_unsupported`]: presence first, then the tier floor. Logs the
/// skip so a host that legitimately meets the crate floor but is below the test's tier
/// (e.g. kernel 6.2 ABI V3 for a V5-needing test) is visible, not a red CI failure.
fn skip_if_abi_below(required: u32) -> bool {
    match host_landlock_abi() {
        Some(host) if host >= required => false,
        Some(host) => {
            eprintln!(
                "skipped: host landlock ABI V{host} is below the V{required} tier this test exercises"
            );
            true
        }
        None => {
            eprintln!("skipped: could not probe the host landlock ABI");
            true
        }
    }
}

/// A parent dir guaranteed *outside* the baseline writable set (`$TMPDIR` / `/tmp` /
/// `/var/tmp`), so a child path of it is genuinely write-denied by landlock and not
/// merely unwritable on the host. `CARGO_TARGET_TMPDIR` (`<repo>/target/tmp`) is set by
/// `cargo test` and is distinct from [`std::env::temp_dir`].
///
/// Returns `None` (and prints a visible skip line) when `CARGO_TARGET_TMPDIR` is unset,
/// rather than silently passing — so a missing test harness var surfaces in the output.
fn non_baseline_parent() -> Option<PathBuf> {
    match std::env::var_os("CARGO_TARGET_TMPDIR") {
        Some(v) => Some(PathBuf::from(v)),
        None => {
            eprintln!(
                "skipped: CARGO_TARGET_TMPDIR is not set (run via `cargo test`); \
                 landlock test cannot place its secret outside the baseline writable set."
            );
            None
        }
    }
}

fn unique_dir(parent: &Path, label: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = parent.join(format!("libsandbox-landlock-{label}-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `bash -c <script>` under the landlock domain derived from `decision`. The ruleset
/// is built via the production [`prepare_landlock`]; `restrict_self_raw` runs in
/// `pre_exec`. The prepared fd is held alive across `output()` (which spawns + waits).
fn run_under_decision(decision: &AccessDecision, script: &str) -> std::process::Output {
    let prepared =
        prepare_landlock(decision).expect("prepare_landlock should succeed on a supported kernel");
    let raw = prepared.raw_fd();
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(script).env("LC_ALL", "C");
    // SAFETY: `restrict_self_raw` issues only async-signal-safe raw syscalls.
    unsafe {
        cmd.pre_exec(move || restrict_self_raw(raw));
    }
    cmd.output().expect("spawn + wait should succeed")
}

/// Run `bash -c <script>` under a ruleset built from explicit `(path, mask)` rules (via
/// the production [`build_ruleset`]) at a given [`ABI`]. Used by the limitation probes and
/// the cross-directory gates that need raw control over the granted masks / the ABI tier.
fn run_under_rules(
    abi: ABI,
    rules: &[(&Path, BitFlags<AccessFs>)],
    script: &str,
) -> std::process::Output {
    let owned: Vec<(PathBuf, BitFlags<AccessFs>)> =
        rules.iter().map(|(p, m)| (p.to_path_buf(), *m)).collect();
    let prepared =
        build_ruleset(abi, &owned).expect("ruleset build should succeed on a supported kernel");
    let raw = prepared.raw_fd();
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(script).env("LC_ALL", "C");
    // SAFETY: `restrict_self_raw` issues only async-signal-safe raw syscalls.
    unsafe {
        cmd.pre_exec(move || restrict_self_raw(raw));
    }
    cmd.output().expect("spawn + wait should succeed")
}

#[test]
fn write_outside_writable_is_denied() {
    if skip_if_unsupported() {
        return;
    }
    let Some(parent) = non_baseline_parent() else {
        return;
    };
    let allowed = unique_dir(&parent, "allowed");
    let outside = unique_dir(&parent, "outside"); // host-writable, NOT in writable set

    let target = outside.join("f");
    let decision = AccessDecision {
        read: ReadPolicy::Broad,
        writable: vec![allowed.clone()],
    };
    let output = run_under_decision(&decision, &format!("echo x > '{}'", target.display()));

    // Without landlock the write would succeed (outside is host-writable); with landlock
    // it must be denied (EACCES → non-zero exit).
    assert!(
        !output.status.success(),
        "write outside writable unexpectedly succeeded; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !target.exists(),
        "the denied write nonetheless created the file"
    );
}

#[test]
fn write_inside_writable_succeeds() {
    if skip_if_unsupported() {
        return;
    }
    let Some(parent) = non_baseline_parent() else {
        return;
    };
    let allowed = unique_dir(&parent, "allowed");

    let target = allowed.join("f");
    let decision = AccessDecision {
        read: ReadPolicy::Broad,
        writable: vec![allowed.clone()],
    };
    let output = run_under_decision(&decision, &format!("echo x > '{}'", target.display()));

    assert!(output.status.success(), "write inside writable failed");
    assert!(target.exists(), "the allowed write did not create the file");
}

#[test]
fn build_ruleset_succeeds_when_supported() {
    if skip_if_unsupported() {
        return;
    }
    let dir = std::env::temp_dir();
    build_ruleset(REQUIRED_ABI, &[(dir, AccessFs::from_all(REQUIRED_ABI))])
        .expect("ruleset build should succeed on a supported kernel");
}

// -- empirical probes of landlock's exclude limitation --
//
// These two tests pin down the design constraint behind the writable-set model: landlock
// CANNOT carve a read-only "hole" out of a writable tree (rules only grant; they never
// subtract). Read-only holes must therefore be realized via the mount layer
// (`FilesystemConfig` + `Permission::ReadOnly`), not landlock — see `decision.rs`.

/// **Limitation:** granting write on a parent makes the whole subtree writable, and
/// adding a read-only rule on a child does NOT carve it back out (rules only grant; they
/// cannot subtract). The write to the "hole" therefore succeeds despite the read-only
/// rule — proving a read-only hole inside a writable tree is impossible in a single
/// landlock ruleset.
#[test]
fn writable_ancestor_cannot_be_narrowed_to_readonly() {
    if skip_if_unsupported() {
        return;
    }
    let Some(parent) = non_baseline_parent() else {
        return;
    };
    let root = unique_dir(&parent, "root");
    let hole = unique_dir(&root, "hole"); // host-writable subdir

    // Attempt the carve: write on root, PLUS a read-only rule on the hole.
    let rules: &[(&Path, BitFlags<AccessFs>)] = &[
        (Path::new("/"), AccessFs::from_read(REQUIRED_ABI)),
        (&root, AccessFs::from_all(REQUIRED_ABI)),
        (&hole, AccessFs::from_read(REQUIRED_ABI)), // attempted read-only override — no effect
    ];
    let target = hole.join("f");
    let output = run_under_rules(
        REQUIRED_ABI,
        rules,
        &format!("echo x > '{}'", target.display()),
    );

    // The carve FAILS: root's recursive write grant covers the hole, and the read-only
    // rule can only grant read, not deny write. So writing succeeds.
    assert!(
        output.status.success(),
        "expected the hole to remain writable (landlock cannot narrow a writable ancestor); \
         stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(target.exists(), "the write should have created the file");
}

/// **Workaround:** DON'T grant the parent; grant its children individually, omitting the
/// hole. The hole then gets no write grant → read-only by default-deny — while a granted
/// sibling stays writable. This is how an "exclude" model is realized within landlock's
/// allowlist (the complement-enumeration strategy).
#[test]
fn hole_via_complement_enumeration_is_readonly() {
    if skip_if_unsupported() {
        return;
    }
    let Some(parent) = non_baseline_parent() else {
        return;
    };
    let root = unique_dir(&parent, "root");
    let sibling = unique_dir(&root, "sibling");
    let hole = unique_dir(&root, "hole"); // host-writable, but will be ungranted

    // Grant read on / (so bash + libs load) and write on the sibling ONLY. Deliberately
    // do NOT grant root (it would cover the hole) or the hole.
    let rules: &[(&Path, BitFlags<AccessFs>)] = &[
        (Path::new("/"), AccessFs::from_read(REQUIRED_ABI)),
        (&sibling, AccessFs::from_all(REQUIRED_ABI)),
    ];

    // The granted sibling is writable.
    let sib_target = sibling.join("f");
    let out = run_under_rules(
        REQUIRED_ABI,
        rules,
        &format!("echo x > '{}'", sib_target.display()),
    );
    assert!(
        out.status.success() && sib_target.exists(),
        "sibling should be writable; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The ungranted hole is read-only (no write grant, and root is not granted so it
    // cannot cover the hole).
    let hole_target = hole.join("f");
    let out = run_under_rules(
        REQUIRED_ABI,
        rules,
        &format!("echo x > '{}'", hole_target.display()),
    );
    assert!(
        !out.status.success(),
        "hole should be read-only (complement enumeration); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !hole_target.exists(),
        "the denied write nonetheless created the file"
    );
}

/// **Narrow read:** only the workspace + system dirs are granted read; anything else
/// (here a "secret" dir outside both) is denied by default. This is the zero-access-to-
/// unlisted property that lets a read-restricted process avoid touching `$HOME`/secrets.
#[test]
fn narrow_read_denies_paths_outside_allowlist() {
    if skip_if_unsupported() {
        return;
    }
    let Some(base) = non_baseline_parent() else {
        return;
    };
    let workspace = unique_dir(&base, "narrowws");
    let secret = unique_dir(&base, "narrowsecret"); // outside workspace + baseline_readable
    std::fs::write(workspace.join("readable"), b"ok").unwrap();
    std::fs::write(secret.join("secret"), b"key").unwrap();

    let mut paths = vec![workspace.clone()];
    paths.extend(baseline_readable());
    let decision = AccessDecision {
        read: ReadPolicy::Narrow { paths },
        writable: vec![workspace.clone()],
    };

    let output = run_under_decision(
        &decision,
        &format!(
            "cat '{}' 2>/dev/null; echo \"ws_rc=$?\"; \
             cat '{}' 2>/dev/null; echo \"secret_rc=$?\"",
            workspace.join("readable").display(),
            secret.join("secret").display(),
        ),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The workspace (in the allowlist) is readable; the secret (not in it) is denied by
    // default — proving the zero-access-to-unlisted property.
    assert!(
        stdout.contains("ws_rc=0"),
        "workspace read failed under narrow read (allowlist too tight?); stdout={stdout}, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !stdout.contains("secret_rc=0"),
        "secret read unexpectedly succeeded under narrow read; stdout={stdout}, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Pure unit test for [`legal_mask`] — the primary regression gate for the device-file
/// bug. No kernel, no landlock support required, never skipped: the mask logic must be
/// correct on every host. Before the fix, non-directory paths granted directory-only bits
/// and `add_rule` rejected the whole ruleset.
///
/// Parametrized over the ABI tiers that add a *file* right: V3 adds `Truncate` and V5
/// adds `IoctlDev` to `from_file`, so both exercise the abi-dependence the loop
/// introduces. V2/V4/V6/V7 add no `ACCESS_FILE` bit (only directory rights or nothing),
/// so they would just re-test an identical `from_file` set and are skipped.
#[test]
fn legal_mask_narrows_non_directory_to_file_rights() {
    for &abi in &[ABI::V1, ABI::V3, ABI::V5] {
        let full = AccessFs::from_all(abi);
        let file_rights = AccessFs::from_file(abi);

        // Directory: the desired mask is kept verbatim, directory-only bits included.
        let dir = unique_dir(&std::env::temp_dir(), "legal-mask-dir");
        let dir_mask = legal_mask(full, &dir, abi);
        assert_eq!(dir_mask, full, "a directory keeps the full mask");
        assert!(dir_mask.contains(AccessFs::ReadDir));
        assert!(dir_mask.contains(AccessFs::MakeReg));
        assert!(dir_mask.contains(AccessFs::RemoveFile));

        // Regular file: directory-only bits are dropped, file rights retained. Created
        // inside a unique dir so the name is collision-free across parallel test threads.
        let file = unique_dir(&std::env::temp_dir(), "legal-mask-file").join("f");
        std::fs::write(&file, b"x").unwrap();
        let file_mask = legal_mask(full, &file, abi);
        assert_eq!(
            file_mask, file_rights,
            "a non-directory narrows to from_file(abi)"
        );
        assert!(!file_mask.contains(AccessFs::ReadDir));
        assert!(!file_mask.contains(AccessFs::MakeReg));
        assert!(!file_mask.contains(AccessFs::RemoveFile));
        assert!(file_mask.contains(AccessFs::ReadFile));
        assert!(file_mask.contains(AccessFs::WriteFile));
        assert!(file_mask.contains(AccessFs::Execute));

        // A read-only desired on a file collapses to the read+exec file bits.
        let read_mask = legal_mask(AccessFs::from_read(abi), &file, abi);
        assert_eq!(
            read_mask,
            AccessFs::from_read(abi) & file_rights,
            "a read desired on a non-directory narrows to read file rights",
        );
        let _ = std::fs::remove_file(&file);
    }
}

/// Regression (integration, landlock-gated): a non-directory path in the writable set —
/// the character devices [`baseline_writable`] lists (`/dev/null`) plus a regular file —
/// must not break ruleset construction. Before the [`legal_mask`] fix, `/dev/null` was
/// granted directory-only bits and `add_rule` rejected the whole ruleset at build time, so
/// every landlocked spawn failed regardless of the command's read/write intent.
#[test]
fn non_directory_writable_does_not_break_ruleset() {
    if skip_if_unsupported() {
        return;
    }
    let Some(parent) = non_baseline_parent() else {
        return;
    };

    // A pre-existing regular (non-directory) file the child must be able to overwrite.
    let dir = unique_dir(&parent, "wf");
    let file = dir.join("f");
    std::fs::write(&file, b"").unwrap();

    // baseline_writable() already pulls in /dev/null (where present); add the regular
    // file. Both are non-directories — the bug would reject this ruleset outright.
    let mut writable = baseline_writable();
    writable.push(file.clone());

    let decision = AccessDecision {
        read: ReadPolicy::Broad,
        writable,
    };
    // prepare_landlock succeeding (run_under_decision's expect) is itself the regression
    // assertion; the redirects confirm the file/device rights actually apply at runtime.
    let script = format!("echo hi > /dev/null && echo body > '{}'", file.display());
    let output = run_under_decision(&decision, &script);

    assert!(
        output.status.success(),
        "non-directory writable paths broke the ruleset or spawn; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "body\n");
}

/// **Cross-directory `Refer` works between writable trees** (the EXDEV regression gate).
///
/// Grants `a/` and `b/` as **two separately-listed** writable entries (each
/// `from_all(REQUIRED_ABI)`, so each independently carries `Refer`) under a common parent
/// that is **not** granted (only covered read-only by the `/` rule). A cross-directory
/// hardlink `a/f -> b/f` and a cross-directory rename `a/g -> b/g` must both succeed under
/// the preset domain.
///
/// Two-separately-listed (rather than one parent with two children) locks the invariant
/// that *every* writable rule carries `Refer` — a single-parent variant would still pass if
/// a regression dropped `Refer` from one of two listed trees, while real cargo (which moves
/// artifacts between separately-granted trees) would break.
#[test]
fn cross_dir_refer_works_between_writable_trees() {
    if skip_if_unsupported() {
        return;
    }
    let Some(parent) = non_baseline_parent() else {
        return;
    };
    let a = unique_dir(&parent, "refer-a");
    let b = unique_dir(&parent, "refer-b");
    // parent (CARGO_TARGET_TMPDIR) is deliberately NOT granted; only "/" read covers it.
    let rules: &[(&Path, BitFlags<AccessFs>)] = &[
        (Path::new("/"), AccessFs::from_read(REQUIRED_ABI)),
        (&a, AccessFs::from_all(REQUIRED_ABI)),
        (&b, AccessFs::from_all(REQUIRED_ABI)),
    ];

    let script = format!(
        "echo x > '{a}/f' && ln '{a}/f' '{b}/f' && echo y > '{a}/g' && mv '{a}/g' '{b}/g'",
        a = a.display(),
        b = b.display(),
    );
    let output = run_under_rules(REQUIRED_ABI, rules, &script);

    assert!(
        output.status.success(),
        "cross-directory link/rename failed under the preset domain (Refer not effective?); \
         stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(b.join("f").exists(), "hardlink target b/f was not created");
    assert!(b.join("g").exists(), "renamed target b/g was not created");
}

/// **Cross-directory `Refer` absent is EXDEV** (fail-closed reverse gate).
///
/// Builds a V1 domain (no `Refer` handled) over two writable trees. Same-directory writes
/// still succeed, but a cross-directory hardlink is rejected with **`EXDEV`** specifically —
/// not `EACCES`. Using V1 masks on both endpoints isolates the `Refer` denial: a variant
/// that covered the destination only via the broad `/` read rule could false-pass on a
/// `MakeReg`/EACCES denial instead, hiding a real `Refer` regression.
#[test]
fn cross_dir_refer_absent_is_exdev() {
    if skip_if_unsupported() {
        return;
    }
    let Some(parent) = non_baseline_parent() else {
        return;
    };
    let a = unique_dir(&parent, "exdev-a");
    let b = unique_dir(&parent, "exdev-b");
    let rules: &[(&Path, BitFlags<AccessFs>)] = &[
        (Path::new("/"), AccessFs::from_read(ABI::V1)),
        (&a, AccessFs::from_all(ABI::V1)), // V1: Refer NOT granted
        (&b, AccessFs::from_all(ABI::V1)),
    ];

    // `wrote` confirms same-directory write still works (isolating the failure to the
    // cross-directory link); `linked` must be non-zero and stderr must name EXDEV.
    let script = format!(
        "echo x > '{a}/f'; echo \"wrote=$?\"; ln '{a}/f' '{b}/f'; echo \"linked=$?\"",
        a = a.display(),
        b = b.display(),
    );
    let output = run_under_rules(ABI::V1, rules, &script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("wrote=0"),
        "same-directory write failed under V1 (domain not functional); stdout={stdout}, stderr={stderr}"
    );
    assert!(
        !stdout.contains("linked=0"),
        "cross-directory link unexpectedly succeeded under V1 (Refer leaked in?); stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stderr.to_ascii_lowercase().contains("cross-device"),
        "expected an EXDEV denial, but stderr did not mention cross-device; stderr={stderr}"
    );
}

/// Fork a child that enters the `abi`/`rules` domain, opens `/dev/ptmx`, and issues
/// `TIOCGWINSZ` on it. Returns `[restrict_errno, open_fd, ioctl_rc, ioctl_errno]` so a
/// caller can assert success (`ioctl_rc == 0`) or an `IoctlDev` denial (`ioctl_rc == -1`,
/// `EACCES`).
///
/// `run_under_*` exec `bash`, which cannot issue a raw ioctl, so this reaches
/// [`restrict_self_raw`] directly via a manual `fork` — the child does only
/// async-signal-safe `libc` syscalls and reports back over a pipe, mirroring how a real
/// `pre_exec` applies the domain then performs the syscall in-process.
fn ioctl_ptmx_under(abi: ABI, rules: Vec<(PathBuf, BitFlags<AccessFs>)>) -> [std::ffi::c_int; 4] {
    let prepared = build_ruleset(abi, &rules).expect("ruleset build should succeed");
    let raw = prepared.raw_fd();

    let mut pipefds = [0 as std::ffi::c_int; 2];
    // SAFETY: `pipe(2)` writing into a local 2-int array.
    assert_eq!(
        unsafe { libc::pipe(pipefds.as_mut_ptr()) },
        0,
        "pipe failed"
    );
    let (read_fd, write_fd) = (pipefds[0], pipefds[1]);

    // SAFETY: `fork(2)`. The child branch below issues only async-signal-safe syscalls
    // (open/ioctl/write/_exit) and never touches the Rust allocator or any lock, so it is
    // safe to run between `fork` and `_exit` in cargo-test's multithreaded process.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // --- child ---
        unsafe {
            libc::close(read_fd);
            let restrict_errno = match restrict_self_raw(raw) {
                Ok(()) => 0,
                Err(e) => e.raw_os_error().unwrap_or(-1),
            };
            let fd = libc::open(c"/dev/ptmx".as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
            let ioctl_rc;
            let ioctl_errno;
            if fd >= 0 {
                let mut ws: libc::winsize = std::mem::zeroed();
                ioctl_rc = libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws);
                ioctl_errno = if ioctl_rc == 0 {
                    0
                } else {
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                };
            } else {
                // open itself failed — record it so the caller sees the domain never got
                // far enough to test the ioctl (e.g. ptmx not grantable).
                ioctl_rc = -1;
                ioctl_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            }
            let out = [restrict_errno, fd, ioctl_rc, ioctl_errno];
            let _ = libc::write(
                write_fd,
                out.as_ptr() as *const _,
                std::mem::size_of_val(&out),
            );
            libc::_exit(0);
        }
    }
    // --- parent ---
    // SAFETY: close the write end so the read below sees EOF after the child writes.
    unsafe {
        libc::close(write_fd);
    }
    let mut buf = [0 as std::ffi::c_int; 4];
    // SAFETY: read into a local 4-int buffer from the pipe the child wrote.
    let n = unsafe {
        libc::read(
            read_fd,
            buf.as_mut_ptr() as *mut _,
            std::mem::size_of_val(&buf),
        )
    };
    let mut status: std::ffi::c_int = 0;
    // SAFETY: waitpid on our own child.
    unsafe {
        libc::waitpid(pid, &mut status, 0);
        libc::close(read_fd);
    }
    assert_eq!(
        n,
        std::mem::size_of_val(&buf) as isize,
        "short read from child"
    );
    buf
}

/// **Device ioctls work under the preset domain** (guards against a future preset bump
/// past V3).
///
/// The preset pins `REQUIRED_ABI = V3`, which does **not** handle `IoctlDev`, so device
/// ioctls stay unrestricted. `/dev/ptmx` is granted writable (it is in no baseline and the
/// broad `/` rule is read-only) and `TIOCGWINSZ` must succeed — the same class of ioctl an
/// interactive shell issues on `/dev/tty` for terminal control. This is the regression
/// guard for the device-ioctl footgun that makes the preset stop at V3.
#[test]
fn device_ioctl_works_under_preset_domain() {
    if skip_if_unsupported() {
        return;
    }
    // Needs host ABI >= V3 so build_ruleset(REQUIRED_ABI) creates; below V3 the ruleset
    // errors at creation rather than reaching the ioctl this test exercises.
    if skip_if_abi_below(3) {
        return;
    }
    let [restrict_errno, open_fd, ioctl_rc, ioctl_errno] = ioctl_ptmx_under(
        REQUIRED_ABI,
        vec![
            (PathBuf::from("/"), AccessFs::from_read(REQUIRED_ABI)),
            (PathBuf::from("/dev/ptmx"), AccessFs::from_all(REQUIRED_ABI)),
        ],
    );
    assert_eq!(
        restrict_errno, 0,
        "restrict_self failed; domain not applied"
    );
    assert!(open_fd >= 0, "open /dev/ptmx failed; ptmx not granted");
    assert_eq!(
        (ioctl_rc, ioctl_errno),
        (0, 0),
        "device ioctl denied under the preset domain (IoctlDev leaked into V3?); \
         ioctl_rc={ioctl_rc}, errno={ioctl_errno}"
    );
}

/// **Device ioctls are denied under a V5 escape hatch without an `IoctlDev` grant** —
/// locks in *why* the preset is V3.
///
/// A V5 ruleset handles `IoctlDev`, so it is deny-by-default. `/dev/ptmx` is granted
/// `from_file(V5)` **minus** `IoctlDev` (so `open` still succeeds) but the `TIOCGWINSZ`
/// ioctl must be rejected with `EACCES`. A future "bump the preset to V5" trips this test
/// unless devices are granted `IoctlDev` explicitly — forcing the device-grant decision the
/// preset deliberately avoids.
#[test]
fn device_ioctl_denied_under_v5_escape_hatch_without_grant() {
    if skip_if_unsupported() {
        return;
    }
    // Needs a host that handles the V5 universe; below V5 build_ruleset(ABI::V5) errors at
    // creation rather than reaching the IoctlDev denial this test pins.
    if skip_if_abi_below(5) {
        return;
    }
    // V5 file rights minus IoctlDev: open (ReadFile|WriteFile) still succeeds, but the
    // device ioctl is denied — isolating the IoctlDev denial from any open-time failure.
    let ptmx_mask = AccessFs::from_file(ABI::V5) & !BitFlags::from_flag(AccessFs::IoctlDev);
    let [restrict_errno, open_fd, ioctl_rc, ioctl_errno] = ioctl_ptmx_under(
        ABI::V5,
        vec![
            (PathBuf::from("/"), AccessFs::from_read(ABI::V5)),
            (PathBuf::from("/dev/ptmx"), ptmx_mask),
        ],
    );
    assert_eq!(
        restrict_errno, 0,
        "restrict_self failed; domain not applied"
    );
    assert!(
        open_fd >= 0,
        "open /dev/ptmx failed (ptmx_mask must grant ReadFile|WriteFile so open succeeds \
         and only the ioctl is denied); errno={ioctl_errno}"
    );
    assert_eq!(
        ioctl_rc, -1,
        "device ioctl unexpectedly succeeded under V5 without an IoctlDev grant"
    );
    assert_eq!(
        ioctl_errno,
        libc::EACCES,
        "expected an IoctlDev denial (EACCES); got errno={ioctl_errno}"
    );
}

/// **Subset contract**: a rule mask carrying a bit the ruleset's `abi` does not handle is
/// rejected (not silently clamped). Host ABI >= V3, so the V3 ruleset creates and the
/// rejection happens at `add_rule` (`check_consistency` runs before `try_compat`). A real
/// directory keeps `from_all(V5)` verbatim through [`legal_mask`], so `IoctlDev` reaches
/// the check and surfaces as `UnhandledAccess` naming it.
#[test]
fn build_ruleset_rejects_mask_above_handled_abi() {
    if skip_if_unsupported() {
        return;
    }
    // Needs host ABI >= V3 so the V3 ruleset creates and the rejection happens at add_rule
    // (check_consistency runs before try_compat). Below V3 the error is a creation-phase
    // Incompatible message naming a different right, not the add_rule UnhandledAccess one.
    if skip_if_abi_below(3) {
        return;
    }
    let dir = unique_dir(&std::env::temp_dir(), "subset");
    let err = build_ruleset(ABI::V3, &[(dir, AccessFs::from_all(ABI::V5))])
        .expect_err("a mask carrying a bit the abi does not handle should be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("IoctlDev") && msg.contains("not handled"),
        "expected an UnhandledAccess error naming IoctlDev; got: {msg}"
    );
}

/// Guards the preset's runtime kernel-floor string against silent drift: the message
/// [`abi_ctx_err`] builds for the preset path must interpolate [`REQUIRED_ABI_KERNEL`] and
/// name [`REQUIRED_ABI`]. Pure unit (a stub error), no kernel touched.
#[test]
fn abi_ctx_err_message_names_preset_kernel_floor() {
    let err = abi_ctx_err(REQUIRED_ABI, std::io::Error::from_raw_os_error(524));
    let msg = err.to_string();
    assert!(
        msg.contains(REQUIRED_ABI_KERNEL),
        "abi_ctx_err(preset) must interpolate REQUIRED_ABI_KERNEL ({REQUIRED_ABI_KERNEL:?}); got: {msg}"
    );
    assert!(
        msg.contains(&format!("ABI {REQUIRED_ABI:?}")),
        "abi_ctx_err(preset) must name the requested ABI; got: {msg}"
    );
}

/// End-to-end `cargo build` under the preset domain — the only gate that catches
/// cargo-specific cross-directory shapes (e.g. `renameat2(RENAME_EXCHANGE)`). Ignored by
/// default: it needs `cargo` on `$PATH` and a writable `CARGO_HOME`, and is slow. Run with
/// `cargo test --all-features -- --ignored cross_dir_cargo_build`.
#[test]
#[ignore = "end-to-end cargo build; run manually on a kernel >= 6.2"]
fn cross_dir_cargo_build_under_preset_domain() {
    if skip_if_unsupported() {
        return;
    }
    let Some(parent) = non_baseline_parent() else {
        return;
    };
    let crate_dir = unique_dir(&parent, "cargo-smoke");
    let cargo_home = unique_dir(&parent, "cargo-home");

    // Minimal no-deps binary crate.
    std::fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"smoke\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\n",
    )
    .unwrap();
    std::fs::create_dir_all(crate_dir.join("src")).unwrap();
    std::fs::write(crate_dir.join("src/main.rs"), "fn main() {}\n").unwrap();

    let decision = AccessDecision {
        read: ReadPolicy::Broad,
        // The crate (incl. its `target/`) and a private CARGO_HOME must be writable;
        // rustc/sysroot are covered read-only by the broad `/` rule.
        writable: vec![crate_dir.clone(), cargo_home.clone()],
    };
    let prepared = prepare_landlock(&decision).expect("prepare_landlock should succeed");
    let raw = prepared.raw_fd();
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .env("CARGO_HOME", &cargo_home)
        .env("CARGO_TARGET_DIR", crate_dir.join("target"))
        .current_dir(&crate_dir);
    // SAFETY: `restrict_self_raw` issues only async-signal-safe raw syscalls.
    unsafe {
        cmd.pre_exec(move || restrict_self_raw(raw));
    }
    let output = cmd.output().expect("spawn + wait should succeed");

    assert!(
        output.status.success(),
        "cargo build failed under the preset domain (EXDEV mid-compile?); stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
