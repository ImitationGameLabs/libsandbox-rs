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
    cmd.arg("-c").arg(script);
    // SAFETY: `restrict_self_raw` issues only async-signal-safe raw syscalls.
    unsafe {
        cmd.pre_exec(move || restrict_self_raw(raw));
    }
    cmd.output().expect("spawn + wait should succeed")
}

/// Run `bash -c <script>` under a ruleset built from explicit `(path, mask)` rules (via
/// the production [`build_ruleset`]). Used by the limitation probes that need raw control
/// over the granted masks.
fn run_under_rules(rules: &[(&Path, BitFlags<AccessFs>)], script: &str) -> std::process::Output {
    let owned: Vec<(PathBuf, BitFlags<AccessFs>)> =
        rules.iter().map(|(p, m)| (p.to_path_buf(), *m)).collect();
    let prepared =
        build_ruleset(&owned).expect("ruleset build should succeed on a supported kernel");
    let raw = prepared.raw_fd();
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(script);
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
    build_ruleset(&[(dir, AccessFs::from_all(ABI::V1))])
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
        (Path::new("/"), AccessFs::from_read(ABI::V1)),
        (&root, AccessFs::from_all(ABI::V1)),
        (&hole, AccessFs::from_read(ABI::V1)), // attempted read-only override — no effect
    ];
    let target = hole.join("f");
    let output = run_under_rules(rules, &format!("echo x > '{}'", target.display()));

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
        (Path::new("/"), AccessFs::from_read(ABI::V1)),
        (&sibling, AccessFs::from_all(ABI::V1)),
    ];

    // The granted sibling is writable.
    let sib_target = sibling.join("f");
    let out = run_under_rules(rules, &format!("echo x > '{}'", sib_target.display()));
    assert!(
        out.status.success() && sib_target.exists(),
        "sibling should be writable; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The ungranted hole is read-only (no write grant, and root is not granted so it
    // cannot cover the hole).
    let hole_target = hole.join("f");
    let out = run_under_rules(rules, &format!("echo x > '{}'", hole_target.display()));
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
#[test]
fn legal_mask_narrows_non_directory_to_file_rights() {
    let abi = ABI::V1;
    let full = AccessFs::from_all(abi);
    let file_rights = AccessFs::from_file(abi);

    // Directory: the desired mask is kept verbatim, directory-only bits included.
    let dir = unique_dir(&std::env::temp_dir(), "legal-mask-dir");
    let dir_mask = legal_mask(full, &dir, abi);
    assert_eq!(dir_mask, full, "a directory keeps the full mask");
    assert!(dir_mask.contains(AccessFs::ReadDir));
    assert!(dir_mask.contains(AccessFs::MakeReg));
    assert!(dir_mask.contains(AccessFs::RemoveFile));

    // Regular file: directory-only bits are dropped, file rights retained. Created inside
    // a unique dir so the name is collision-free across parallel test threads.
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
