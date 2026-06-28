//! Bring-your-own `process::Command`: compose libsandbox's child-side
//! primitives inside a `pre_exec` closure.
//!
//! This is the **primitive layer** of the crate — for callers that drive their
//! own process model (here [`std::process::Command`]) and want libsandbox only
//! for the sandboxing *steps*, not the full [`Sandbox`](libsandbox::Sandbox) /
//! [`Child`](libsandbox::Child) lifecycle. It is the supported escape hatch when
//! you need control over how the process is spawned (a different runtime, a
//! PTY, instrumentation around `fork`) but still want libsandbox's namespace /
//! mount isolation.
//!
//! The split is load-bearing:
//! - **Parent-side** `prepare_*` may allocate (build `CString`s, open the
//!   ruleset fd, ...). Their results are moved into the closure.
//! - **Child-side** `install_*` run post-fork / pre-`exec` and call only
//!   async-signal-safe raw syscalls — never allocate.
//!
//! Errors cross the closure's [`io::Result`](std::io::Result) boundary via the
//! `From<SandboxError> for io::Error` impl, so `?` works directly inside
//! `pre_exec`.
//!
//! Layers demonstrated, in the order they must install:
//! 1. a fresh user + mount namespace (`prepare_user_mount_ns`) — grants
//!    `CAP_SYS_ADMIN` inside the namespace so the later mounts are allowed;
//! 2. a read-only self-bind of a host directory (`prepare_bind`) — the child
//!    can read it but not write it;
//! 3. a writable, no-exec tmpfs overlay (`prepare_tmpfs`) — a scratch space the
//!    child can write but cannot execute from.
//!
//! Landlock and seccomp compose identically — `prepare_landlock` /
//! `prepare_seccomp` parent-side, then `install_landlock` /
//! `SeccompFilter::install` *last* inside the closure (so the filter cannot
//! trap the setup syscalls). They need the `landlock` / seccomp features and
//! are omitted here to keep the example dependency-light.

use libsandbox::{MountFlags, Permission, RemountRecursion};
use std::os::unix::process::CommandExt;
use std::process::Command;

fn main() -> libsandbox::Result<()> {
    // A base dir under the host /tmp. The read-only bind and the tmpfs overlay
    // are *siblings* under it, so neither overlay hides the other.
    let base = std::env::temp_dir().join("libsandbox_custom_process");
    std::fs::create_dir_all(&base)?;

    // `host_ro`: a host directory we bind-mount READ-ONLY. The child can read
    // `secret.txt` but not modify it.
    let host_ro = base.join("host_ro");
    std::fs::create_dir_all(&host_ro)?;
    std::fs::write(host_ro.join("secret.txt"), "top secret\n")?;

    // `scratch`: overlaid with a writable tmpfs (created by prepare_tmpfs).
    let scratch = base.join("scratch");

    // ---- parent-side prepare (may allocate; builds CStrings / mount data) ---
    // SAFETY: getuid / getgid take no arguments and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let ns = libsandbox::prepare_user_mount_ns(uid, gid);
    let ro_bind = libsandbox::prepare_bind(
        &host_ro,
        Permission::ReadOnly,
        RemountRecursion::NonRecursive,
    )?;
    // A writable scratch tmpfs: no exec, no suid, no device files.
    let tmpfs = libsandbox::prepare_tmpfs(
        &scratch,
        8 * libsandbox::MB,
        MountFlags::NO_EXEC | MountFlags::NO_SUID | MountFlags::NO_DEV,
    )?;

    // The child references both paths by absolute path: $1 = host_ro, $2 = scratch.
    let script = "\
echo 'read secret:'; cat \"$1/secret.txt\"
echo 'try write read-only bind:'; if echo tampered >> \"$1/secret.txt\" 2>/dev/null; then echo 'LEAK: wrote the read-only bind!'; else echo '(ok: read-only bind blocked the write)'; fi
echo 'try write tmpfs:'; echo scratch-data > \"$2/x\" && cat \"$2/x\"
";

    // ---- spawn: the closure runs in the child before exec ------------------
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(script)
        .arg("sh")
        .arg(&host_ro)
        .arg(&scratch);
    unsafe {
        cmd.pre_exec(move || {
            libsandbox::install_user_mount_ns(&ns)?;
            libsandbox::install_bind(&ro_bind)?;
            libsandbox::install_tmpfs(&tmpfs)?;
            Ok(())
        });
    }

    let output = cmd.output()?;

    println!("exit: {}", output.status.code().unwrap_or(-1));
    println!("--- stdout ---");
    print!("{}", String::from_utf8_lossy(&output.stdout));
    println!("--- stderr ---");
    print!("{}", String::from_utf8_lossy(&output.stderr));
    Ok(())
}
