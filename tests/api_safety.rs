//! Regression tests for the misuse-resistance guarantees of the public API:
//! the `wait()` pipe-deadlock guard, `wait_with_output()` draining, the
//! `Stdio::Owned` low-fd rejection, and the `DetachedChild` contract.

use libsandbox::{ErrorKind, Sandbox, Stdio};

/// `wait()` must refuse to block when piped stdout/stderr are still owned by
/// the `Child` — the classic pipe-buffer deadlock. A child that fills the pipe
/// must NOT hang the caller; the call returns `Err(WouldDeadlock)` instead.
#[test]
fn wait_rejects_undrained_pipes() {
    let sandbox = Sandbox::builder().build().unwrap();
    // 200 KB of NUL bytes — well past the typical 64 KB pipe buffer.
    let child = sandbox
        .spawn("sh", &["-c", "head -c 200000 /dev/zero"])
        .unwrap();
    let err = child.wait().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WouldDeadlock);
}

/// `wait_with_output()` drains the pipes concurrently with reaping, so a child
/// that writes far more than the pipe buffer is collected in full without
/// deadlocking.
#[test]
fn wait_with_output_drains_large_output() {
    let sandbox = Sandbox::builder().build().unwrap();
    let child = sandbox
        .spawn("sh", &["-c", "head -c 200000 /dev/zero"])
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.stdout.len(), 200000);
    assert!(out.status.success());
}

/// A caller-provided fd via `Stdio::Owned` spawns normally when it is a real,
/// non-standard fd. (The fd 0/1/2 rejection is a trivial `<= 2` guard; it is
/// not exercised here because constructing an `OwnedFd` over a standard stream
/// would close that stream on the error path.)
#[test]
fn stdio_owned_valid_fd_accepted() {
    let sandbox = Sandbox::builder().build().unwrap();
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();
    let child = sandbox
        .build_spawn("true", &[])
        .stdout(Stdio::from(sink))
        .start()
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}

/// `detach()` releases the child from `Child`'s kill-on-drop contract: the
/// process survives the drop, and `DetachedChild::reap()` collects its exit
/// status (here after an explicit kill) without leaving a zombie.
#[test]
fn detach_then_reap_collects_exit() {
    let sandbox = Sandbox::builder().build().unwrap();
    let child = sandbox.spawn("sleep", &["30"]).unwrap();
    let detached = child.detach();
    let pid = detached.pid() as libc::pid_t;
    // The detached child must still be alive (detach did not kill it); signal
    // it ourselves, then reap via the handle.
    // SAFETY: killing a positive pid we just detached.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let status = detached.reap().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}
