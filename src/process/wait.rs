//! Process wait with timeout and output collection.
//!
//! [`wait_with_timeout`] is the blocking loop used by one-shot execution.
//! [`wait_with_timeout_async`] (behind the `tokio` feature) is the event-driven
//! equivalent: it awaits the child's pidfd for exit instead of busy-polling,
//! so it does not stall an async runtime.

#[cfg(feature = "tokio")]
use super::fd::try_pidfd_open;
use super::fd::{drain_owned_fd, set_nonblock};
use crate::error::{ErrorKind, Result, SandboxError};
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// Non-blocking reap: `waitpid(WNOHANG)`. Returns `Some((exit_code, signal))`
/// if the child has exited, else `None`.
fn try_reap(pid: nix::unistd::Pid) -> Result<Option<(i32, Option<i32>)>> {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    let status = loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Err(nix::errno::Errno::EINTR) => continue,
            other => break other,
        }
    };
    match status
        .map_err(|e| SandboxError::new(ErrorKind::Exec, format!("waitpid for child {pid}: {e}")))?
    {
        WaitStatus::Exited(_, code) => Ok(Some((code, None))),
        WaitStatus::Signaled(_, sig, _) => Ok(Some((128 + sig as i32, Some(sig as i32)))),
        // StillAlive, or a non-exit status (Stopped/Continued/Ptrace*) which the
        // sandbox never produces (no tracer attaches). Treat as "not yet exited".
        _ => Ok(None),
    }
}

/// Drain both pipes fully (non-blocking) into their buffers, then drop them.
fn finalize(
    stdout_fd: Option<std::os::fd::OwnedFd>,
    stderr_fd: Option<std::os::fd::OwnedFd>,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
) {
    drain_owned_fd(stdout_fd.as_ref(), stdout);
    drain_owned_fd(stderr_fd.as_ref(), stderr);
    drop(stdout_fd);
    drop(stderr_fd);
}

fn set_pipes_nonblocking(
    stdout_fd: &Option<std::os::fd::OwnedFd>,
    stderr_fd: &Option<std::os::fd::OwnedFd>,
) {
    if let Some(fd) = stdout_fd {
        if let Err(e) = set_nonblock(fd.as_raw_fd()) {
            tracing::warn!("failed to set stdout non-blocking: {e}");
        }
    }
    if let Some(fd) = stderr_fd {
        if let Err(e) = set_nonblock(fd.as_raw_fd()) {
            tracing::warn!("failed to set stderr non-blocking: {e}");
        }
    }
}

/// Send SIGKILL to the child and its process group (best-effort).
fn kill_child(pid: nix::unistd::Pid) {
    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
    // SAFETY: kill(-pgid, SIGKILL) — best-effort pgrp kill.
    unsafe {
        libc::kill(-pid.as_raw(), libc::SIGKILL);
    }
}

/// Pack the collected output into the result tuple.
fn pack(
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: i32,
    killed_by_timeout: bool,
    signal: Option<i32>,
) -> (String, String, i32, bool, Option<i32>) {
    (
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
        exit_code,
        killed_by_timeout,
        signal,
    )
}

/// Read whatever is currently available on a non-blocking pipe into `buf`.
fn read_available(fd: Option<&std::os::fd::OwnedFd>, buf: &mut Vec<u8>) {
    let Some(fd) = fd else { return };
    let mut tmp = [0u8; 4096];
    loop {
        match nix::unistd::read(fd.as_fd(), &mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break, // EAGAIN / closed — stop
        }
    }
}

/// Wait for a child process with a wall-clock timeout, collecting stdout and
/// stderr from pipe fds.
///
/// Returns `(stdout, stderr, exit_code, killed_by_timeout, signal)`. Polls
/// every 10 ms — for async callers prefer [`wait_with_timeout_async`].
pub(crate) fn wait_with_timeout(
    pid: nix::unistd::Pid,
    stdout_fd: Option<std::os::fd::OwnedFd>,
    stderr_fd: Option<std::os::fd::OwnedFd>,
    timeout: Duration,
) -> Result<(String, String, i32, bool, Option<i32>)> {
    set_pipes_nonblocking(&stdout_fd, &stderr_fd);

    let start = Instant::now();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut killed_by_timeout = false;
    let mut kill_time: Option<Instant> = None;

    loop {
        read_available(stdout_fd.as_ref(), &mut stdout);
        read_available(stderr_fd.as_ref(), &mut stderr);

        if let Some((code, signal)) = try_reap(pid)? {
            finalize(stdout_fd, stderr_fd, &mut stdout, &mut stderr);
            return Ok(pack(stdout, stderr, code, killed_by_timeout, signal));
        }

        if start.elapsed() > timeout && !killed_by_timeout {
            kill_child(pid);
            killed_by_timeout = true;
            kill_time = Some(Instant::now());
        }

        // Give up if the child is unkillable (e.g. stuck in D-state).
        if let Some(kt) = kill_time {
            if kt.elapsed() > Duration::from_secs(5) {
                return Err(SandboxError::new(
                    ErrorKind::Exec,
                    "child unkillable after SIGKILL (5s post-kill timeout expired)",
                ));
            }
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Event-driven wait for a child process with a wall-clock timeout.
///
/// Like [`wait_with_timeout`] but awaits the child's pidfd for exit (Linux
/// 5.3+) instead of busy-polling, so it composes with other async work. On
/// older kernels without `pidfd_open`, falls back to short `tokio::time::sleep`
/// polling.
#[cfg(feature = "tokio")]
pub(crate) async fn wait_with_timeout_async(
    pid: nix::unistd::Pid,
    stdout_fd: Option<std::os::fd::OwnedFd>,
    stderr_fd: Option<std::os::fd::OwnedFd>,
    timeout: Duration,
) -> Result<(String, String, i32, bool, Option<i32>)> {
    use tokio::io::unix::AsyncFd;

    set_pipes_nonblocking(&stdout_fd, &stderr_fd);

    // `checked_add`: a timeout of `Duration::MAX` (the timeoutless `wait_async`
    // entry point) would overflow `Instant + Duration` (panic in debug). An
    // unrepresentable deadline means "no deadline" — never deadline-kill, just
    // wait for exit. Real timeouts still yield `Some`.
    let deadline = Instant::now().checked_add(timeout);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut killed_by_timeout = false;
    let mut kill_time: Option<Instant> = None;

    // pidfd for exit readiness (None on kernels without pidfd_open).
    let pidfd = try_pidfd_open(pid.as_raw()).map(|fd| {
        // try_pidfd_open returns an OwnedFd already; wrap for AsyncFd.
        AsyncFd::new(fd)
    });
    let pidfd = match pidfd {
        Some(Ok(ad)) => Some(ad),
        Some(Err(e)) => {
            return Err(SandboxError::new(
                ErrorKind::Exec,
                format!("pidfd AsyncFd setup failed: {e}"),
            ))
        }
        None => None,
    };

    loop {
        read_available(stdout_fd.as_ref(), &mut stdout);
        read_available(stderr_fd.as_ref(), &mut stderr);

        if let Some((code, signal)) = try_reap(pid)? {
            finalize(stdout_fd, stderr_fd, &mut stdout, &mut stderr);
            return Ok(pack(stdout, stderr, code, killed_by_timeout, signal));
        }

        if let Some(dl) = deadline {
            if Instant::now() >= dl && !killed_by_timeout {
                kill_child(pid);
                killed_by_timeout = true;
                kill_time = Some(Instant::now());
            }
        }
        if let Some(kt) = kill_time {
            if kt.elapsed() > Duration::from_secs(5) {
                return Err(SandboxError::new(
                    ErrorKind::Exec,
                    "child unkillable after SIGKILL (5s post-kill timeout expired)",
                ));
            }
        }

        // Wait for exit (pidfd readable) or a bounded sleep that lets us
        // re-check the deadline / drain pipes.
        let cap = if killed_by_timeout {
            Duration::from_millis(100)
        } else {
            deadline
                .and_then(|dl| dl.checked_duration_since(Instant::now()))
                // No real deadline (timeoutless wait): a long-but-bounded sleep.
                // The pidfd still interrupts on exit; this only bounds the
                // no-pidfd polling fallback (clamped to 10ms below).
                .unwrap_or(Duration::from_secs(60))
        };
        if let Some(ad) = pidfd.as_ref() {
            tokio::select! {
                res = ad.readable() => {
                    let _ = res; // reaped on next loop iteration
                }
                _ = tokio::time::sleep(cap) => {}
            }
        } else {
            // No pidfd: fall back to short polling.
            tokio::time::sleep(cap.min(Duration::from_millis(10))).await;
        }
    }
}
