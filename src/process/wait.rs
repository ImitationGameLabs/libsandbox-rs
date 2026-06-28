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

/// Busy-wait reap granularity: short enough to bound timeout overshoot, long
/// enough to avoid sub-millisecond scheduler wakeups.
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Post-SIGKILL grace window before declaring the child unkillable (D-state).
const POST_KILL_GRACE: Duration = Duration::from_secs(5);
/// Async path: cap the reap poll immediately after a timeout-kill.
#[cfg(feature = "tokio")]
const POST_KILL_REAP_CAP: Duration = Duration::from_millis(100);
/// Async path: bounded sleep when no timeout is set (no pidfd wait source).
#[cfg(feature = "tokio")]
const TIMEOUTLESS_SLEEP_CAP: Duration = Duration::from_secs(60);

/// What [`wait_with_timeout`] / [`wait_with_timeout_async`] collect from a child:
/// its drained stdout/stderr (raw bytes) and how it exited.
///
/// A named struct rather than a positional 5-tuple so call sites destructure by
/// field name (the tuple's element order is easy to swap by mistake).
pub(crate) struct CollectedOutput {
    /// Drained stdout (raw bytes — no lossy UTF-8 conversion).
    pub(crate) stdout: Vec<u8>,
    /// Drained stderr (raw bytes).
    pub(crate) stderr: Vec<u8>,
    /// Exit code (`128 + signal` for signal deaths, per shell convention).
    pub(crate) exit_code: i32,
    /// Whether the child was killed for exceeding the wall-clock timeout.
    pub(crate) killed_by_timeout: bool,
    /// The fatal signal, if the child was killed by one.
    pub(crate) signal: Option<i32>,
}

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
/// stdout/stderr are raw bytes — no lossy UTF-8 conversion, so binary output
/// round-trips intact. Polls every [`REAP_POLL_INTERVAL`] — for async callers
/// prefer [`wait_with_timeout_async`].
pub(crate) fn wait_with_timeout(
    pid: nix::unistd::Pid,
    stdout_fd: Option<std::os::fd::OwnedFd>,
    stderr_fd: Option<std::os::fd::OwnedFd>,
    timeout: Duration,
) -> Result<CollectedOutput> {
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
            return Ok(CollectedOutput {
                stdout,
                stderr,
                exit_code: code,
                killed_by_timeout,
                signal,
            });
        }

        if start.elapsed() > timeout && !killed_by_timeout {
            kill_child(pid);
            killed_by_timeout = true;
            kill_time = Some(Instant::now());
        }

        // Give up if the child is unkillable (e.g. stuck in D-state).
        if let Some(kt) = kill_time {
            if kt.elapsed() > POST_KILL_GRACE {
                return Err(SandboxError::new(
                    ErrorKind::Exec,
                    format!(
                        "child unkillable after SIGKILL ({POST_KILL_GRACE:?} post-kill timeout expired)"
                    ),
                ));
            }
        }

        std::thread::sleep(REAP_POLL_INTERVAL);
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
) -> Result<CollectedOutput> {
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
            return Ok(CollectedOutput {
                stdout,
                stderr,
                exit_code: code,
                killed_by_timeout,
                signal,
            });
        }
        if let Some(dl) = deadline {
            if Instant::now() >= dl && !killed_by_timeout {
                kill_child(pid);
                killed_by_timeout = true;
                kill_time = Some(Instant::now());
            }
        }
        if let Some(kt) = kill_time {
            if kt.elapsed() > POST_KILL_GRACE {
                return Err(SandboxError::new(
                    ErrorKind::Exec,
                    format!(
                        "child unkillable after SIGKILL ({POST_KILL_GRACE:?} post-kill timeout expired)"
                    ),
                ));
            }
        }

        // Wait for exit (pidfd readable) or a bounded sleep that lets us
        // re-check the deadline / drain pipes.
        let cap = if killed_by_timeout {
            POST_KILL_REAP_CAP
        } else {
            deadline
                .and_then(|dl| dl.checked_duration_since(Instant::now()))
                // No real deadline (timeoutless wait): a long-but-bounded sleep.
                // The pidfd still interrupts on exit; this only bounds the
                // no-pidfd polling fallback (clamped to REAP_POLL_INTERVAL below).
                .unwrap_or(TIMEOUTLESS_SLEEP_CAP)
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
            tokio::time::sleep(cap.min(REAP_POLL_INTERVAL)).await;
        }
    }
}
