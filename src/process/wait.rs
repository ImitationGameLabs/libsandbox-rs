//! Process wait with timeout and output collection.
//!
//! Provides the non-blocking wait loop used by one-shot execution to
//! collect stdout/stderr while enforcing a wall-clock deadline.

use crate::error::{Result, SandboxError};
use super::fd::{drain_owned_fd, set_nonblock};
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// Wait for a child process with a wall-clock timeout, collecting stdout
/// and stderr from pipe fds.
///
/// Returns `(stdout, stderr, exit_code, killed_by_timeout, signal)`.
pub(crate) fn wait_with_timeout(
    pid: nix::unistd::Pid,
    stdout_fd: Option<std::os::fd::OwnedFd>,
    stderr_fd: Option<std::os::fd::OwnedFd>,
    timeout: Duration,
) -> Result<(String, String, i32, bool, Option<i32>)> {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

    let start = Instant::now();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut killed_by_timeout = false;
    let mut kill_time: Option<Instant> = None;

    // Set non-blocking on pipe fds (guard against None — no pipe configured).
    if let Some(ref fd) = stdout_fd {
        if let Err(e) = set_nonblock(fd.as_raw_fd()) {
            tracing::warn!("failed to set stdout non-blocking: {e}");
        }
    }
    if let Some(ref fd) = stderr_fd {
        if let Err(e) = set_nonblock(fd.as_raw_fd()) {
            tracing::warn!("failed to set stderr non-blocking: {e}");
        }
    }

    loop {
        // Read available output from each pipe.
        if let Some(ref fd) = stdout_fd {
            let mut buf = [0u8; 4096];
            if let Ok(n) = nix::unistd::read(fd.as_fd(), &mut buf) {
                if n > 0 {
                    stdout.extend_from_slice(&buf[..n]);
                }
            }
        }
        if let Some(ref fd) = stderr_fd {
            let mut buf = [0u8; 4096];
            if let Ok(n) = nix::unistd::read(fd.as_fd(), &mut buf) {
                if n > 0 {
                    stderr.extend_from_slice(&buf[..n]);
                }
            }
        }

        let wait_result = loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Err(nix::errno::Errno::EINTR) => continue,
                other => break other,
            }
        };
        match wait_result
            .map_err(|e| SandboxError::Internal(format!("waitpid for child {pid}: {e}")))?
        {
            WaitStatus::Exited(_, code) => {
                drain_owned_fd(stdout_fd.as_ref(), &mut stdout);
                drain_owned_fd(stderr_fd.as_ref(), &mut stderr);
                drop(stdout_fd);
                drop(stderr_fd);
                return Ok((
                    String::from_utf8_lossy(&stdout).to_string(),
                    String::from_utf8_lossy(&stderr).to_string(),
                    code,
                    killed_by_timeout,
                    None,
                ));
            }
            WaitStatus::Signaled(_, sig, _) => {
                drain_owned_fd(stdout_fd.as_ref(), &mut stdout);
                drain_owned_fd(stderr_fd.as_ref(), &mut stderr);
                drop(stdout_fd);
                drop(stderr_fd);
                return Ok((
                    String::from_utf8_lossy(&stdout).to_string(),
                    String::from_utf8_lossy(&stderr).to_string(),
                    128 + sig as i32,
                    killed_by_timeout,
                    Some(sig as i32),
                ));
            }
            WaitStatus::StillAlive => {
                if start.elapsed() > timeout && !killed_by_timeout {
                    // Kill the entire process group (negative PID)
                    // The child runs in a PID namespace where it's PID 1,
                    // but from our namespace we see the real PID.
                    // Use SIGKILL on the process - the PID namespace
                    // will ensure all children are killed when init (pid 1) dies.
                    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);

                    // Also try to kill the process group just in case
                    unsafe {
                        libc::kill(-(pid.as_raw()), libc::SIGKILL);
                    }

                    killed_by_timeout = true;
                    kill_time = Some(Instant::now());
                }

                // If the child was killed but hasn't exited after 5 seconds
                // (e.g., stuck in uninterruptible D-state), give up rather
                // than spinning forever.
                if let Some(kt) = kill_time {
                    if kt.elapsed() > Duration::from_secs(5) {
                        return Err(SandboxError::ExecutionFailed(
                            "child unkillable after SIGKILL (5s post-kill timeout expired)".into(),
                        ));
                    }
                }

                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
