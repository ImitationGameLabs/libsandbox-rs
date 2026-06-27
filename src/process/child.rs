//! A spawned sandboxed process handle.
//!
//! [`Child`] owns the child PID, any pipe fds created for I/O, the cgroup
//! used for resource limits, and the optional network proxy guard. When
//! dropped without being explicitly waited on, the child is killed and
//! reaped to prevent zombie processes.

use crate::cgroup::CgroupManager;
use crate::error::{ErrorKind, Result, SandboxError};
use crate::mount::handle::MountHandle;
use crate::network::ProxiedNetwork;
use std::os::fd::{FromRawFd, OwnedFd};

// ---------------------------------------------------------------------------
// Grouped parameter types for Child::new
// ---------------------------------------------------------------------------

/// Parent-end pipe file descriptors for child stdio.
///
/// Each field is `Some(fd)` when the corresponding stdio stream was configured
/// as `Stdio::Pipe`; otherwise `None` (inherited or null).
pub(crate) struct StdioFds {
    pub(crate) stdin: Option<OwnedFd>,
    pub(crate) stdout: Option<OwnedFd>,
    pub(crate) stderr: Option<OwnedFd>,
}

/// Pre-opened namespace file descriptors for dynamic mount operations.
///
/// These remain valid after the child exits because the kernel holds a
/// reference count on the namespace as long as any fd refers to it.
pub(crate) struct NamespaceFds {
    pub(crate) user: Option<OwnedFd>,
    pub(crate) mnt: Option<OwnedFd>,
}

/// Exit status of a sandboxed child process.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitStatus {
    /// The exit code returned by the process (0 typically means success).
    pub(crate) code: i32,

    /// If the process was killed by a signal, the signal number.
    pub(crate) signal: Option<i32>,
}

impl ExitStatus {
    /// Construct from a normal exit code.
    pub(crate) fn from_exit(code: i32) -> Self {
        Self { code, signal: None }
    }

    /// Construct from a fatal signal.
    pub(crate) fn from_signal(sig: i32) -> Self {
        Self {
            code: 128 + sig,
            signal: Some(sig),
        }
    }

    /// The exit code returned by the process.
    ///
    /// For signal deaths, this follows the shell convention of `128 + signal`.
    pub fn code(&self) -> i32 {
        self.code
    }

    /// If the process was killed by a signal, the signal number.
    pub fn signal(&self) -> Option<i32> {
        self.signal
    }

    /// Returns `true` if the exit code is 0 and no signal was received.
    pub fn success(&self) -> bool {
        self.code == 0 && self.signal.is_none()
    }
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.signal {
            Some(sig) => write!(f, "signal {}", sig),
            None => write!(f, "exit code {}", self.code),
        }
    }
}

/// A handle to a spawned sandboxed process.
///
/// The `Child` owns all resources tied to the sandboxed process:
/// - The child PID (for signalling and waiting)
/// - Parent-end pipe fds when `Stdio::Pipe` was used
/// - The cgroup manager (cleaned up on drop)
/// - The network proxy guard (shut down on drop)
///
/// If dropped without calling [`wait`](Child::wait), the child is killed
/// and reaped automatically to prevent zombie processes.
pub struct Child {
    pid: i32,
    /// pidfd for reliable process lifecycle management (Linux 5.3+).
    /// When available, kill() uses pidfd_send_signal instead of kill(pid),
    /// eliminating PID recycling races. Uses OwnedFd for RAII cleanup.
    pidfd: Option<OwnedFd>,
    stdio: StdioFds,
    cgroup: Option<CgroupManager>,
    _proxy: Option<ProxiedNetwork>,
    waited: bool,
    /// Pre-opened namespace fds for dynamic mount operations.
    ns_fds: NamespaceFds,
}

impl std::fmt::Debug for Child {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Child")
            .field("pid", &self.pid)
            .field("pidfd", &self.pidfd.as_ref().map(|_| "some"))
            .field("waited", &self.waited)
            .field("stdin", &self.stdio.stdin.as_ref().map(|_| "some"))
            .field("stdout", &self.stdio.stdout.as_ref().map(|_| "some"))
            .field("stderr", &self.stdio.stderr.as_ref().map(|_| "some"))
            .field("cgroup", &self.cgroup.as_ref().map(|_| "some"))
            .field("_proxy", &self._proxy.as_ref().map(|_| "some"))
            .finish()
    }
}

impl Child {
    /// Wrap the raw components into a `Child`.
    ///
    /// Called by the platform-specific spawn implementation.
    pub(crate) fn new(
        pid: i32,
        pidfd: Option<OwnedFd>,
        stdio: StdioFds,
        cgroup: Option<CgroupManager>,
        proxy: Option<ProxiedNetwork>,
        ns_fds: NamespaceFds,
    ) -> Self {
        assert!(pid > 0, "Child::new called with invalid pid: {pid}");
        Self {
            pid,
            pidfd,
            stdio,
            cgroup,
            _proxy: proxy,
            waited: false,
            ns_fds,
        }
    }

    /// The PID of the sandboxed child process (in the parent's PID namespace).
    pub fn pid(&self) -> u32 {
        self.pid as u32
    }

    /// The parent-end write fd for stdin, if `Stdio::Pipe` was used.
    pub fn stdin_fd(&self) -> Option<&OwnedFd> {
        self.stdio.stdin.as_ref()
    }

    /// The parent-end read fd for stdout, if `Stdio::Pipe` was used.
    pub fn stdout_fd(&self) -> Option<&OwnedFd> {
        self.stdio.stdout.as_ref()
    }

    /// The parent-end read fd for stderr, if `Stdio::Pipe` was used.
    pub fn stderr_fd(&self) -> Option<&OwnedFd> {
        self.stdio.stderr.as_ref()
    }

    /// Access the cgroup manager for metric collection.
    ///
    /// **Note**: This returns a Linux-specific type. The `Child` type is
    /// currently Linux-only (the only supported platform). If multi-platform
    /// support is added in the future, this method will move to a
    /// platform-specific extension trait.
    pub fn cgroup(&self) -> Option<&CgroupManager> {
        self.cgroup.as_ref()
    }

    /// Obtain a handle for dynamic mount operations on this sandbox.
    ///
    /// The returned [`MountHandle`] owns duplicated copies of the namespace
    /// file descriptors and can be used to add, remove, or remount filesystem
    /// entries inside the running sandbox. Multiple handles can exist
    /// simultaneously (each call duplicates the fds).
    ///
    /// Returns `Err(ChildExited)` if the child process has already exited.
    /// Requires kernel >= 5.2 for the new mount API.
    pub fn mount_handle(&self) -> Result<MountHandle> {
        // Check if child is still alive.
        if let Some(ref pidfd) = self.pidfd {
            use std::os::fd::AsRawFd;
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd() as libc::c_int,
                    0 as libc::c_int,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                )
            };
            if ret < 0 {
                let errno = nix::errno::Errno::last_raw();
                if errno == libc::ESRCH {
                    return Err(SandboxError::new(
                        crate::error::ErrorKind::ChildGone,
                        "child process has exited",
                    ));
                }
            }
        }

        // Helper to duplicate an fd via F_DUPFD_CLOEXEC, returning Err on failure.
        fn dup_fd(fd: &OwnedFd) -> Result<OwnedFd> {
            use std::os::fd::AsRawFd;
            let new_fd = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if new_fd < 0 {
                let errno = nix::errno::Errno::last_raw();
                Err(SandboxError::new(
                    ErrorKind::Exec,
                    format!("F_DUPFD_CLOEXEC failed: {errno}"),
                ))
            } else {
                Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
            }
        }

        // Duplicate namespace fds.
        let user_ns_fd = self.ns_fds.user.as_ref()
            .ok_or_else(|| SandboxError::new(ErrorKind::Mount, format!("dynamic mount operation failed: {}", "namespace fds not available (child may not have been spawned with namespace support)")))
            .and_then(dup_fd)?;

        let mnt_ns_fd = self
            .ns_fds
            .mnt
            .as_ref()
            .ok_or_else(|| {
                SandboxError::new(
                    ErrorKind::Mount,
                    format!(
                        "dynamic mount operation failed: {}",
                        "namespace fds not available"
                    ),
                )
            })
            .and_then(dup_fd)?;

        // Duplicate pidfd for liveness checks inside MountHandle.
        let child_pidfd = self.pidfd.as_ref().map(dup_fd).transpose()?;

        Ok(MountHandle::new(user_ns_fd, mnt_ns_fd, child_pidfd))
    }

    /// Kill the sandboxed child and (best-effort) all of its descendants.
    ///
    /// Priority:
    /// 1. **Cgroup** (`CgroupManager::kill_all`) — atomic `cgroup.kill` file on
    ///    ≥5.14, else freeze + iterated kill. Catches every descendant
    ///    including those that escaped via `setpgid`.
    /// 2. **`kill_tree`** — iteratively walks `/proc/<pid>/.../children` and
    ///    `pidfd_send_signal`s each descendant. Best-effort fallback for the
    ///    non-cgroup case; closes the `setpgid` escape hole that `kill(-pid)`
    ///    has.
    /// 3. A final `pidfd_send_signal` on the root pidfd (PID-recycling-safe).
    ///
    /// For untrusted workloads, prefer a cgroup-backed sandbox.
    ///
    /// This is **best-effort and infallible by design**: each layer swallows
    /// its own errors — a descendant we cannot signal must not abort the rest
    /// of the sweep, and the [`Drop`] path that calls this cannot react to a
    /// failure anyway. The rare non-`ESRCH` errno from the final pidfd signal
    /// (e.g. `EBADF`, indicating a real bug) is emitted via `tracing::warn!`
    /// rather than propagated.
    pub fn kill(&self) {
        if let Some(cg) = self.cgroup.as_ref() {
            // Strongest: cgroup membership catches all descendants regardless
            // of setpgid.
            cg.kill_all();
            return;
        }

        // No cgroup: walk the descendant tree to catch setpgid-escaped
        // grandchildren that kill(-pid) would miss.
        super::kill::kill_tree(self.pid);

        // PID-recycling-safe backup on the root itself.
        if let Some(ref pidfd) = self.pidfd {
            use std::os::fd::AsRawFd;
            let raw_pidfd = pidfd.as_raw_fd();
            // SAFETY: pidfd_send_signal on a valid pidfd with null siginfo.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    raw_pidfd as libc::c_int,
                    libc::SIGKILL as libc::c_int,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                )
            };
            // ESRCH = already dead, expected. Anything else (e.g. EBADF) is a
            // real anomaly worth surfacing in the log; we still cannot act on
            // it, so the contract stays infallible.
            if ret < 0 {
                let errno = nix::errno::Errno::last();
                if errno != nix::errno::Errno::ESRCH {
                    tracing::warn!(
                        "libsandbox: pidfd_send_signal(SIGKILL) on child pid {} \
                         failed ({errno}); the process may not have been killed",
                        self.pid
                    );
                }
            }
        }
    }

    /// Non-blocking check for child exit.
    ///
    /// Returns `Ok(Some(status))` if the child has exited, `Ok(None)` if it
    /// is still running.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        let pid = nix::unistd::Pid::from_raw(self.pid);
        let result = loop {
            match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                Err(nix::errno::Errno::EINTR) => continue,
                other => break other,
            }
        };
        match result {
            Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => {
                self.waited = true;
                Ok(Some(ExitStatus::from_exit(code)))
            }
            Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                self.waited = true;
                Ok(Some(ExitStatus::from_signal(sig as i32)))
            }
            Ok(nix::sys::wait::WaitStatus::StillAlive) => Ok(None),
            Ok(_) => Ok(None),
            Err(e) => Err(SandboxError::new(
                ErrorKind::Exec,
                format!("try_waitpid: {e}"),
            )),
        }
    }

    /// Block until the child exits and return its exit status.
    ///
    /// This consumes the `Child`. After this call the cgroup is cleaned up
    /// and all pipe fds are closed.
    ///
    /// # Deadlock hazard
    ///
    /// If stdout or stderr is configured as [`Stdio::Pipe`](crate::Stdio::Pipe)
    /// and the child writes enough data to fill the OS pipe buffer (typically
    /// 64 KB), the child will block on `write()` and this call will block on
    /// `waitpid()` forever. To avoid this, call [`take_stdout_fd`](Child::take_stdout_fd)
    /// and/or [`take_stderr_fd`](Child::take_stderr_fd) before calling `wait()`,
    /// and drain the pipes concurrently (e.g., in a separate thread or using
    /// non-blocking I/O between [`try_wait`](Child::try_wait) polls).
    pub fn wait(mut self) -> Result<ExitStatus> {
        let status = self.wait_blocking()?;
        Ok(status)
    }

    /// Asynchronously wait for the child to exit (requires the `tokio` feature).
    ///
    /// Event-driven: awaits the child's pidfd for exit rather than
    /// busy-polling, so it composes with other async work. Like [`wait`](Self::wait),
    /// take and drain stdout/stderr fds beforehand to avoid pipe-buffer
    /// deadlock.
    #[cfg(feature = "tokio")]
    pub async fn wait_async(mut self) -> Result<ExitStatus> {
        let pid = nix::unistd::Pid::from_raw(self.pid);
        // No pipes here (caller drains them); large timeout — the pidfd fires
        // on actual exit.
        let (_out, _err, code, _killed_by_timeout, signal) =
            super::wait::wait_with_timeout_async(pid, None, None, std::time::Duration::MAX).await?;
        self.waited = true;
        Ok(match signal {
            Some(sig) => ExitStatus::from_signal(sig),
            None => ExitStatus::from_exit(code),
        })
    }

    /// Close the parent-end stdin fd, signalling EOF to the child.
    ///
    /// This method is idempotent — subsequent calls are no-ops.
    pub fn close_stdin(&mut self) {
        drop(self.stdio.stdin.take());
    }

    /// Take ownership of the stdin pipe fd.
    ///
    /// Returns `None` if stdin was not configured as `Stdio::Pipe`.
    /// The caller is responsible for writing to and closing the fd.
    pub fn take_stdin_fd(&mut self) -> Option<OwnedFd> {
        self.stdio.stdin.take()
    }

    /// Extract the raw child PID without consuming the `Child`.
    ///
    /// Used internally by `execute_detailed()` to pass the PID to
    /// `wait_with_timeout()`.
    pub(crate) fn raw_pid(&self) -> i32 {
        self.pid
    }

    /// Detach from the child process without killing or reaping it.
    ///
    /// Returns the child's PID as a `u32`. The caller assumes responsibility
    /// for reaping the child (e.g., via `waitpid`) to prevent zombies.
    /// After calling `detach()`, [`Drop`] will not kill or reap the child.
    ///
    /// # Resource leaks
    ///
    /// Detaching intentionally leaks:
    /// - The pidfd (if opened on Linux 5.3+) — remains open until process exit.
    /// - The cgroup — not cleaned up; the cgroup directory remains on disk.
    /// - The network proxy (if any) — remains running.
    ///
    /// This is necessary because cleanup would kill the child or tear down its
    /// network path, violating the detach contract.
    pub fn detach(mut self) -> u32 {
        let pid = self.pid as u32;
        self.waited = true;
        // Prevent Drop from killing/reaping — the caller takes over.
        let _ = self.pidfd.take();
        // Prevent CgroupManager::Drop from calling cleanup() → kill_all().
        // Without this, the cgroup cleanup would send SIGKILL to the detached child.
        std::mem::forget(self.cgroup.take());
        // Prevent ProxiedNetwork::Drop from shutting down the proxy,
        // which would kill the child's network connectivity. (Under the
        // no-tokio config ProxiedNetwork is a Drop-less ZST, so take() is
        // enough; the guard is only meaningful with the tokio feature.)
        #[cfg(feature = "tokio")]
        std::mem::forget(self._proxy.take());
        #[cfg(not(feature = "tokio"))]
        let _ = self._proxy.take();
        pid
    }

    /// Take ownership of the stdout pipe fd.
    ///
    /// Returns `None` if stdout was not configured as `Stdio::Pipe`.
    /// The caller is responsible for reading from and closing the fd.
    pub fn take_stdout_fd(&mut self) -> Option<OwnedFd> {
        self.stdio.stdout.take()
    }

    /// Take ownership of the stderr pipe fd.
    ///
    /// Returns `None` if stderr was not configured as `Stdio::Pipe`.
    /// The caller is responsible for reading from and closing the fd.
    pub fn take_stderr_fd(&mut self) -> Option<OwnedFd> {
        self.stdio.stderr.take()
    }

    /// Mark that the child has been waited on (called by `wait_with_timeout`).
    pub(crate) fn set_waited(&mut self) {
        self.waited = true;
    }

    fn wait_blocking(&mut self) -> Result<ExitStatus> {
        let pid = nix::unistd::Pid::from_raw(self.pid);
        let status = loop {
            match nix::sys::wait::waitpid(pid, None) {
                Err(nix::errno::Errno::EINTR) => continue,
                other => break other,
            }
        };
        match status {
            Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => {
                self.waited = true;
                Ok(ExitStatus::from_exit(code))
            }
            Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                self.waited = true;
                Ok(ExitStatus::from_signal(sig as i32))
            }
            Ok(other) => Err(SandboxError::new(
                ErrorKind::Exec,
                format!("unexpected waitpid status: {other:?}"),
            )),
            Err(e) => Err(SandboxError::new(ErrorKind::Exec, format!("waitpid: {e}"))),
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.waited {
            // Kill and reap to prevent zombie processes.
            self.kill();
            let pid = nix::unistd::Pid::from_raw(self.pid);

            // Poll for up to 1 second (100 iterations × 10 ms). Most
            // processes die within milliseconds of SIGKILL, but processes in
            // uninterruptible sleep (D-state, e.g., blocked on NFS) cannot be
            // killed even by SIGKILL and may take longer to reap.
            let mut reaped = false;
            for _ in 0..100 {
                // Inner loop retries EINTR without consuming the iteration budget.
                let result = loop {
                    match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                        Err(nix::errno::Errno::EINTR) => continue,
                        other => break other,
                    }
                };
                match result {
                    Ok(nix::sys::wait::WaitStatus::Exited(_, _))
                    | Ok(nix::sys::wait::WaitStatus::Signaled(_, _, _)) => {
                        reaped = true;
                        break;
                    }
                    Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    _ => break,
                }
            }

            if !reaped {
                tracing::warn!(
                    "libsandbox: failed to reap child pid {} within 1s after SIGKILL; \
                     a zombie process may accumulate",
                    self.pid
                );
            }
        }
        // pidfd (OwnedFd), pipe fds, CgroupManager, and ProxiedNetwork
        // clean up via their own Drop impls when `self` is dropped.
    }
}
