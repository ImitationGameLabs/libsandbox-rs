//! Low-level file descriptor utilities for the sandbox.
//!
//! Provides raw fd I/O helpers, RAII guard, pidfd/namespace fd openers,
//! and child process cleanup primitives used during spawn and wait.

use crate::error::{ChildStage, ErrorKind, SandboxError};
use std::os::fd::{AsFd, FromRawFd};
use std::os::unix::io::RawFd;

/// RawFd version of close
pub(super) fn close_raw(fd: RawFd) -> nix::Result<()> {
    let ret = unsafe { libc::close(fd) };
    nix::errno::Errno::result(ret).map(|_| ())
}

/// RawFd version of write
pub(super) fn write_raw(fd: RawFd, data: &[u8]) -> nix::Result<usize> {
    let ret = unsafe { libc::write(fd, data.as_ptr() as _, data.len()) };
    nix::errno::Errno::result(ret).map(|r| r as usize)
}

/// RawFd version of read
pub(super) fn read_raw(fd: RawFd, buf: &mut [u8]) -> nix::Result<usize> {
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as _, buf.len()) };
    nix::errno::Errno::result(ret).map(|r| r as usize)
}

/// Write all bytes, retrying on partial writes and EINTR.
pub(crate) fn write_all_raw(fd: RawFd, mut data: &[u8]) -> nix::Result<()> {
    while !data.is_empty() {
        match write_raw(fd, data) {
            Ok(0) => return Err(nix::errno::Errno::EPIPE),
            Ok(n) => data = &data[n..],
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Single `read(2)`, retrying on EINTR. Unlike `write_all_raw` this does NOT loop
/// to fill the buffer -- it returns whatever the kernel gives in one call. Used by
/// the spawn error-pipe drain, which loops itself to reassemble the full frame.
pub(super) fn read_retry(fd: RawFd, buf: &mut [u8]) -> nix::Result<usize> {
    loop {
        match read_raw(fd, buf) {
            Err(nix::errno::Errno::EINTR) => continue,
            other => return other,
        }
    }
}

/// Set `O_NONBLOCK` on a file descriptor.
pub(super) fn set_nonblock(fd: RawFd) -> nix::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let flags = nix::errno::Errno::result(flags)?;
    nix::errno::Errno::result(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
    Ok(())
}

/// RAII guard that closes a raw fd on drop.
pub(super) struct AutoCloseFd {
    fd: RawFd,
}

impl AutoCloseFd {
    pub(super) fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    pub(super) fn raw(&self) -> RawFd {
        self.fd
    }

    pub(super) fn write_byte_and_close(&mut self, byte: u8) -> nix::Result<()> {
        let fd = self.fd;
        // Retry on EINTR — a single byte cannot produce a partial write.
        loop {
            match write_raw(fd, &[byte]) {
                Ok(_) => break,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(e),
            }
        }
        self.close()
    }

    pub(super) fn close(&mut self) -> nix::Result<()> {
        if self.fd >= 0 {
            let fd = self.fd;
            self.fd = -1;
            close_raw(fd)?;
        }
        Ok(())
    }
}

impl Drop for AutoCloseFd {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Attempt to open a pidfd for the given PID (Linux 5.3+).
///
/// Returns `None` on kernels older than 5.3 or on any error — the caller
/// falls back to PID-based kill.
pub(super) fn try_pidfd_open(pid: i32) -> Option<std::os::fd::OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) };
    if fd >= 0 {
        // SAFETY: pidfd_open returns a new, valid fd on success.
        Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as RawFd) })
    } else {
        None
    }
}

/// Open a namespace fd for the given child PID.
///
/// Returns `None` if the namespace file cannot be opened (e.g., the child
/// has already exited or the namespace type does not exist).
pub(super) fn open_namespace_fd(pid: i32, ns_type: &str) -> Option<std::os::fd::OwnedFd> {
    let path = format!("/proc/{pid}/ns/{ns_type}");
    let c_path = std::ffi::CString::new(path).ok()?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd >= 0 {
        Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    } else {
        None
    }
}

/// Close the ready pipe and kill+reap the child, returning the error message
/// as a [`SandboxError`] at [`ChildStage::Startup`].
pub(super) fn abort_child_startup(
    child_pid: nix::unistd::Pid,
    ready_write: &mut AutoCloseFd,
    message: String,
) -> SandboxError {
    let _ = ready_write.close();
    kill_and_reap(child_pid);
    SandboxError::new(
        ErrorKind::Exec,
        format!("child setup failed at {}: {}", ChildStage::Startup, message),
    )
}

/// Send SIGKILL then poll for up to 100ms to reap the child.
/// Avoids indefinite blocking on D-state processes.
pub(super) fn kill_and_reap(child_pid: nix::unistd::Pid) {
    let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGKILL);
    for _ in 0..10 {
        // Inner loop retries EINTR without consuming the iteration budget.
        let result = loop {
            match nix::sys::wait::waitpid(child_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                Err(nix::errno::Errno::EINTR) => continue,
                other => break other,
            }
        };
        match result {
            Ok(nix::sys::wait::WaitStatus::Exited(_, _))
            | Ok(nix::sys::wait::WaitStatus::Signaled(_, _, _)) => break,
            Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                // Matches wait.rs::REAP_POLL_INTERVAL; not unified to avoid a
                // shared const module for a single literal.
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            _ => break,
        }
    }
}

/// Drain all remaining data from an optional pipe fd into `buf`.
pub(super) fn drain_owned_fd(fd: Option<&std::os::fd::OwnedFd>, buf: &mut Vec<u8>) {
    let Some(fd) = fd else { return };
    let mut tmp = [0u8; 4096];
    loop {
        match nix::unistd::read(fd.as_fd(), &mut tmp) {
            Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
    }
}
