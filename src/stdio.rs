//! Standard I/O configuration for spawned sandboxed processes.
//!
//! Modeled after [`std::process::Stdio`] — each variant describes how a
//! specific standard stream (stdin, stdout, stderr) should be set up inside
//! the sandboxed child.

use std::fmt;
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, RawFd};

/// Describes what to do with a standard I/O stream for a spawned child.
#[derive(Debug)]
pub enum Stdio {
    /// Inherit the corresponding stream from the parent process.
    Inherit,

    /// Redirect the stream to `/dev/null`.
    Null,

    /// Create a pipe pair. The child end is dup2'd onto the standard stream;
    /// the parent end is returned via [`crate::Child`] so the caller can
    /// read child output or write child input.
    Pipe,

    /// Use a caller-provided file descriptor.
    ///
    /// The fd is dup2'd onto the standard stream inside the child. After the
    /// child is spawned, the parent's copy of the fd is closed automatically.
    /// The caller should not rely on this fd remaining open in the parent
    /// after spawn.
    ///
    /// Typical use: the slave end of a PTY pair, where the caller keeps the
    /// master end and lets libsandbox manage the slave end's lifetime in the
    /// parent process.
    Owned(OwnedFd),
}

impl Stdio {
    /// Default for stdin: [`Stdio::Null`].
    pub fn default_stdin() -> Self {
        Stdio::Null
    }

    /// Default for stdout: [`Stdio::Pipe`].
    pub fn default_stdout() -> Self {
        Stdio::Pipe
    }

    /// Default for stderr: [`Stdio::Pipe`].
    pub fn default_stderr() -> Self {
        Stdio::Pipe
    }
}

impl From<OwnedFd> for Stdio {
    fn from(fd: OwnedFd) -> Self {
        Stdio::Owned(fd)
    }
}

impl From<std::fs::File> for Stdio {
    fn from(file: std::fs::File) -> Self {
        Stdio::Owned(file.into())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — stream role and resolved fd state
// ---------------------------------------------------------------------------

/// Identifies which standard stream is being configured.
///
/// Used by [`StdioSlot::resolve`] to determine pipe direction without
/// relying on fragile string comparisons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StreamRole {
    Stdin,
    Stdout,
    Stderr,
}

impl fmt::Display for StreamRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StreamRole::Stdin => "stdin",
            StreamRole::Stdout => "stdout",
            StreamRole::Stderr => "stderr",
        })
    }
}

/// Tracks the file-descriptor arrangement for one standard stream between
/// the parent and the child after [`StdioSlot::resolve`].
pub(super) struct StdioSlot {
    /// The fd that will be dup2'd to STDIN/STDOUT/STDERR inside the child.
    /// `None` means "do nothing" (Inherit).
    pub child_fd: Option<RawFd>,

    /// The parent-side fd to return in `Child` (only set for `Pipe` mode).
    pub parent_fd: Option<OwnedFd>,

    /// Whether the parent should close `child_fd` after clone() succeeds.
    pub close_in_parent: bool,

    /// The fd the child must close (the parent's end of the pipe). After
    /// `clone()`, the child inherits a copy of every open fd. If we don't
    /// close the parent-side pipe fd in the child, the child holds open the
    /// "other end" of the pipe, preventing EOF propagation.
    pub close_in_child: Option<RawFd>,
}

impl StdioSlot {
    /// Consume the [`Stdio`] configuration and produce the fd arrangement.
    ///
    /// For `Pipe`, a new pipe pair is created. For `Null`, `/dev/null` is
    /// opened. For `Owned`, the fd is extracted without closing it in the
    /// parent. For `Inherit`, both sides are `None`.
    pub fn resolve(stdio: Stdio, role: StreamRole) -> crate::error::Result<Self> {
        use crate::error::SandboxError;
        use std::os::unix::io::{FromRawFd, IntoRawFd};

        match stdio {
            Stdio::Inherit => Ok(StdioSlot {
                child_fd: None,
                parent_fd: None,
                close_in_parent: false,
                close_in_child: None,
            }),

            Stdio::Null => {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/null")
                    .map_err(|e| {
                        SandboxError::Internal(format!("open /dev/null for {role}: {e}"))
                    })?;
                // into_raw_fd() consumes the File; fd stays open.
                let fd = file.into_raw_fd();
                Ok(StdioSlot {
                    child_fd: Some(fd),
                    parent_fd: None,
                    close_in_parent: true,
                    close_in_child: None,
                })
            }

            Stdio::Pipe => {
                let (read_end, write_end) = nix::unistd::pipe()
                    .map_err(|e| SandboxError::Internal(format!("create pipe for {role}: {e}")))?;
                let r: RawFd = read_end.into_raw_fd();
                let w: RawFd = write_end.into_raw_fd();

                // For stdin: parent writes → child reads.
                // For stdout/stderr: child writes → parent reads.
                let (child_fd, parent_fd, child_closes) = match role {
                    // stdin: child reads r, parent writes w, child must close w
                    StreamRole::Stdin => (r, w, Some(w)),
                    // stdout/stderr: child writes w, parent reads r, child must close r
                    StreamRole::Stdout | StreamRole::Stderr => (w, r, Some(r)),
                };

                Ok(StdioSlot {
                    child_fd: Some(child_fd),
                    // SAFETY: `parent_fd` was just obtained from `into_raw_fd()` on one
                    // end of a pipe created by `nix::unistd::pipe()`. It is a valid,
                    // exclusively-owned fd that has not been closed.
                    parent_fd: Some(unsafe { OwnedFd::from_raw_fd(parent_fd) }),
                    close_in_parent: true,
                    close_in_child: child_closes,
                })
            }

            Stdio::Owned(fd) => {
                // Guard against accidentally passing fd 0/1/2, which would
                // cause close_in_parent to close the parent's own std streams.
                debug_assert!(
                    fd.as_raw_fd() > 2,
                    "Stdio::Owned fd should not be 0, 1, or 2 \
                     (would close parent's standard streams)"
                );
                // into_raw_fd() consumes the OwnedFd; fd stays open.
                // The parent closes it after clone() (the child inherits a copy).
                let raw = fd.into_raw_fd();
                Ok(StdioSlot {
                    child_fd: Some(raw),
                    parent_fd: None,
                    close_in_parent: true,
                    close_in_child: None,
                })
            }
        }
    }

    /// Close the child-side fd in the parent after clone() returns.
    ///
    /// After closing, clears `close_in_parent` and `child_fd` so that the
    /// [`Drop`] impl does not double-close.
    pub fn close_child_fd_in_parent(&mut self) {
        if self.close_in_parent {
            if let Some(fd) = self.child_fd {
                let _ = nix::unistd::close(fd);
            }
            self.close_in_parent = false;
            self.child_fd = None;
        }
    }

    /// Take ownership of the parent-side fd.
    ///
    /// Returns `None` if no parent fd was created (Inherit / Null modes).
    /// After this call, `parent_fd` is `None` so the `Drop` impl won't
    /// touch it.
    pub fn take_parent_fd(&mut self) -> Option<OwnedFd> {
        self.parent_fd.take()
    }
}

impl Drop for StdioSlot {
    fn drop(&mut self) {
        // RAII fallback: if close_child_fd_in_parent() was never called
        // (e.g., spawn_isolated failed before clone()), close the fd now.
        if self.close_in_parent {
            if let Some(fd) = self.child_fd {
                let _ = nix::unistd::close(fd);
            }
        }
    }
}
