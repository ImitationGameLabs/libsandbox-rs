//! Error types for libsandbox.
//!
//! [`SandboxError`] is a flat `{ kind, context }` struct rather than a large
//! enum: the historical variants carried typed fields (`MemoryExceeded {
//! used, limit }`, `Timeout { duration }`, …) that no caller ever destructured
//! — they were display-only, and the same data is already available on
//! [`crate::result::ExecutionResult`] / [`crate::result::ExecutionReport`] as
//! typed fields. Collapsing to a kind discriminator + context string halves
//! the type surface (one struct + one enum) while keeping the only thing
//! callers actually do with errors: match on [`ErrorKind`] via [`kind`](SandboxError::kind).
//!
//! Child-side setup failures arrive over the spawn error-pipe as a
//! `[tag:u8][msg:bytes]` frame; the parent decodes the tag into a [`ChildStage`]
//! and builds the context string.

/// Coarse discriminator for programmatic error matching.
///
/// Use [`SandboxError::kind`] to obtain this from any error, then match on it
/// instead of stringifying the error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Platform not supported / feature unavailable.
    Platform,
    /// Namespace creation or entry, user-namespace disabled.
    Namespace,
    /// Mount, bind, pivot, dynamic mount, mount path validation.
    Mount,
    /// Cgroup creation, controller availability, control-file writes.
    Cgroup,
    /// Seccomp / security filter build or load, blocked syscall.
    Seccomp,
    /// Landlock filesystem-access ruleset build, support probe, or `restrict_self`.
    Landlock,
    /// Resource limit (cgroup-backed or rlimit) unavailable or exceeded.
    Resource,
    /// Network policy denial.
    Network,
    /// Process execution: command not found, exec failure, signal exit, child setup.
    Exec,
    /// Execution timeout.
    Timeout,
    /// Configuration / validation error.
    Config,
    /// Underlying IO error.
    Io,
    /// The child process has already exited.
    ChildGone,
    /// Anything not covered by a dedicated variant.
    Other,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Platform => "platform",
            Self::Namespace => "namespace",
            Self::Mount => "mount",
            Self::Cgroup => "cgroup",
            Self::Seccomp => "seccomp",
            Self::Landlock => "landlock",
            Self::Resource => "resource",
            Self::Network => "network",
            Self::Exec => "exec",
            Self::Timeout => "timeout",
            Self::Config => "config",
            Self::Io => "io",
            Self::ChildGone => "child-gone",
            Self::Other => "other",
        };
        f.write_str(s)
    }
}

/// Lifecycle stage of the sandboxed child at which a setup failure occurred.
///
/// Doubles as the on-wire tag for the spawn error-pipe (`[tag:u8][msg:bytes]`):
/// the child writes the discriminant, the parent maps it back via [`from_tag`](Self::from_tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChildStage {
    /// Generic startup failure (e.g. abort before a specific stage ran).
    Startup = 0,
    /// Closing / arranging inherited file descriptors.
    Fd = 1,
    /// `dup2` of stdio fds.
    Dup2 = 2,
    /// `sethostname` (UTS namespace).
    Sethostname = 3,
    /// Mount namespace setup (bind / tmpfs / procfs / pivot).
    Mount = 4,
    /// `chdir` to working directory.
    Chdir = 5,
    /// `setrlimit` resource limits.
    Rlimit = 6,
    /// seccomp filter load.
    Seccomp = 7,
    /// Caller-supplied [`crate::ChildSetup`] hook.
    Hook = 8,
    /// `execvpe` of the target program.
    Exec = 9,
}

impl ChildStage {
    /// Decode a wire tag byte into a stage. Unknown bytes map to [`Startup`].
    ///
    /// [`Startup`]: ChildStage::Startup
    pub fn from_tag(tag: u8) -> Self {
        match tag {
            x if x == Self::Fd as u8 => Self::Fd,
            x if x == Self::Dup2 as u8 => Self::Dup2,
            x if x == Self::Sethostname as u8 => Self::Sethostname,
            x if x == Self::Mount as u8 => Self::Mount,
            x if x == Self::Chdir as u8 => Self::Chdir,
            x if x == Self::Rlimit as u8 => Self::Rlimit,
            x if x == Self::Seccomp as u8 => Self::Seccomp,
            x if x == Self::Hook as u8 => Self::Hook,
            x if x == Self::Exec as u8 => Self::Exec,
            _ => Self::Startup,
        }
    }
}

impl std::fmt::Display for ChildStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Startup => "startup",
            Self::Fd => "fd-setup",
            Self::Dup2 => "dup2",
            Self::Sethostname => "sethostname",
            Self::Mount => "mount",
            Self::Chdir => "chdir",
            Self::Rlimit => "rlimit",
            Self::Seccomp => "seccomp",
            Self::Hook => "child-hook",
            Self::Exec => "exec",
        };
        f.write_str(s)
    }
}

/// The libsandbox error type: a coarse [`ErrorKind`] plus a human-readable
/// context string.
///
/// Construct with [`SandboxError::new`]; IO/FFI errors convert via `?`
/// (`From<io::Error>`, `From<NulError>`). Match on [`kind`](Self::kind) for
/// programmatic decisions.
#[derive(thiserror::Error, Debug)]
#[error("{kind}: {context}")]
pub struct SandboxError {
    kind: ErrorKind,
    context: Box<str>,
}

impl SandboxError {
    /// Build an error from a kind and an arbitrary context string.
    pub fn new(kind: ErrorKind, context: impl Into<Box<str>>) -> Self {
        Self {
            kind,
            context: context.into(),
        }
    }

    /// Coarse category of this error for programmatic matching.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The human-readable context string.
    pub fn context(&self) -> &str {
        &self.context
    }
}

impl From<std::io::Error> for SandboxError {
    fn from(e: std::io::Error) -> Self {
        Self::new(ErrorKind::Io, e.to_string())
    }
}

impl From<std::ffi::NulError> for SandboxError {
    fn from(e: std::ffi::NulError) -> Self {
        Self::new(ErrorKind::Config, e.to_string())
    }
}

/// Result type alias for libsandbox operations.
pub type Result<T> = std::result::Result<T, SandboxError>;
