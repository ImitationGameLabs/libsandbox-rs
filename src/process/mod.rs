//! Process lifecycle: spawn, fd management, wait, and child handle.
//!
//! The spawn pipeline is split into a parent-side *protocol* (`protocol`: the
//! ordered `clone`/`uid_map`/`cgroup`/ready-pipe sequence) and a child-side
//! *toolbox* (`child_setup`: pre-computed payload + async-signal-safe
//! installers + the `exec_sandboxed` entrypoint). [`Child`] is the public
//! handle for a spawned process.

pub(crate) mod child;
pub(crate) mod child_setup;
pub(crate) mod fd;
pub(crate) mod kill;
pub(crate) mod protocol;
pub(crate) mod spawn;
pub(crate) mod wait;

// Public re-exports
pub use child::{Child, ExitStatus};
pub use child_setup::{
    install_rlimits, install_seccomp, prepare_rlimits, prepare_seccomp, ChildCtx, ChildPayload,
    ChildSetup, PreparedRlimits,
};
pub use protocol::{prepare_sandbox, run_prepared, PreparedSandbox};

// Crate-internal re-exports
pub(crate) use spawn::{run, spawn};
