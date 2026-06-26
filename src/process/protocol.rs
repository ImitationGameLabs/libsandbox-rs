//! Parent-side spawn protocol.
//!
//! [`prepare_sandbox`] computes everything that can be decided before touching
//! the kernel (clone flags, compiled seccomp filter, rlimit plan, argv/env,
//! the child setup hook) into a self-contained [`PreparedSandbox`]. It holds
//! **no** kernel resources.
//!
//! [`run_prepared`] owns the actual protocol — the sequence whose ordering is a
//! correctness invariant, not a composable choice:
//!
//! ```text
//! create ready/error pipes
//!   → clone(flags)                       // child runs exec_sandboxed, blocks on ready-pipe
//!   → post_clone_protocol(child)         // write uid/gid maps → create+attach cgroup
//!   → write ready byte                   // release the child
//!   → non-blocking error drain           // surface any child setup failure
//!   → pidfd + namespace fds
//!   → Child
//! ```
//!
//! The child unblocks only after the parent has written `uid_map`/`gid_map`
//! (required before any privileged op in the user namespace) and attached the
//! child to its cgroup (required before the child forks, so descendants are
//! charged). Reordering these breaks correctness.

use super::child::{Child, NamespaceFds, StdioFds};
use super::child_setup::{exec_sandboxed, ChildCtx, ChildPayload, ChildSetup, PreparedRlimits};
use super::fd::{
    abort_child_startup, kill_and_reap, open_namespace_fd, read_retry, try_pidfd_open, AutoCloseFd,
};
use crate::builder::SandboxConfig;
use crate::cgroup::{configure_cgroup, needs_cgroup, LimitPlan};
use crate::config::{ExecutionPolicy, NetworkMode};
use crate::error::{ChildStage, ErrorKind, Result, SandboxError};
use crate::namespace::UserNamespace;
use crate::network::ProxiedNetwork;
use crate::result::{LimitDiagnostics, LimitStatus};
use crate::seccomp::SeccompFilter;
use crate::stdio::{Stdio, StdioSlot, StreamRole};
use nix::fcntl::OFlag;
use nix::sched::CloneFlags;
use nix::sys::signal::Signal;
use nix::unistd::{pipe, pipe2};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::IntoRawFd;

const STACK_SIZE: usize = 1024 * 1024;

/// Derive `clone(2)` flags from the namespace config + the network mode.
///
/// The network-namespace decision follows [`NetworkMode`] (the single source
/// of truth): `None` ⇒ isolated net namespace (`CLONE_NEWNET`); `Host`/`Proxied`
/// ⇒ share the host net namespace. "Proxied" is a network *policy* (HTTP proxy
/// on host loopback), not a topology, so it deliberately does not add
/// `CLONE_NEWNET`.
pub(crate) fn derive_clone_flags(
    ns: &crate::config::NamespaceConfig,
    net_isolated: bool,
) -> CloneFlags {
    let mut flags = CloneFlags::empty();
    if ns.user {
        flags |= CloneFlags::CLONE_NEWUSER;
    }
    if ns.pid {
        flags |= CloneFlags::CLONE_NEWPID;
    }
    if ns.mount {
        flags |= CloneFlags::CLONE_NEWNS;
    }
    if ns.uts {
        flags |= CloneFlags::CLONE_NEWUTS;
    }
    if ns.ipc {
        flags |= CloneFlags::CLONE_NEWIPC;
    }
    if net_isolated {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    flags
}

/// A fully-resolved, ready-to-run sandbox description.
///
/// Built by [`prepare_sandbox`] and consumed by [`run_prepared`]. Holds no
/// kernel resources — the ready/error pipes, the proxy runtime, and the cgroup
/// are all created inside `run_prepared`.
pub struct PreparedSandbox {
    clone_flags: CloneFlags,
    config: SandboxConfig,
    policy: ExecutionPolicy,
    user_ns: UserNamespace,
    hostname: Option<String>,
    working_dir: std::path::PathBuf,
    rlimits: PreparedRlimits,
    seccomp: Option<SeccompFilter>,
    child_hook: Option<ChildSetup>,
    ctx: ChildCtx,
    argv: Vec<CString>,
    /// Base environment (before proxy env vars are merged in at run time).
    base_env: HashMap<String, String>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
}

/// Pre-compute a sandbox description without touching the kernel.
///
/// Compiles the seccomp filter, derives clone flags, builds argv, and freezes
/// the child setup hook. The returned [`PreparedSandbox`] is opaque; pass it
/// to [`run_prepared`].
#[allow(clippy::too_many_arguments)]
pub fn prepare_sandbox(
    config: &SandboxConfig,
    policy: &ExecutionPolicy,
    cmd: &str,
    args: &[&str],
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    child_setup: Option<ChildSetup>,
) -> Result<PreparedSandbox> {
    let net_isolated = matches!(config.network.mode, NetworkMode::None);
    let clone_flags = derive_clone_flags(&config.namespace, net_isolated);

    let user_ns = UserNamespace::new(config.security.uid, config.security.gid);

    // argv[0] = cmd
    let mut argv: Vec<CString> = args
        .iter()
        .map(|s| CString::new(*s))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    argv.insert(0, CString::new(cmd)?);

    // Base environment (proxy env vars are merged in at run time).
    let default_path =
        std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());
    let mut base_env: HashMap<String, String> = if config.environment.clear_env {
        HashMap::new()
    } else {
        std::env::vars().collect()
    };
    base_env.extend(config.environment.env.clone());
    if !base_env.contains_key("PATH") {
        base_env.insert("PATH".into(), default_path);
    }

    let hostname = if config.namespace.uts {
        Some(config.environment.hostname.clone())
    } else {
        None
    };

    let rlimits = super::child_setup::prepare_rlimits(&config.resources);
    let seccomp = super::child_setup::prepare_seccomp(&config.security.seccomp_profile)?;

    let ctx = ChildCtx {
        uid: user_ns.inner_uid(),
        gid: user_ns.inner_gid(),
        has_user_ns: config.namespace.user,
        has_mount_ns: config.namespace.mount,
        has_pid_ns: config.namespace.pid,
        has_net_ns: net_isolated,
    };

    Ok(PreparedSandbox {
        clone_flags,
        config: config.clone(),
        policy: policy.clone(),
        user_ns,
        hostname,
        working_dir: config.filesystem.working_dir.clone(),
        rlimits,
        seccomp,
        child_hook: child_setup,
        ctx,
        argv,
        base_env,
        stdin,
        stdout,
        stderr,
    })
}

// Parent-side post-clone invariants (write uid/gid maps → create+attach
// cgroup) are inlined into `run_prepared` below — single implementation,
// never composed, because the ordering is a correctness invariant.

/// Execute the prepared sandbox: clone the child, run the parent-side
/// invariants, release the child, and return the [`Child`] handle plus limit
/// diagnostics.
pub fn run_prepared(mut prep: PreparedSandbox) -> Result<(Child, LimitDiagnostics)> {
    // 1. Start the network proxy (if proxied mode). Holds a tokio runtime.
    #[cfg(feature = "tokio")]
    let proxy = match &prep.config.network.mode {
        NetworkMode::Proxied { allowed_domains } => {
            Some(ProxiedNetwork::setup(allowed_domains.clone())?)
        }
        _ => None,
    };
    #[cfg(not(feature = "tokio"))]
    let proxy: Option<ProxiedNetwork> = None; // Proxied mode is unconstructible.

    // 2. Resolve stdio (opens pipes / /dev/null).
    let mut stdin_slot = StdioSlot::resolve(prep.stdin, StreamRole::Stdin)?;
    let mut stdout_slot = StdioSlot::resolve(prep.stdout, StreamRole::Stdout)?;
    let mut stderr_slot = StdioSlot::resolve(prep.stderr, StreamRole::Stderr)?;

    // 3. Create ready (parent->child) and error (child->parent) pipes. The error
    //    pipe is created with `O_CLOEXEC` so the child's write end auto-closes at
    //    `execvpe`: the parent's drain then sees EOF exactly when the child
    //    commits to running the target program, regardless of which setup path
    //    ran. This is the guarantee the blocking drain (step 10) relies on.
    let (r, w) = pipe().map_err(|e| {
        SandboxError::new(
            ErrorKind::Exec,
            format!("create pipe for parent-child sync: {e}"),
        )
    })?;
    let mut ready_read = AutoCloseFd::new(r.into_raw_fd());
    let ready_write = AutoCloseFd::new(w.into_raw_fd());

    let (r, w) = pipe2(OFlag::O_CLOEXEC).map_err(|e| {
        SandboxError::new(
            ErrorKind::Exec,
            format!("create pipe for error reporting: {e}"),
        )
    })?;
    let mut error_read = AutoCloseFd::new(r.into_raw_fd());
    let error_write = AutoCloseFd::new(w.into_raw_fd());

    // 4. Merge proxy env vars into the base env, then build envp CStrings.
    let mut env = std::mem::take(&mut prep.base_env);
    #[cfg(feature = "tokio")]
    if let Some(ref proxy_guard) = proxy {
        for (key, value) in proxy_guard.env_vars() {
            env.insert(key, value);
        }
    }
    #[cfg(not(feature = "tokio"))]
    let _ = &mut env; // suppress unused-mut when the proxy branch is absent
    let envp: Vec<CString> = env
        .iter()
        .map(|(key, value)| CString::new(format!("{key}={value}")))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // 5. Assemble the child payload (pre-computed parts + run-time pipe fds).
    let payload = ChildPayload {
        ready_read_fd: ready_read.raw(),
        error_write_fd: error_write.raw(),
        parent_ready_write_fd: ready_write.raw(),
        parent_error_read_fd: error_read.raw(),
        stdin_close_in_child: stdin_slot.close_in_child,
        stdout_close_in_child: stdout_slot.close_in_child,
        stderr_close_in_child: stderr_slot.close_in_child,
        stdio_fds: [
            stdin_slot.child_fd,
            stdout_slot.child_fd,
            stderr_slot.child_fd,
        ],
        hostname: prep.hostname.take(),
        filesystem: prep.config.filesystem.clone(),
        working_dir: prep.working_dir.clone(),
        rlimits: prep.rlimits,
        seccomp: prep.seccomp.take(),
        child_hook: prep.child_hook.take(),
        ctx: prep.ctx,
        argv: prep.argv,
        envp,
    };

    // 6. clone(). The child runs exec_sandboxed(&payload), blocking on the
    //    ready-pipe before doing anything.
    let mut stack = vec![0u8; STACK_SIZE];
    let user_ns_for_protocol = prep.user_ns.clone();
    let clone_flags = prep.clone_flags;
    let config_for_protocol = prep.config.clone();
    let policy_for_protocol = prep.policy.clone();

    let child_fn: Box<dyn FnMut() -> isize> = Box::new(move || exec_sandboxed(&payload));
    let child_pid = unsafe {
        nix::sched::clone(
            child_fn,
            &mut stack,
            clone_flags,
            Some(Signal::SIGCHLD as i32),
        )
    }
    .map_err(|e| SandboxError::new(ErrorKind::Exec, format!("clone sandboxed process: {e}")))?;

    // 7. Parent: close the child-side fds.
    let mut ready_write = ready_write;
    ready_read.close().map_err(|e| {
        abort_child_startup(
            child_pid,
            &mut ready_write,
            format!("close sync pipe read end in parent: {e}"),
        )
    })?;
    let mut error_write_owned = error_write;
    error_write_owned.close().map_err(|e| {
        abort_child_startup(
            child_pid,
            &mut ready_write,
            format!("close error pipe write end in parent: {e}"),
        )
    })?;
    stdin_slot.close_child_fd_in_parent();
    stdout_slot.close_child_fd_in_parent();
    stderr_slot.close_child_fd_in_parent();

    // 8. Parent-side invariants: uid/gid maps → cgroup attach. On failure,
    //    drop the ready-pipe so the child aborts, then reap.
    if let Err(e) = user_ns_for_protocol.write_mappings(child_pid.as_raw()) {
        drop(ready_write);
        kill_and_reap(child_pid);
        return Err(e);
    }
    let limit_plan = LimitPlan::from(&config_for_protocol, &policy_for_protocol);
    let sandbox_id = format!("libsandbox-{}", child_pid.as_raw());
    let (cgroup, limit_diagnostics) = if needs_cgroup(&config_for_protocol) {
        match configure_cgroup(
            &config_for_protocol,
            &limit_plan,
            &sandbox_id,
            child_pid.as_raw() as u32,
        ) {
            Ok(result) => result,
            Err(e) => {
                drop(ready_write);
                kill_and_reap(child_pid);
                return Err(e);
            }
        }
    } else {
        (
            None,
            LimitDiagnostics {
                memory: LimitStatus::NotRequested,
                cpu: LimitStatus::NotRequested,
                pids: LimitStatus::NotRequested,
            },
        )
    };

    // 9. Release the child.
    ready_write.write_byte_and_close(0).map_err(|e| {
        abort_child_startup(
            child_pid,
            &mut ready_write,
            format!("signal child to continue: {e}"),
        )
    })?;

    // 10. Blocking error drain. The child either closes the error pipe on
    //     successful setup (the success signal: `exec_sandboxed`'s last step
    //     before exec, and the pipe is O_CLOEXEC so it auto-closes at exec
    //     regardless) or writes a `[tag:u8][msg]` frame then closes on failure.
    //     We BLOCK on the read until the child commits -- this is what makes
    //     every setup failure surface here instead of being missed as a
    //     non-blocking EAGAIN and later confused with the target program exiting
    //     non-zero. The child always commits in bounded time (the built-in steps
    //     are bounded kernel calls; only a caller `ChildSetup` hook could hang,
    //     which is the caller's responsibility). The drain cost counts toward
    //     `report.duration` (clocked from `run()` entry) but NOT toward the
    //     `wall_time_limit` kill budget, whose timer starts at `wait_with_timeout`
    //     entry, after this drain.
    let mut error_buf = [0u8; 4096];
    match read_retry(error_read.raw(), &mut error_buf) {
        Ok(0) => {
            // EOF -- child closed without writing: successful setup.
            let _ = error_read.close();
        }
        Ok(n) => {
            // Frame start. The child writes the whole frame then closes, so we
            // loop-read until EOF to reassemble the complete frame however the
            // kernel split the delivery, then decode `[tag][msg]`.
            let mut frame = error_buf[..n].to_vec();
            loop {
                match read_retry(error_read.raw(), &mut error_buf) {
                    Ok(0) | Err(_) => break,
                    Ok(m) => frame.extend_from_slice(&error_buf[..m]),
                }
            }
            let _ = error_read.close();
            let (tag_byte, msg_bytes) = frame.split_first().unwrap_or((&0, &[]));
            let stage = ChildStage::from_tag(*tag_byte);
            let msg = String::from_utf8_lossy(msg_bytes);
            kill_and_reap(child_pid);
            return Err(SandboxError::new(
                ErrorKind::Exec,
                format!("child setup failed at {}: {}", stage, msg),
            ));
        }
        Err(e) => {
            // Unexpected read error on a fresh pipe; surface it rather than mask.
            let _ = error_read.close();
            kill_and_reap(child_pid);
            return Err(SandboxError::new(
                ErrorKind::Exec,
                format!("read child error pipe: {e}"),
            ));
        }
    }

    // 11. pidfd + namespace fds (survive child exit for dynamic mounts).
    let pidfd = try_pidfd_open(child_pid.as_raw());
    let user_ns_fd = open_namespace_fd(child_pid.as_raw(), "user");
    let mnt_ns_fd = open_namespace_fd(child_pid.as_raw(), "mnt");

    let _ = stdin_slot.child_fd; // child_fd consumed into payload above (Copy); nothing to close here
    let child = Child::new(
        child_pid.as_raw(),
        pidfd,
        StdioFds {
            stdin: stdin_slot.take_parent_fd(),
            stdout: stdout_slot.take_parent_fd(),
            stderr: stderr_slot.take_parent_fd(),
        },
        cgroup,
        proxy,
        NamespaceFds {
            user: user_ns_fd,
            mnt: mnt_ns_fd,
        },
    );
    Ok((child, limit_diagnostics))
}
