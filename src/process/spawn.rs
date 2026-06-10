//! Core spawn pipeline for sandboxed child processes.
//!
//! [`spawn_isolated`] is the shared foundation for both the one-shot
//! execution API ([`LinuxExecutor::execute_detailed`]) and the persistent
//! process API ([`LinuxExecutor::spawn`]). It handles `clone()` + namespace
//! setup + parent-child synchronization, but does **not** wait for the child
//! to exit — that responsibility belongs to the caller.

use super::child::Child;
use super::fd::{
    abort_child_startup, close_raw, kill_and_reap, open_namespace_fd, read_raw, set_nonblock,
    try_pidfd_open, write_all_raw, AutoCloseFd,
};
use crate::builder::SandboxConfig;
use crate::cgroup::{apply_resource_limits, configure_cgroup, needs_cgroup, LimitPlan};
use crate::config::{ExecutionPolicy, NetworkMode, SeccompProfile};
use crate::error::{Result, SandboxError};
use crate::mount::ops::{setup_mount_namespace, setup_mount_overlays};
use crate::namespace::UserNamespace;
use crate::network::ProxiedNetwork;
use crate::result::{LimitDiagnostics, LimitStatus};
use crate::seccomp::SeccompFilter;
use crate::stdio::{Stdio, StdioSlot, StreamRole};
use std::os::unix::io::{IntoRawFd, RawFd};

/// Spawn a sandboxed child process with arbitrary stdio configuration.
///
/// This is the shared foundation for both [`LinuxExecutor::spawn`] (the
/// public persistent-process API) and [`LinuxExecutor::execute_detailed`]
/// (the one-shot API). It handles clone + namespace setup + sync, but does
/// NOT wait for the child to exit — that responsibility belongs to the caller.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_isolated(
    config: &SandboxConfig,
    policy: &ExecutionPolicy,
    cmd: &str,
    args: &[&str],
    stdin_stdio: Stdio,
    stdout_stdio: Stdio,
    stderr_stdio: Stdio,
) -> Result<(Child, LimitDiagnostics)> {
    use nix::sched::{clone, CloneFlags};
    use nix::sys::signal::Signal;
    use nix::unistd::{execvpe, pipe};
    use std::collections::HashMap;
    use std::ffi::CString;

    const STACK_SIZE: usize = 1024 * 1024;

    // 1. Setup proxy if using proxied network mode
    let proxy = match &config.network.mode {
        NetworkMode::Proxied { allowed_domains } => {
            Some(ProxiedNetwork::setup(allowed_domains.clone())?)
        }
        _ => None,
    };

    // 2. Resolve stdio fd arrangements
    let mut stdin_slot = StdioSlot::resolve(stdin_stdio, StreamRole::Stdin)?;
    let mut stdout_slot = StdioSlot::resolve(stdout_stdio, StreamRole::Stdout)?;
    let mut stderr_slot = StdioSlot::resolve(stderr_stdio, StreamRole::Stderr)?;

    // 3. Create ready pipe (parent→child synchronization)
    let (r, w) = pipe()
        .map_err(|e| SandboxError::Internal(format!("create pipe for parent-child sync: {e}")))?;
    let mut ready_read = AutoCloseFd::new(r.into_raw_fd());
    let mut ready_write = AutoCloseFd::new(w.into_raw_fd());

    // 4. Create error pipe (child→parent startup error reporting)
    let (r, w) = pipe()
        .map_err(|e| SandboxError::Internal(format!("create pipe for error reporting: {e}")))?;
    let mut error_read = AutoCloseFd::new(r.into_raw_fd());
    let mut error_write = AutoCloseFd::new(w.into_raw_fd());

    // 5. Build clone flags
    let mut clone_flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWIPC;

    if matches!(config.network.mode, NetworkMode::None) {
        clone_flags |= CloneFlags::CLONE_NEWNET;
    }

    // 6. Prepare command arguments
    let cmd_cstr = CString::new(cmd)?;
    let mut args_cstr: Vec<CString> = args
        .iter()
        .map(|s| CString::new(*s))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    args_cstr.insert(0, cmd_cstr.clone());

    // Allocate stack for child
    let mut stack = vec![0u8; STACK_SIZE];

    // Clone config for child
    let child_config = config.clone();
    let default_path =
        std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());
    let mut env: HashMap<String, String> = if config.environment.clear_env {
        HashMap::new()
    } else {
        std::env::vars().collect()
    };
    env.extend(config.environment.env.clone());

    // Add proxy environment variables if using proxied network
    if let Some(ref proxy_guard) = proxy {
        for (key, value) in proxy_guard.env_vars() {
            env.insert(key, value);
        }
    }
    if !env.contains_key("PATH") {
        env.insert("PATH".into(), default_path);
    }
    let env_cstr: Vec<CString> = env
        .iter()
        .map(|(key, value)| CString::new(format!("{key}={value}")))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let working_dir = config.filesystem.working_dir.clone();
    let hostname = config.environment.hostname.clone();
    let child_ready_write = ready_write.raw();
    let child_error_read = error_read.raw();
    let child_ready_read = ready_read.raw();
    let child_error_write = error_write.raw();

    // Capture child fds for the closure
    let child_stdin_fd = stdin_slot.child_fd;
    let child_stdout_fd = stdout_slot.child_fd;
    let child_stderr_fd = stderr_slot.child_fd;

    // Parent-side pipe fds that the child must close. After clone(), the
    // child inherits a copy of every open fd. If the child keeps the
    // parent's end of a pipe open, the pipe will never see EOF (e.g.,
    // cat would block forever reading from a stdin pipe whose write end
    // is also held open by the child itself).
    let stdin_close_in_child = stdin_slot.close_in_child;
    let stdout_close_in_child = stdout_slot.close_in_child;
    let stderr_close_in_child = stderr_slot.close_in_child;

    // Create user namespace config
    let user_ns = UserNamespace::new(config.security.uid, config.security.gid);

    // 7. Child closure
    //
    // SAFETY NOTE: This closure calls non-async-signal-safe functions
    // (CString formatting, create_dir_all via mount setup, etc.). This is
    // acceptable because:
    // - The parent blocks on write_mappings/configure_cgroup while the child
    //   blocks on the ready pipe — no concurrent signal-handler access.
    // - clone() with CLONE_NEWUSER creates a new process context, not a
    //   signal handler context.
    // Future improvement: pre-compute all path strings before clone().
    let child_fn: Box<dyn FnMut() -> isize> = Box::new(move || {
        // Close parent-side fds
        let _ = close_raw(child_ready_write);
        let _ = close_raw(child_error_read);

        // Close the parent's end of each stdio pipe. After clone() the child
        // inherited copies of every fd; without these closes the child would
        // hold open the "wrong" end of each pipe, preventing EOF propagation.
        if let Some(fd) = stdin_close_in_child {
            let _ = close_raw(fd);
        }
        if let Some(fd) = stdout_close_in_child {
            let _ = close_raw(fd);
        }
        if let Some(fd) = stderr_close_in_child {
            let _ = close_raw(fd);
        }

        // Create a new process group with this process as leader
        unsafe {
            libc::setpgid(0, 0);
        }

        // Wait for parent to setup UID/GID mappings and cgroup
        let mut buf = [0u8; 1];
        match read_raw(child_ready_read, &mut buf) {
            Ok(1) if buf[0] == 0 => {}
            _ => {
                let _ = close_raw(child_ready_read);
                return 1;
            }
        }
        let _ = close_raw(child_ready_read);

        // Helper: report error to parent via error pipe and abort.
        fn child_abort(error_write: RawFd, msg: &str) -> isize {
            let _ = write_all_raw(error_write, msg.as_bytes());
            let _ = close_raw(error_write);
            1
        }

        // Setup stdin
        if let Some(fd) = child_stdin_fd {
            if unsafe { libc::dup2(fd, libc::STDIN_FILENO) } < 0 {
                return child_abort(child_error_write, "dup2 stdin failed");
            }
            let _ = close_raw(fd);
        }

        // Setup stdout
        if let Some(fd) = child_stdout_fd {
            if unsafe { libc::dup2(fd, libc::STDOUT_FILENO) } < 0 {
                return child_abort(child_error_write, "dup2 stdout failed");
            }
            let _ = close_raw(fd);
        }

        // Setup stderr
        if let Some(fd) = child_stderr_fd {
            if unsafe { libc::dup2(fd, libc::STDERR_FILENO) } < 0 {
                return child_abort(child_error_write, "dup2 stderr failed");
            }
            let _ = close_raw(fd);
        }

        // Setup hostname (UTS namespace)
        if let Err(e) = nix::unistd::sethostname(&hostname) {
            return child_abort(child_error_write, &format!("set hostname: {e}"));
        }

        // Setup mount namespace if needed
        if let Some(rootfs) = &child_config.filesystem.rootfs {
            if let Err(e) = setup_mount_namespace(
                rootfs,
                &child_config.filesystem.mounts,
                &child_config.filesystem.tmpfs_mounts,
            ) {
                return child_abort(child_error_write, &format!("mount namespace: {e}"));
            }
        } else if let Err(e) = setup_mount_overlays(
            &child_config.filesystem.mounts,
            &child_config.filesystem.tmpfs_mounts,
        ) {
            return child_abort(child_error_write, &format!("mount overlays: {e}"));
        }

        // Change working directory
        if working_dir.exists() {
            let _ = std::env::set_current_dir(&working_dir);
        }

        apply_resource_limits(&child_config);

        // Apply seccomp filter
        if !matches!(
            child_config.security.seccomp_profile,
            SeccompProfile::Disabled
        ) {
            if let Err(e) = SeccompFilter::apply(&child_config.security.seccomp_profile) {
                return child_abort(child_error_write, &format!("seccomp: {e}"));
            }
        }

        // Close error pipe — signals successful setup to parent
        let _ = close_raw(child_error_write);

        // Execute
        let _ = execvpe(&cmd_cstr, &args_cstr, &env_cstr);
        // exec failed — parent won't see this via error pipe (write end closed
        // above), but the exit code 127 is the standard convention.
        127
    });

    // 8. Clone child
    let child_pid = unsafe {
        clone(
            child_fn,
            &mut stack,
            clone_flags,
            Some(Signal::SIGCHLD as i32),
        )
    }
    .map_err(|e| SandboxError::Internal(format!("clone sandboxed process: {e}")))?;

    // 9. Parent: close child-side fds and error pipe write end
    ready_read.close().map_err(|e| {
        abort_child_startup(
            child_pid,
            &mut ready_write,
            format!("close sync pipe read end in parent: {e}"),
        )
    })?;
    error_write.close().map_err(|e| {
        abort_child_startup(
            child_pid,
            &mut ready_write,
            format!("close error pipe write end in parent: {e}"),
        )
    })?;

    // Close child-side stdio fds in parent
    stdin_slot.close_child_fd_in_parent();
    stdout_slot.close_child_fd_in_parent();
    stderr_slot.close_child_fd_in_parent();

    // 10. Write UID/GID mappings
    if let Err(e) = user_ns.write_mappings(child_pid.as_raw()) {
        drop(ready_write);
        kill_and_reap(child_pid);
        return Err(e);
    }

    // 11. Configure cgroup
    let limit_plan = LimitPlan::from(config, policy);
    let sandbox_id = format!("libsandbox-{}", child_pid.as_raw());
    let (cgroup, limit_diagnostics) = if needs_cgroup(config) {
        match configure_cgroup(config, &limit_plan, &sandbox_id, child_pid.as_raw() as u32) {
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

    // 12. Signal child to continue
    ready_write.write_byte_and_close(0).map_err(|e| {
        abort_child_startup(
            child_pid,
            &mut ready_write,
            format!("signal child to continue: {e}"),
        )
    })?;

    // 13. Read error pipe — non-blocking check for startup failures.
    //
    // The child writes to error_write on setup failure and closes it on
    // success (just before exec). We set error_read to O_NONBLOCK so
    // this read does NOT wait for the child to finish setup. If the
    // child hasn't closed error_write yet (EAGAIN), we assume success
    // and let the caller detect failures via exit code. This avoids
    // adding latency that would throw off wall_time_limit under
    // concurrent execution.
    set_nonblock(error_read.raw())
        .map_err(|e| SandboxError::Internal(format!("set error pipe non-blocking: {e}")))?;
    // NOTE: 4096-byte buffer. Setup errors exceeding this are silently
    // truncated. Mount error messages are typically under 200 bytes.
    let mut error_buf = [0u8; 4096];
    match read_raw(error_read.raw(), &mut error_buf) {
        Ok(0) => {
            // EOF — child already closed error_write (fast setup)
            let _ = error_read.close();
        }
        Ok(n) => {
            // Child reported a setup error
            let _ = error_read.close();
            let msg = String::from_utf8_lossy(&error_buf[..n]);
            kill_and_reap(child_pid);
            return Err(SandboxError::SetupFailed(msg.to_string()));
        }
        Err(_) => {
            // EAGAIN or other — child hasn't finished setup yet. Assume
            // success; failures will surface as a non-zero exit code.
            let _ = error_read.close();
        }
    }

    // 14. Construct and return Child with its limit diagnostics
    let pidfd = try_pidfd_open(child_pid.as_raw());

    // Open namespace fds for dynamic mount operations.
    // These remain valid after child exit (kernel reference counting).
    let user_ns_fd = open_namespace_fd(child_pid.as_raw(), "user");
    let mnt_ns_fd = open_namespace_fd(child_pid.as_raw(), "mnt");

    let child = Child::new(
        child_pid.as_raw(),
        pidfd,
        super::child::StdioFds {
            stdin: stdin_slot.take_parent_fd(),
            stdout: stdout_slot.take_parent_fd(),
            stderr: stderr_slot.take_parent_fd(),
        },
        cgroup,
        proxy,
        super::child::NamespaceFds {
            user: user_ns_fd,
            mnt: mnt_ns_fd,
        },
    );
    Ok((child, limit_diagnostics))
}
