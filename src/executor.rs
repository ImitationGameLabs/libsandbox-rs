//! Linux sandbox executor.
//!
//! [`LinuxExecutor`] is the concrete executor that runs commands inside
//! isolated Linux namespaces with cgroup resource limits and seccomp
//! filtering. There is no trait indirection — this is the only executor
//! for this Linux-only crate.

#[cfg(not(target_os = "linux"))]
compile_error!("libsandbox requires Linux");

use crate::builder::SandboxConfig;
use crate::config::ExecutionPolicy;
use crate::error::{Result, SandboxError};
use crate::cgroup::collect_linux_metrics;
use crate::process::{Child, spawn_isolated, wait_with_timeout, write_all_raw};
use crate::result::{ExecutionDiagnostics, ExecutionReport, ExecutionResult};
use crate::stdio::Stdio;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// Check if Linux sandboxing is supported.
pub fn is_supported() -> bool {
    check_user_namespace_support()
}

fn check_user_namespace_support() -> bool {
    // Check if unprivileged user namespaces are enabled
    std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map(|s| s.trim() == "1")
        .unwrap_or(true) // If file doesn't exist, assume enabled (newer kernels)
}

/// Linux sandbox executor.
///
/// Uses Linux kernel primitives for sandboxing:
///
/// - **Namespaces**: PID, mount, network, user, UTS, IPC isolation
/// - **Cgroups v2**: Resource limits (memory, CPU, PIDs)
/// - **Seccomp-BPF**: Syscall filtering
/// - **HTTP Proxy**: Domain whitelisting for proxied network mode
pub struct LinuxExecutor {
    _private: (),
}

impl LinuxExecutor {
    /// Create a new `LinuxExecutor`.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Execute a command in the sandbox (one-shot).
    pub fn execute(
        &self,
        config: &SandboxConfig,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecutionResult> {
        self.execute_detailed(config, &ExecutionPolicy::default(), cmd, args, stdin)
            .map(|report| report.result)
    }

    /// Execute a command and return detailed diagnostics.
    pub fn execute_detailed(
        &self,
        config: &SandboxConfig,
        policy: &ExecutionPolicy,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecutionReport> {
        let start = Instant::now();

        // Determine stdin mode
        let stdin_stdio = if stdin.is_some() {
            Stdio::Pipe
        } else {
            Stdio::Null
        };

        // Spawn the sandboxed child
        let (mut child, limit_diagnostics) = spawn_isolated(
            config,
            policy,
            cmd,
            args,
            stdin_stdio,
            Stdio::Pipe, // stdout
            Stdio::Pipe, // stderr
        )?;

        // Write stdin data if provided
        if let Some(data) = stdin {
            if let Some(stdin_fd) = child.stdin_fd() {
                let raw = stdin_fd.as_raw_fd();
                // Best-effort: the child may have already closed stdin
                // (e.g., exited early), so we tolerate write errors here.
                let _ = write_all_raw(raw, data);
            }
            child.close_stdin();
        }

        // Wait for child with timeout
        // Take ownership of pipe fds from Child — wait_with_timeout will
        // read from and close them. OwnedFd guarantees cleanup on error.
        let child_pid = nix::unistd::Pid::from_raw(child.raw_pid());
        let stdout_fd = child.take_stdout_fd();
        let stderr_fd = child.take_stderr_fd();
        let timeout = config
            .resources
            .wall_time_limit
            .unwrap_or(Duration::from_secs(3600));
        let (stdout, stderr, exit_code, killed_by_timeout, signal) =
            wait_with_timeout(child_pid, stdout_fd, stderr_fd, timeout)?;

        // Mark child as waited so Drop doesn't try to kill/reap
        child.set_waited();

        // Collect resource stats BEFORE cgroup cleanup
        let (peak_memory, cpu_time, killed_by_oom, metric_diagnostics) =
            collect_linux_metrics(child.cgroup());

        // Cgroup + proxy cleaned up when child is dropped

        Ok(ExecutionReport {
            result: ExecutionResult {
                stdout,
                stderr,
                exit_code,
                duration: start.elapsed(),
                killed_by_timeout,
                killed_by_oom,
                signal,
                peak_memory,
                cpu_time,
            },
            diagnostics: ExecutionDiagnostics {
                limits: limit_diagnostics,
                metrics: metric_diagnostics,
            },
        })
    }

    /// Check if this platform supports all requested features.
    pub fn check_support(&self, _config: &SandboxConfig) -> Result<()> {
        if !check_user_namespace_support() {
            return Err(SandboxError::UserNamespaceDisabled);
        }
        Ok(())
    }

    /// Spawn a sandboxed process and return a handle for interactive use.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        &self,
        config: &SandboxConfig,
        policy: &ExecutionPolicy,
        cmd: &str,
        args: &[&str],
        stdin: Stdio,
        stdout: Stdio,
        stderr: Stdio,
    ) -> Result<Child> {
        let (child, _) = spawn_isolated(config, policy, cmd, args, stdin, stdout, stderr)?;
        Ok(child)
    }
}

impl Default for LinuxExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_executor_creation() {
        let executor = LinuxExecutor::new();
        let _ = executor;
    }
}