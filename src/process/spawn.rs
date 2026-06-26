//! Thin spawn façade over the protocol + toolbox.
//!
//! [`spawn`] is the primitive handle API (returns a [`Child`]). [`run`] is the
//! one-shot convenience (spawns, waits with timeout, collects metrics). Both
//! delegate the real work to [`crate::process::protocol`].
//!
//! The heavier one-shot orchestration (stdin write-back, timeout wait, cgroup
//! metric collection) lives in [`wait_and_collect`] so that a future async
//! entry point can reuse it without duplicating the logic.

use super::child::Child;
use super::child_setup::ChildSetup;
use super::fd::write_all_raw;
use super::protocol::{prepare_sandbox, run_prepared};
use super::wait::wait_with_timeout;
use crate::builder::SandboxConfig;
use crate::cgroup::collect_linux_metrics;
use crate::config::ExecutionPolicy;
use crate::error::Result;
use crate::result::{ExecutionDiagnostics, ExecutionReport, ExecutionResult, LimitDiagnostics};
use crate::stdio::Stdio;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// Spawn a sandboxed child process with arbitrary stdio and an optional
/// [`ChildSetup`] hook. Does **not** wait — that is the caller's responsibility
/// (see [`Child::wait`](super::child::Child::wait)).
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn(
    config: &SandboxConfig,
    policy: &ExecutionPolicy,
    cmd: &str,
    args: &[&str],
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    child_setup: Option<ChildSetup>,
) -> Result<Child> {
    let prep = prepare_sandbox(
        config,
        policy,
        cmd,
        args,
        stdin,
        stdout,
        stderr,
        child_setup,
    )?;
    let (child, _limit_diagnostics) = run_prepared(prep)?;
    Ok(child)
}

/// Execute a command one-shot: spawn, optionally feed stdin, wait with the
/// configured wall-time limit, and collect cgroup metrics into an
/// [`ExecutionReport`].
pub(crate) fn run(
    config: &SandboxConfig,
    policy: &ExecutionPolicy,
    cmd: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<ExecutionReport> {
    let start = Instant::now();
    let stdin_stdio = if stdin.is_some() {
        Stdio::Pipe
    } else {
        Stdio::Null
    };

    let prep = prepare_sandbox(
        config,
        policy,
        cmd,
        args,
        stdin_stdio,
        Stdio::Pipe,
        Stdio::Pipe,
        None,
    )?;
    let (mut child, limit_diagnostics) = run_prepared(prep)?;

    // Best-effort stdin write: the child may have already closed stdin.
    if let Some(data) = stdin {
        if let Some(stdin_fd) = child.stdin_fd() {
            let _ = write_all_raw(stdin_fd.as_raw_fd(), data);
        }
        child.close_stdin();
    }

    wait_and_collect(child, limit_diagnostics, config, start)
}

/// Wait for a child with the configured wall-time limit and assemble the
/// [`ExecutionReport`] from the exit status and cgroup metrics. Shared between
/// [`run`] (sync) and any future async entry point.
fn wait_and_collect(
    mut child: Child,
    limit_diagnostics: LimitDiagnostics,
    config: &SandboxConfig,
    start: Instant,
) -> Result<ExecutionReport> {
    let child_pid = nix::unistd::Pid::from_raw(child.raw_pid());
    let stdout_fd = child.take_stdout_fd();
    let stderr_fd = child.take_stderr_fd();
    let timeout = config
        .resources
        .wall_time_limit
        .unwrap_or(Duration::from_secs(3600));
    let (stdout, stderr, exit_code, killed_by_timeout, signal) =
        wait_with_timeout(child_pid, stdout_fd, stderr_fd, timeout)?;

    // Mark waited so Child::drop does not try to kill/reap.
    child.set_waited();

    // Collect metrics BEFORE the cgroup is torn down when `child` drops.
    let (peak_memory, cpu_time, killed_by_oom, metric_diagnostics) =
        collect_linux_metrics(child.cgroup());

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
