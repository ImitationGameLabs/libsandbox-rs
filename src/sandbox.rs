//! Sandbox facade.
//!
//! [`Sandbox`] is the ergonomic entry point: a config + policy holder that
//! delegates to the protocol/toolbox pipeline in [`crate::process`].
//! [`SpawnBuilder`] owns its per-spawn overrides (stdio + [`ChildSetup`] hook)
//! by value, fixing the historical `&Sandbox`-borrowed limitation — a builder
//! can be held and started independently of the [`Sandbox`] that produced it.

use crate::builder::{SandboxBuilder, SandboxConfig};
use crate::config::ExecutionPolicy;
use crate::error::Result;
use crate::executor;
use crate::process::{self, Child, ChildSetup};
use crate::result::{ExecutionReport, ExecutionResult};
use crate::stdio::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};

static SANDBOX_COUNTER: AtomicU64 = AtomicU64::new(0);

fn generate_sandbox_id() -> String {
    let count = SANDBOX_COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}-{}", timestamp, count)
}

/// A sandbox: a frozen configuration + execution policy.
///
/// Built via [`Sandbox::builder`]. Use [`run`](Self::run) for one-shot
/// execution or [`spawn`](Self::spawn) / [`build_spawn`](Self::build_spawn) for
/// an interactive [`Child`] handle. There are no preset constructors — compose
/// the configuration you need via the domain builders.
pub struct Sandbox {
    config: SandboxConfig,
    execution_policy: ExecutionPolicy,
    id: String,
}

impl Sandbox {
    /// Create a new [`SandboxBuilder`].
    pub fn builder() -> SandboxBuilder {
        SandboxBuilder::new()
    }

    /// Create a sandbox from a pre-built config and execution policy.
    pub(crate) fn from_config(
        config: SandboxConfig,
        execution_policy: ExecutionPolicy,
    ) -> Result<Self> {
        executor::check_support()?;
        Ok(Self {
            config,
            execution_policy,
            id: generate_sandbox_id(),
        })
    }

    /// Run a command in the sandbox (one-shot).
    pub fn run(&self, cmd: &str, args: &[&str]) -> Result<ExecutionResult> {
        self.run_with_input(cmd, args, None)
    }

    /// Run a command with optional stdin input (one-shot).
    pub fn run_with_input(
        &self,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecutionResult> {
        let mut report = self.run_with_input_detailed(cmd, args, stdin)?;
        if self.execution_policy.resource_enforcement
            == crate::config::ResourceEnforcement::BestEffort
        {
            if let Some(summary) = report.diagnostics.degradation_summary() {
                append_best_effort_warning(&mut report.result.stderr, &summary);
            }
        }
        Ok(report.result)
    }

    /// Run a command and return structured diagnostics alongside the result.
    pub fn run_detailed(&self, cmd: &str, args: &[&str]) -> Result<ExecutionReport> {
        self.run_with_input_detailed(cmd, args, None)
    }

    /// Run a command with optional stdin input and return structured diagnostics.
    pub fn run_with_input_detailed(
        &self,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecutionReport> {
        process::run(&self.config, &self.execution_policy, cmd, args, stdin)
    }

    /// Spawn a sandboxed process and return a handle for interactive use.
    ///
    /// # Defaults
    ///
    /// - stdin  → `/dev/null`
    /// - stdout → pipe (read via `child.stdout_fd()`)
    /// - stderr → pipe (read via `child.stderr_fd()`)
    ///
    /// For custom stdio or a [`ChildSetup`] hook, use [`build_spawn`](Self::build_spawn).
    pub fn spawn(&self, cmd: &str, args: &[&str]) -> Result<Child> {
        process::spawn(
            &self.config,
            &self.execution_policy,
            process::SpawnRequest {
                cmd,
                args,
                stdin: Stdio::default_stdin(),
                stdout: Stdio::default_stdout(),
                stderr: Stdio::default_stderr(),
                child_setup: None,
            },
        )
    }

    /// Begin building a spawned process with custom stdio and/or a
    /// [`ChildSetup`] hook.
    ///
    /// The returned [`SpawnBuilder`] owns its per-spawn data (a clone of the
    /// sandbox config), so it can be held and started independently of this
    /// [`Sandbox`].
    pub fn build_spawn(&self, cmd: &str, args: &[&str]) -> SpawnBuilder {
        SpawnBuilder {
            config: self.config.clone(),
            policy: self.execution_policy.clone(),
            command: cmd.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            stdin: Stdio::default_stdin(),
            stdout: Stdio::default_stdout(),
            stderr: Stdio::default_stderr(),
            child_setup: None,
        }
    }

    /// Get the sandbox ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the platform name.
    pub fn platform(&self) -> &'static str {
        "linux"
    }
}

/// Builder for configuring and launching a sandboxed child process with
/// per-spawn overrides.
///
/// Created by [`Sandbox::build_spawn`]. Owns its configuration (cloned from the
/// parent [`Sandbox`]), so it is not lifetime-tied to the sandbox.
pub struct SpawnBuilder {
    config: SandboxConfig,
    policy: ExecutionPolicy,
    command: String,
    args: Vec<String>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    child_setup: Option<ChildSetup>,
}

impl std::fmt::Debug for SpawnBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnBuilder")
            .field("command", &self.command)
            .field("args", &self.args)
            .field("stdin", &self.stdin)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            // Omit `child_setup` (an opaque closure) and the cloned config.
            .finish_non_exhaustive()
    }
}

impl SpawnBuilder {
    /// Configure the child's stdin.
    pub fn stdin(mut self, stdio: Stdio) -> Self {
        self.stdin = stdio;
        self
    }

    /// Configure the child's stdout.
    pub fn stdout(mut self, stdio: Stdio) -> Self {
        self.stdout = stdio;
        self
    }

    /// Configure the child's stderr.
    pub fn stderr(mut self, stdio: Stdio) -> Self {
        self.stderr = stdio;
        self
    }

    /// Install a [`ChildSetup`] hook run inside the child after seccomp install
    /// and before `exec` (e.g. landlock, privilege drop, custom mounts).
    pub fn child_setup<F>(mut self, f: F) -> Self
    where
        F: Fn(&crate::process::ChildCtx) -> Result<()> + Send + Sync + 'static,
    {
        self.child_setup = Some(Box::new(f));
        self
    }

    /// Launch the sandboxed child process.
    pub fn start(self) -> Result<Child> {
        let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
        process::spawn(
            &self.config,
            &self.policy,
            process::SpawnRequest {
                cmd: &self.command,
                args: &args,
                stdin: self.stdin,
                stdout: self.stdout,
                stderr: self.stderr,
                child_setup: self.child_setup,
            },
        )
    }
}

fn append_best_effort_warning(stderr: &mut String, summary: &str) {
    if !stderr.is_empty() && !stderr.ends_with('\n') {
        stderr.push('\n');
    }
    stderr.push_str("[libsandbox] best-effort degradation: ");
    stderr.push_str(summary);
    stderr.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResourceEnforcement;
    use crate::result::{
        ExecutionDiagnostics, ExecutionReport, LimitDiagnostics, LimitStatus, MetricDiagnostics,
        MetricStatus,
    };

    #[test]
    fn test_sandbox_id_generation() {
        let id1 = generate_sandbox_id();
        let id2 = generate_sandbox_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_append_best_effort_warning() {
        let mut report = ExecutionReport {
            result: ExecutionResult::default(),
            diagnostics: ExecutionDiagnostics {
                limits: LimitDiagnostics {
                    memory: LimitStatus::NotEnforced {
                        reason: "memory controller unavailable".into(),
                    },
                    cpu: LimitStatus::NotRequested,
                    pids: LimitStatus::NotRequested,
                },
                metrics: MetricDiagnostics {
                    peak_memory: MetricStatus::Unavailable {
                        reason: "memory stats missing".into(),
                    },
                    cpu_time: MetricStatus::Collected,
                },
            },
        };

        if let Some(summary) = report.diagnostics.degradation_summary() {
            append_best_effort_warning(&mut report.result.stderr, &summary);
        }

        assert!(report.result.stderr.contains("best-effort degradation"));
        assert!(report.result.stderr.contains("memory limit not enforced"));
        assert!(report.result.stderr.contains("peak memory unavailable"));
    }

    #[test]
    fn test_spawn_builder_is_owned() {
        // SpawnBuilder owns its data — it must not borrow the Sandbox.
        let sandbox = Sandbox::builder().build().unwrap();
        let builder = sandbox.build_spawn("echo", &["hi"]);
        // Drop the sandbox; the builder must still be usable.
        drop(sandbox);
        assert_eq!(builder.command, "echo");
    }

    #[test]
    fn test_execution_policy_best_effort_helper() {
        // The helper must only flag BestEffort policy, not Strict.
        let strict = ExecutionPolicy::default();
        assert_eq!(strict.resource_enforcement, ResourceEnforcement::Strict);
    }
}
