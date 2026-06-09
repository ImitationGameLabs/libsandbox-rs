//! Sandbox implementation.
//!
//! The main Sandbox struct that provides the high-level API for running
//! sandboxed processes across different platforms.

use crate::builder::{SandboxBuilder, SandboxConfig};
use crate::config::{
    EnvironmentConfig, ExecutionPolicy, FilesystemConfig, NetworkConfig, Permission,
    ResourceConfig, ResourceEnforcement, SeccompProfile, SecurityConfig,
};
use crate::error::Result;
use crate::executor::LinuxExecutor;
use crate::process::Child;
use crate::result::{ExecutionReport, ExecutionResult};
use crate::stdio::Stdio;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static SANDBOX_COUNTER: AtomicU64 = AtomicU64::new(0);

fn generate_sandbox_id() -> String {
    let count = SANDBOX_COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}-{}", timestamp, count)
}

/// Main sandbox struct.
///
/// Provides a Linux API for running sandboxed processes.
/// The actual sandboxing mechanism uses:
///
/// - **Linux**: namespaces, cgroups v2, seccomp
pub struct Sandbox {
    config: SandboxConfig,
    execution_policy: ExecutionPolicy,
    id: String,
    executor: LinuxExecutor,
}

impl Sandbox {
    /// Create a new [`SandboxBuilder`].
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use libsandbox::Sandbox;
    /// use libsandbox::config::{FilesystemConfig, ResourceConfig, NetworkConfig};
    /// use libsandbox::{MB, Permission};
    /// use std::time::Duration;
    ///
    /// let sandbox = Sandbox::builder()
    ///     .filesystem(
    ///         FilesystemConfig::builder()
    ///             .working_dir("/tmp")
    ///             .build()
    ///             .unwrap()
    ///     )
    ///     .resources(
    ///         ResourceConfig::builder()
    ///             .memory_limit(256 * MB)
    ///             .build()
    ///             .unwrap()
    ///     )
    ///     .network(NetworkConfig::none())
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder() -> SandboxBuilder {
        SandboxBuilder::new()
    }

    /// Create a sandbox from a pre-built config and execution policy.
    pub(crate) fn from_config(
        config: SandboxConfig,
        execution_policy: ExecutionPolicy,
    ) -> Result<Self> {
        let executor = LinuxExecutor::new();
        executor.check_support(&config)?;
        Ok(Self {
            config,
            execution_policy,
            id: generate_sandbox_id(),
            executor,
        })
    }

    /// Run a command in the sandbox.
    ///
    /// # Arguments
    ///
    /// * `cmd` - The command to execute
    /// * `args` - Command arguments
    ///
    /// # Returns
    ///
    /// An `ExecutionResult` containing stdout, stderr, exit code, and resource usage.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use libsandbox::Sandbox;
    /// use libsandbox::config::FilesystemConfig;
    ///
    /// let sandbox = Sandbox::builder()
    ///     .filesystem(
    ///         FilesystemConfig::builder().working_dir("/tmp").build().unwrap()
    ///     )
    ///     .build()
    ///     .unwrap();
    /// let result = sandbox.run("echo", &["hello", "world"]).unwrap();
    /// assert_eq!(result.stdout.trim(), "hello world");
    /// ```
    pub fn run(&self, cmd: &str, args: &[&str]) -> Result<ExecutionResult> {
        self.run_with_input(cmd, args, None)
    }

    /// Run a command with optional stdin input.
    ///
    /// # Arguments
    ///
    /// * `cmd` - The command to execute
    /// * `args` - Command arguments
    /// * `stdin` - Optional data to pass to stdin
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use libsandbox::Sandbox;
    /// use libsandbox::config::FilesystemConfig;
    ///
    /// let sandbox = Sandbox::builder()
    ///     .filesystem(
    ///         FilesystemConfig::builder().working_dir("/tmp").build().unwrap()
    ///     )
    ///     .build()
    ///     .unwrap();
    /// let result = sandbox.run_with_input("cat", &[], Some(b"hello")).unwrap();
    /// assert_eq!(result.stdout.trim(), "hello");
    /// ```
    pub fn run_with_input(
        &self,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecutionResult> {
        let mut report = self.run_with_input_detailed(cmd, args, stdin)?;
        if self.execution_policy.resource_enforcement == ResourceEnforcement::BestEffort {
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
        self.executor
            .execute_detailed(&self.config, &self.execution_policy, cmd, args, stdin)
    }

    /// Spawn a sandboxed process and return a handle for interactive use.
    ///
    /// Unlike `run()`, this returns a [`Child`] that the caller can read
    /// from, write to, wait on, or kill independently. The sandbox isolation
    /// (namespaces, cgroups, seccomp, network) is applied exactly as
    /// configured in the builder.
    ///
    /// # Defaults
    ///
    /// - stdin  → `/dev/null`
    /// - stdout → pipe (read via `child.stdout_fd()`)
    /// - stderr → pipe (read via `child.stderr_fd()`)
    ///
    /// To customize stdio configuration (e.g., piped stdin or null output),
    /// use [`Sandbox::build_spawn`] instead.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use libsandbox::{Sandbox, Stdio};
    ///
    /// let sandbox = Sandbox::builder().build().unwrap();
    /// let child = sandbox.spawn("echo", &["hello"]).unwrap();
    /// // read from child.stdout_fd(), then call child.wait()
    /// ```
    pub fn spawn(&self, cmd: &str, args: &[&str]) -> Result<Child> {
        self.executor.spawn(
            &self.config,
            &self.execution_policy,
            cmd,
            args,
            Stdio::default_stdin(),
            Stdio::default_stdout(),
            Stdio::default_stderr(),
        )
    }

    /// Begin building a spawned process with custom stdio configuration.
    ///
    /// Returns a [`SpawnBuilder`] that lets you configure stdin/stdout/stderr
    /// before calling [`SpawnBuilder::start`] to launch the sandboxed child.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use libsandbox::{Sandbox, Stdio};
    ///
    /// let sandbox = Sandbox::builder().build().unwrap();
    /// let child = sandbox.build_spawn("cat", &[])
    ///     .stdin(Stdio::Pipe)
    ///     .start()
    ///     .unwrap();
    /// ```
    pub fn build_spawn(&self, cmd: &str, args: &[&str]) -> SpawnBuilder<'_> {
        // NOTE: args are cloned into String here, then converted back to &str
        // in start(). This is an intentional tradeoff: SpawnBuilder must own its
        // data because 'a is tied to &'a Sandbox, not to the caller's arg slices.
        // The allocation cost is negligible for the typical O(10) argument count.
        SpawnBuilder {
            sandbox: self,
            command: cmd.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            stdin: Stdio::default_stdin(),
            stdout: Stdio::default_stdout(),
            stderr: Stdio::default_stderr(),
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

    // ========== Preset configurations ==========

    /// Data analysis preset.
    ///
    /// - Read-only input directory
    /// - Read-write output directory
    /// - Appropriate memory and CPU limits
    /// - No network (default)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use libsandbox::Sandbox;
    ///
    /// let sandbox = Sandbox::data_analysis("/data/input", "/data/output")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn data_analysis(
        input_dir: impl Into<PathBuf>,
        output_dir: impl Into<PathBuf>,
    ) -> SandboxBuilder {
        Sandbox::builder()
            .filesystem(
                FilesystemConfig::builder()
                    .mount(input_dir, "/input", Permission::ReadOnly)
                    .mount(output_dir, "/output", Permission::ReadWrite)
                    .tmpfs("/tmp", 256 * 1024 * 1024)
                    .working_dir("/workspace")
                    .build()
                    .expect("preset config is valid"),
            )
            .resources(
                ResourceConfig::builder()
                    .memory_limit(2 * 1024 * 1024 * 1024)
                    .cpu_limit(2.0)
                    .wall_time_limit(Duration::from_secs(300))
                    .max_pids(100)
                    .build()
                    .expect("preset config is valid"),
            )
            .network(NetworkConfig::none())
            .security(
                SecurityConfig::builder()
                    .seccomp_profile(SeccompProfile::Standard)
                    .build()
                    .expect("preset config is valid"),
            )
    }

    /// Code judge preset (for OJ systems).
    ///
    /// - Strict limits
    /// - Minimal permissions
    /// - No network
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use libsandbox::Sandbox;
    /// use libsandbox::config::ResourceConfig;
    /// use std::time::Duration;
    ///
    /// let sandbox = Sandbox::code_judge("/submissions/123")
    ///     .resources(
    ///         ResourceConfig::builder()
    ///             .cpu_time_limit(Duration::from_secs(2))
    ///             .memory_limit(256 * 1024 * 1024)
    ///             .cpu_limit(1.0)
    ///             .wall_time_limit(Duration::from_secs(10))
    ///             .max_pids(10)
    ///             .build()
    ///             .unwrap()
    ///     )
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn code_judge(code_dir: impl Into<PathBuf>) -> SandboxBuilder {
        Sandbox::builder()
            .filesystem(
                FilesystemConfig::builder()
                    .mount(code_dir, "/workspace", Permission::ReadOnly)
                    .tmpfs("/tmp", 64 * 1024 * 1024)
                    .working_dir("/workspace")
                    .build()
                    .expect("preset config is valid"),
            )
            .resources(
                ResourceConfig::builder()
                    .memory_limit(256 * 1024 * 1024)
                    .cpu_limit(1.0)
                    .wall_time_limit(Duration::from_secs(10))
                    .cpu_time_limit(Duration::from_secs(5))
                    .max_pids(10)
                    .build()
                    .expect("preset config is valid"),
            )
            .network(NetworkConfig::none())
            .security(
                SecurityConfig::builder()
                    .seccomp_profile(SeccompProfile::Strict)
                    .build()
                    .expect("preset config is valid"),
            )
    }

    /// AI Agent executor preset.
    ///
    /// - Read-write workspace
    /// - Moderate limits
    /// - Network controlled by caller
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use libsandbox::Sandbox;
    /// use libsandbox::config::NetworkConfig;
    ///
    /// let sandbox = Sandbox::agent_executor("/agent/workspace")
    ///     .network(
    ///         NetworkConfig::proxied(&["api.openai.com"])
    ///     )
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn agent_executor(workspace: impl Into<PathBuf>) -> SandboxBuilder {
        Sandbox::builder()
            .filesystem(
                FilesystemConfig::builder()
                    .mount(workspace, "/workspace", Permission::ReadWrite)
                    .tmpfs("/tmp", 512 * 1024 * 1024)
                    .working_dir("/workspace")
                    .build()
                    .expect("preset config is valid"),
            )
            .resources(
                ResourceConfig::builder()
                    .memory_limit(4 * 1024 * 1024 * 1024)
                    .cpu_limit(4.0)
                    .wall_time_limit(Duration::from_secs(600))
                    .max_pids(256)
                    .build()
                    .expect("preset config is valid"),
            )
            .security(
                SecurityConfig::builder()
                    .seccomp_profile(SeccompProfile::Standard)
                    .build()
                    .expect("preset config is valid"),
            )
            .environment(
                EnvironmentConfig::builder()
                    .env("HOME", "/workspace")
                    .env("USER", "sandbox")
                    .build()
                    .expect("preset config is valid"),
            )
    }

    /// Interactive shell preset.
    ///
    /// - For debugging
    /// - Relatively permissive
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use libsandbox::Sandbox;
    ///
    /// let sandbox = Sandbox::interactive("/home/user/project")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn interactive(workspace: impl Into<PathBuf>) -> SandboxBuilder {
        Sandbox::builder()
            .filesystem(
                FilesystemConfig::builder()
                    .mount(workspace, "/workspace", Permission::ReadWrite)
                    .tmpfs("/tmp", 1024 * 1024 * 1024)
                    .working_dir("/workspace")
                    .build()
                    .expect("preset config is valid"),
            )
            .resources(
                ResourceConfig::builder()
                    .memory_limit(8 * 1024 * 1024 * 1024)
                    .cpu_limit(4.0)
                    .max_pids(512)
                    .build()
                    .expect("preset config is valid"),
            )
            .security(
                SecurityConfig::builder()
                    .seccomp_profile(SeccompProfile::Permissive)
                    .build()
                    .expect("preset config is valid"),
            )
            .environment(
                EnvironmentConfig::builder()
                    .hostname("sandbox")
                    .env("TERM", "xterm-256color")
                    .env("HOME", "/workspace")
                    .env("USER", "sandbox")
                    .env("SHELL", "/bin/bash")
                    .build()
                    .expect("preset config is valid"),
            )
    }
}

/// Builder for configuring and launching a sandboxed child process.
///
/// Created by [`Sandbox::build_spawn`]. Allows customizing the stdio
/// configuration before calling [`SpawnBuilder::start`].
pub struct SpawnBuilder<'a> {
    sandbox: &'a Sandbox,
    command: String,
    args: Vec<String>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
}

impl<'a> std::fmt::Debug for SpawnBuilder<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnBuilder")
            .field("command", &self.command)
            .field("args", &self.args)
            .field("stdin", &self.stdin)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .finish_non_exhaustive()
    }
}

impl<'a> SpawnBuilder<'a> {
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

    /// Launch the sandboxed child process.
    pub fn start(self) -> Result<Child> {
        let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
        self.sandbox.executor.spawn(
            &self.sandbox.config,
            &self.sandbox.execution_policy,
            &self.command,
            &args,
            self.stdin,
            self.stdout,
            self.stderr,
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
    fn test_sandbox_builder() {
        let builder = Sandbox::builder()
            .filesystem(
                FilesystemConfig::builder()
                    .working_dir("/tmp")
                    .build()
                    .unwrap(),
            )
            .resources(
                ResourceConfig::builder()
                    .memory_limit(512 * 1024 * 1024)
                    .build()
                    .unwrap(),
            )
            .environment(
                EnvironmentConfig::builder()
                    .hostname("test")
                    .build()
                    .unwrap(),
            );

        assert_eq!(builder.resources.memory_limit, Some(512 * 1024 * 1024));
        assert_eq!(builder.environment.hostname, "test");
        assert!(builder.resources.cgroup_limit_requests.memory);
    }

    #[test]
    fn test_presets() {
        // Verify presets compile and return builders.
        let _ = Sandbox::data_analysis("/in", "/out");
        let _ = Sandbox::code_judge("/code");
        let _ = Sandbox::agent_executor("/workspace");
        let _ = Sandbox::interactive("/home");
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
}
