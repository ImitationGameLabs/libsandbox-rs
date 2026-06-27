//! Resource limit configuration and builder.

use crate::error::Result;
use std::time::Duration;

/// How strictly Linux cgroup-backed resource limits should be enforced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ResourceEnforcement {
    /// Fail closed when an explicitly requested cgroup-backed limit cannot be enforced.
    #[default]
    Strict,
    /// Continue execution and surface any skipped limits through diagnostics.
    BestEffort,
}

/// Tracks which cgroup-backed limits were explicitly requested by the caller.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CgroupLimitRequests {
    /// Whether a memory limit was explicitly requested.
    pub memory: bool,
    /// Whether a CPU limit was explicitly requested.
    pub cpu: bool,
    /// Whether a pids limit was explicitly requested.
    pub pids: bool,
}

/// Execution policy derived from resource configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionPolicy {
    /// How strictly cgroup-backed limits are enforced when unavailable.
    pub resource_enforcement: ResourceEnforcement,
    /// Which cgroup-backed limits were explicitly requested by the caller.
    pub cgroup_limit_requests: CgroupLimitRequests,
}

/// Resource limit configuration produced by [`ResourceBuilder`].
///
/// # Defaults
///
/// | Field | Default | Notes |
/// |-------|---------|-------|
/// | `max_pids` | `Some(64)` | Implicit limit, not treated as explicitly requested |
/// | All others | `None` | No limit enforced unless explicitly set |
/// | `resource_enforcement` | `Strict` | Fail closed on unenforceable limits |
#[derive(Clone, Debug)]
pub struct ResourceConfig {
    // Cgroup-backed limits
    /// Memory limit in bytes (cgroup `memory.max`).
    pub memory_limit: Option<u64>,
    /// CPU limit in cores, 0.0..N (cgroup `cpu.max`).
    pub cpu_limit: Option<f64>,
    /// Maximum number of processes/threads (cgroup `pids.max`).
    pub max_pids: Option<u32>,

    // RLIMIT-backed limits
    /// Wall-clock time limit (the process is killed after this duration).
    pub wall_time_limit: Option<Duration>,
    /// CPU time limit (`RLIMIT_CPU`).
    pub cpu_time_limit: Option<Duration>,
    /// Maximum file size in bytes (`RLIMIT_FSIZE`).
    pub max_file_size: Option<u64>,
    /// Maximum number of open file descriptors (`RLIMIT_NOFILE`).
    pub max_open_files: Option<u32>,

    // Enforcement metadata (set by the builder, not directly by users)
    pub(crate) resource_enforcement: ResourceEnforcement,
    pub(crate) cgroup_limit_requests: CgroupLimitRequests,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            memory_limit: None,
            cpu_limit: None,
            max_pids: Some(64),
            wall_time_limit: None,
            cpu_time_limit: None,
            max_file_size: None,
            max_open_files: None,
            resource_enforcement: ResourceEnforcement::Strict,
            cgroup_limit_requests: CgroupLimitRequests::default(),
        }
    }
}

impl ResourceConfig {
    /// Derive an [`ExecutionPolicy`] from this configuration.
    pub(crate) fn to_execution_policy(&self) -> ExecutionPolicy {
        ExecutionPolicy {
            resource_enforcement: self.resource_enforcement.clone(),
            cgroup_limit_requests: self.cgroup_limit_requests.clone(),
        }
    }

    /// Whether any cgroup-backed limit is set.
    pub fn needs_cgroup(&self) -> bool {
        self.memory_limit.is_some() || self.cpu_limit.is_some() || self.max_pids.is_some()
    }

    /// Create a new [`ResourceBuilder`].
    pub fn builder() -> ResourceBuilder {
        ResourceBuilder::new()
    }
}

/// Fluent builder for [`ResourceConfig`].
#[derive(Clone)]
pub struct ResourceBuilder {
    config: ResourceConfig,
}

impl Default for ResourceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceBuilder {
    /// Create a new `ResourceBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            config: ResourceConfig::default(),
        }
    }

    /// Set memory limit in bytes.
    pub fn memory_limit(mut self, bytes: u64) -> Self {
        self.config.memory_limit = Some(bytes);
        self.config.cgroup_limit_requests.memory = true;
        self
    }

    /// Set CPU limit (0.0 - N.0, where N is number of CPU cores).
    pub fn cpu_limit(mut self, cpus: f64) -> Self {
        self.config.cpu_limit = Some(cpus);
        self.config.cgroup_limit_requests.cpu = true;
        self
    }

    /// Set wall clock time limit (process will be killed after this duration).
    pub fn wall_time_limit(mut self, duration: Duration) -> Self {
        self.config.wall_time_limit = Some(duration);
        self
    }

    /// Set CPU time limit.
    pub fn cpu_time_limit(mut self, duration: Duration) -> Self {
        self.config.cpu_time_limit = Some(duration);
        self
    }

    /// Set maximum number of processes/threads.
    pub fn max_pids(mut self, n: u32) -> Self {
        self.config.max_pids = Some(n);
        self.config.cgroup_limit_requests.pids = true;
        self
    }

    /// Set maximum file size in bytes.
    pub fn max_file_size(mut self, bytes: u64) -> Self {
        self.config.max_file_size = Some(bytes);
        self
    }

    /// Set maximum number of open files.
    pub fn max_open_files(mut self, n: u32) -> Self {
        self.config.max_open_files = Some(n);
        self
    }

    /// Control whether explicitly requested Linux cgroup-backed limits fail closed
    /// or degrade best-effort when they cannot be enforced.
    pub fn resource_enforcement(mut self, enforcement: ResourceEnforcement) -> Self {
        self.config.resource_enforcement = enforcement;
        self
    }

    /// Build the [`ResourceConfig`].
    pub fn build(self) -> Result<ResourceConfig> {
        // Structural validation
        if let Some(limit) = self.config.memory_limit {
            if limit == 0 {
                return Err(crate::error::config("memory_limit must be greater than 0"));
            }
        }
        if let Some(limit) = self.config.cpu_limit {
            if limit <= 0.0 {
                return Err(crate::error::config("cpu_limit must be greater than 0"));
            }
        }
        if let Some(limit) = self.config.wall_time_limit {
            if limit.is_zero() {
                return Err(crate::error::config(
                    "wall_time_limit must be greater than 0",
                ));
            }
        }
        if let Some(limit) = self.config.cpu_time_limit {
            if limit.is_zero() {
                return Err(crate::error::config(
                    "cpu_time_limit must be greater than 0",
                ));
            }
        }
        if let Some(limit) = self.config.max_file_size {
            if limit == 0 {
                return Err(crate::error::config("max_file_size must be greater than 0"));
            }
        }
        if let Some(limit) = self.config.max_open_files {
            if limit == 0 {
                return Err(crate::error::config(
                    "max_open_files must be greater than 0",
                ));
            }
        }
        Ok(self.config)
    }
}
