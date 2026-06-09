//! Sandbox builder implementation.
//!
//! Provides a fluent API for composing domain configs into a sandbox.

use crate::config::ResourceEnforcement;
use crate::config::{
    EnvironmentConfig, FilesystemConfig, NetworkConfig, ResourceConfig, SecurityConfig,
};
use crate::error::{Result, SandboxError};
use crate::sandbox::Sandbox;

/// Sandbox configuration — a composition of domain configs.
///
/// Produced by [`SandboxBuilder::build()`] and consumed by the platform
/// executor at spawn time. Users do not construct this directly.
#[derive(Clone, Debug, Default)]
pub struct SandboxConfig {
    pub filesystem: FilesystemConfig,
    pub resources: ResourceConfig,
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub environment: EnvironmentConfig,
}

/// Sandbox builder — an aggregator for domain configs.
///
/// Construct via [`Sandbox::builder()`] or one of the preset methods
/// ([`Sandbox::code_judge`], [`Sandbox::agent_executor`], etc.).
/// Each domain has its own builder (e.g., [`ResourceConfig::builder()`])
/// that produces a typed config struct. Use the consume methods
/// (`.filesystem()`, `.resources()`, etc.) to set domain configs.
///
/// # Example
///
/// ```rust,no_run
/// use libsandbox::{Sandbox, Permission, MB};
/// use libsandbox::config::{FilesystemConfig, ResourceConfig, NetworkConfig};
/// use std::time::Duration;
///
/// let sandbox = Sandbox::builder()
///     .filesystem(
///         FilesystemConfig::builder()
///             .mount("/data/input", "/input", Permission::ReadOnly)
///             .working_dir("/tmp")
///             .build()
///             .unwrap()
///     )
///     .resources(
///         ResourceConfig::builder()
///             .memory_limit(512 * MB)
///             .wall_time_limit(Duration::from_secs(30))
///             .build()
///             .unwrap()
///     )
///     .network(NetworkConfig::none())
///     .build()
///     .unwrap();
/// ```
#[derive(Clone)]
pub struct SandboxBuilder {
    pub(crate) filesystem: FilesystemConfig,
    pub(crate) resources: ResourceConfig,
    pub(crate) network: NetworkConfig,
    pub(crate) security: SecurityConfig,
    pub(crate) environment: EnvironmentConfig,
}

impl Default for SandboxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxBuilder {
    /// Create a new `SandboxBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            filesystem: FilesystemConfig::default(),
            resources: ResourceConfig::default(),
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            environment: EnvironmentConfig::default(),
        }
    }

    // ========== Domain consume methods ==========

    /// Set the filesystem configuration.
    pub fn filesystem(mut self, config: FilesystemConfig) -> Self {
        self.filesystem = config;
        self
    }

    /// Set the resource limit configuration.
    pub fn resources(mut self, config: ResourceConfig) -> Self {
        self.resources = config;
        self
    }

    /// Set the network configuration.
    pub fn network(mut self, config: NetworkConfig) -> Self {
        self.network = config;
        self
    }

    /// Set the security configuration.
    pub fn security(mut self, config: SecurityConfig) -> Self {
        self.security = config;
        self
    }

    /// Set the environment configuration.
    pub fn environment(mut self, config: EnvironmentConfig) -> Self {
        self.environment = config;
        self
    }

    // ========== Build ==========

    /// Build the sandbox.
    pub fn build(self) -> Result<Sandbox> {
        self.validate()?;
        let config = SandboxConfig {
            filesystem: self.filesystem,
            resources: self.resources,
            network: self.network,
            security: self.security,
            environment: self.environment,
        };
        let execution_policy = config.resources.to_execution_policy();
        Sandbox::from_config(config, execution_policy)
    }

    fn validate(&self) -> Result<()> {
        self.pre_check_platform()?;

        // Validate mount source paths exist.
        for mount in &self.filesystem.mounts {
            if !mount.source.exists() {
                return Err(SandboxError::PathNotFound(mount.source.clone()));
            }
        }

        // Validate rootfs if specified.
        if let Some(rootfs) = &self.filesystem.rootfs {
            if !rootfs.exists() || !rootfs.is_dir() {
                return Err(SandboxError::PathNotFound(rootfs.clone()));
            }
        }

        Ok(())
    }

    /// Pre-check platform capabilities before building sandbox.
    fn pre_check_platform(&self) -> Result<()> {
        use crate::cgroup::{probe_cgroup_support, CgroupController};

        let support = probe_cgroup_support();

        if self.resources.cgroup_limit_requests.memory
            && !nix::unistd::geteuid().is_root()
            && !support.can_enforce(CgroupController::Memory)
        {
            return Err(SandboxError::ResourceLimitUnavailable {
                limit: "memory".into(),
                reason: support.unavailable_reason(Some(CgroupController::Memory)),
            });
        }

        let strict_limits = [
            (
                self.resources.cgroup_limit_requests.memory,
                CgroupController::Memory,
                "memory",
            ),
            (
                self.resources.cgroup_limit_requests.cpu,
                CgroupController::Cpu,
                "cpu",
            ),
            (
                self.resources.cgroup_limit_requests.pids,
                CgroupController::Pids,
                "pids",
            ),
        ];

        if self.resources.resource_enforcement == ResourceEnforcement::Strict
            && strict_limits.iter().any(|(requested, _, _)| *requested)
        {
            for (requested, controller, name) in strict_limits {
                if !requested {
                    continue;
                }
                if !support.can_enforce(controller) {
                    return Err(SandboxError::ResourceLimitUnavailable {
                        limit: name.into(),
                        reason: support.unavailable_reason(Some(controller)),
                    });
                }
            }
        }

        // Check user namespace support.
        if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
            if content.trim() == "0" {
                return Err(SandboxError::Config(
                    "Unprivileged user namespaces disabled. Run: sudo sysctl kernel.unprivileged_userns_clone=1".into()
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CgroupLimitRequests, SeccompProfile};

    #[test]
    fn test_builder_default() {
        let builder = SandboxBuilder::new();
        assert!(builder.filesystem.mounts.is_empty());
        assert!(builder.resources.memory_limit.is_none());
        assert_eq!(builder.resources.max_pids, Some(64));
        assert!(matches!(
            builder.network.mode,
            crate::config::NetworkMode::None
        ));
    }

    #[test]
    fn test_builder_memory_limit() {
        let builder = SandboxBuilder::new().resources(
            ResourceConfig::builder()
                .memory_limit(512 * 1024 * 1024)
                .build()
                .unwrap(),
        );
        assert_eq!(builder.resources.memory_limit, Some(512 * 1024 * 1024));
        assert!(builder.resources.cgroup_limit_requests.memory);
    }

    #[test]
    fn test_builder_env() {
        let config = EnvironmentConfig::builder()
            .env("FOO", "bar")
            .env("BAZ", "qux")
            .build()
            .unwrap();
        assert_eq!(config.env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(config.env.get("BAZ"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_builder_tmpfs() {
        let config = FilesystemConfig::builder()
            .tmpfs("/tmp", 64 * 1024 * 1024)
            .build()
            .unwrap();
        assert_eq!(config.tmpfs_mounts.len(), 1);
        assert_eq!(config.tmpfs_mounts[0].1, 64 * 1024 * 1024);
    }

    #[test]
    fn test_builder_network_modes() {
        let config = NetworkConfig::none();
        assert!(matches!(config.mode, crate::config::NetworkMode::None));

        let config = NetworkConfig::host();
        assert!(matches!(config.mode, crate::config::NetworkMode::Host));

        let config = NetworkConfig::proxied(&["example.com"]);
        assert!(matches!(
            config.mode,
            crate::config::NetworkMode::Proxied { .. }
        ));
    }

    #[test]
    fn test_seccomp_profile() {
        let config = SecurityConfig::builder()
            .seccomp_profile(SeccompProfile::Strict)
            .build()
            .unwrap();
        assert!(matches!(config.seccomp_profile, SeccompProfile::Strict));
    }

    #[test]
    fn test_resource_enforcement_default() {
        let builder = SandboxBuilder::new();
        assert_eq!(
            builder.resources.resource_enforcement,
            ResourceEnforcement::Strict
        );
        assert_eq!(
            builder.resources.cgroup_limit_requests,
            CgroupLimitRequests::default()
        );
    }

    #[test]
    fn test_resource_enforcement_override() {
        let builder = SandboxBuilder::new().resources(
            ResourceConfig::builder()
                .resource_enforcement(ResourceEnforcement::BestEffort)
                .build()
                .unwrap(),
        );
        assert_eq!(
            builder.resources.resource_enforcement,
            ResourceEnforcement::BestEffort
        );
    }

    #[test]
    fn test_seccomp_profile_equality() {
        assert_eq!(SeccompProfile::Disabled, SeccompProfile::Disabled);
        assert_eq!(SeccompProfile::Strict, SeccompProfile::Strict);
        assert_eq!(SeccompProfile::Standard, SeccompProfile::Standard);
        assert_eq!(SeccompProfile::Permissive, SeccompProfile::Permissive);
        assert_ne!(SeccompProfile::Standard, SeccompProfile::Strict);
        assert_ne!(SeccompProfile::Disabled, SeccompProfile::Permissive);
    }

    #[test]
    fn test_seccomp_profile_custom_equality() {
        use crate::seccomp::{SeccompAction, SeccompFilterBuilder};

        let a = SeccompFilterBuilder::new(SeccompAction::Allow)
            .deny("ptrace")
            .unwrap()
            .build()
            .unwrap();
        let b = SeccompFilterBuilder::new(SeccompAction::Allow)
            .deny("ptrace")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(SeccompProfile::Custom(a), SeccompProfile::Custom(b));

        let c = SeccompFilterBuilder::new(SeccompAction::Allow)
            .deny("mount")
            .unwrap()
            .build()
            .unwrap();
        assert_ne!(SeccompProfile::Custom(c), SeccompProfile::Standard);
    }

    #[test]
    fn test_seccomp_filter_inequality() {
        use crate::seccomp::{SeccompAction, SeccompFilterBuilder};

        let a = SeccompFilterBuilder::new(SeccompAction::Allow)
            .build()
            .unwrap();
        let b = SeccompFilterBuilder::new(SeccompAction::Allow)
            .deny("ptrace")
            .unwrap()
            .build()
            .unwrap();
        assert_ne!(a, b);
    }
}
