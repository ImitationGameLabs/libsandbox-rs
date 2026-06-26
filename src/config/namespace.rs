//! Namespace configuration.
//!
//! [`NamespaceConfig`] selects which Linux namespaces the sandboxed child
//! unshares via `clone()`. The network namespace decision is *not* part of
//! this struct: it is derived from [`crate::config::NetworkMode`] (`None`
//! implies an isolated net namespace; `Host`/`Proxied` share the host's) so
//! there is a single source of truth for network behavior.

/// Per-namespace unshare toggles for the sandboxed child.
///
/// All fields default to `true` (full isolation). The network namespace is
/// controlled separately via [`crate::config::NetworkMode`].
#[derive(Clone, Debug)]
pub struct NamespaceConfig {
    /// Unshare the user namespace (`CLONE_NEWUSER`).
    pub user: bool,
    /// Unshare the PID namespace (`CLONE_NEWPID`).
    pub pid: bool,
    /// Unshare the mount namespace (`CLONE_NEWNS`).
    pub mount: bool,
    /// Unshare the UTS namespace (`CLONE_NEWUTS`).
    pub uts: bool,
    /// Unshare the IPC namespace (`CLONE_NEWIPC`).
    pub ipc: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            user: true,
            pid: true,
            mount: true,
            uts: true,
            ipc: true,
        }
    }
}

impl NamespaceConfig {
    /// Create a new [`NamespaceBuilder`].
    pub fn builder() -> NamespaceBuilder {
        NamespaceBuilder::new()
    }
}

/// Fluent builder for [`NamespaceConfig`].
#[derive(Clone, Debug, Default)]
pub struct NamespaceBuilder {
    config: NamespaceConfig,
}

impl NamespaceBuilder {
    /// Create a new builder with full isolation (all namespaces enabled).
    pub fn new() -> Self {
        Self {
            config: NamespaceConfig::default(),
        }
    }

    /// Toggle the user namespace.
    pub fn user(mut self, enable: bool) -> Self {
        self.config.user = enable;
        self
    }

    /// Toggle the PID namespace.
    pub fn pid(mut self, enable: bool) -> Self {
        self.config.pid = enable;
        self
    }

    /// Toggle the mount namespace.
    pub fn mount(mut self, enable: bool) -> Self {
        self.config.mount = enable;
        self
    }

    /// Toggle the UTS namespace.
    pub fn uts(mut self, enable: bool) -> Self {
        self.config.uts = enable;
        self
    }

    /// Toggle the IPC namespace.
    pub fn ipc(mut self, enable: bool) -> Self {
        self.config.ipc = enable;
        self
    }

    /// Build the [`NamespaceConfig`].
    pub fn build(self) -> NamespaceConfig {
        self.config
    }
}
