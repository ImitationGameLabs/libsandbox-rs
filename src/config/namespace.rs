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
///
/// Note that the default PID namespace has subtle signal/reaping consequences
/// for the spawned command — see [`Self::pid`].
#[derive(Clone, Debug)]
pub struct NamespaceConfig {
    /// Unshare the user namespace (`CLONE_NEWUSER`).
    pub user: bool,
    /// Unshare the PID namespace (`CLONE_NEWPID`).
    ///
    /// Enabled by default. The spawned command then runs as **PID 1** of the
    /// new namespace, which has two consequences worth knowing:
    ///
    /// - **Signal immunity:** the kernel does not deliver a signal sent *from
    ///   within the namespace* to its own init (PID 1) unless the process
    ///   installed a handler for it — this covers self-sent `SIGKILL`/`SIGSTOP`
    ///   and signals from descendant processes. A command that tries to exit by
    ///   signalling itself (e.g. `kill -9 0`, `raise(SIGKILL)`) will *not* die
    ///   from that signal. It is only terminated by the sandbox's parent-side
    ///   enforcement — wall-time timeout, cgroup OOM, or drop-time `SIGKILL` —
    ///   which act from the ancestor namespace and bypass this protection.
    /// - **Zombie reaping:** as PID 1, the command is responsible for reaping
    ///   its own children. No reaper init is installed, so grandchildren the
    ///   command does not `wait` for accumulate as zombies.
    ///
    /// Disable this (`pid(false)`) if the command needs ordinary in-namespace
    /// signal semantics — note that mounting `/proc` then requires
    /// [`ProcfsMode::Leave`] (a procfs remount needs a PID namespace).
    ///
    /// [`ProcfsMode::Leave`]: crate::config::ProcfsMode::Leave
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
    ///
    /// Enabling it (the default) makes the spawned command PID 1 of the new
    /// namespace, with the signal-immunity and zombie-reaping consequences
    /// described on [`NamespaceConfig::pid`] — read that before relying on
    /// in-namespace signal semantics.
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
