//! Security configuration and builder.

/// Seccomp security profile (syscall filtering).
///
/// Preset profiles compile and install BPF filter programs at sandbox spawn
/// time. Use [`SeccompFilterBuilder`](crate::seccomp::SeccompFilterBuilder)
/// to construct a `Custom` profile.
#[derive(Clone, Debug, Default)]
pub enum SeccompProfile {
    /// Disable seccomp filtering (not recommended).
    Disabled,
    /// Allow only safe syscalls (most restrictive).
    Strict,
    /// Standard set of allowed syscalls.
    #[default]
    Standard,
    /// More permissive, for interactive use.
    Permissive,
    /// Custom filter built with [`SeccompFilterBuilder`](crate::seccomp::SeccompFilterBuilder).
    Custom(crate::seccomp::SeccompFilter),
}

impl PartialEq for SeccompProfile {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Disabled, Self::Disabled) => true,
            (Self::Strict, Self::Strict) => true,
            (Self::Standard, Self::Standard) => true,
            (Self::Permissive, Self::Permissive) => true,
            (Self::Custom(a), Self::Custom(b)) => a == b,
            _ => false,
        }
    }
}

/// Security configuration produced by [`SecurityBuilder`].
#[derive(Clone, Debug, Default)]
pub struct SecurityConfig {
    /// The seccomp profile to install in the child.
    pub seccomp_profile: SeccompProfile,
    /// Mapped UID inside the user namespace (`None` -> inherit / default mapping).
    pub uid: Option<u32>,
    /// Mapped GID inside the user namespace (`None` -> inherit / default mapping).
    pub gid: Option<u32>,
}

impl SecurityConfig {
    /// Create a new [`SecurityBuilder`].
    pub fn builder() -> SecurityBuilder {
        SecurityBuilder::new()
    }
}

/// Fluent builder for [`SecurityConfig`].
#[derive(Clone)]
pub struct SecurityBuilder {
    config: SecurityConfig,
}

impl Default for SecurityBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityBuilder {
    /// Create a new `SecurityBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            config: SecurityConfig::default(),
        }
    }

    /// Set seccomp profile.
    pub fn seccomp_profile(mut self, profile: SeccompProfile) -> Self {
        self.config.seccomp_profile = profile;
        self
    }

    /// Set UID inside the sandbox.
    pub fn uid(mut self, uid: u32) -> Self {
        self.config.uid = Some(uid);
        self
    }

    /// Set GID inside the sandbox.
    pub fn gid(mut self, gid: u32) -> Self {
        self.config.gid = Some(gid);
        self
    }

    /// Build the [`SecurityConfig`].
    pub fn build(self) -> crate::error::Result<SecurityConfig> {
        Ok(self.config)
    }
}
