//! Network configuration and builder.

/// Network access mode.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum NetworkMode {
    /// No network access (default, most secure).
    #[default]
    None,
    /// Use host network (not recommended, breaks isolation).
    Host,
    /// Network access through an HTTP proxy with a domain whitelist.
    ///
    /// Only available with the `tokio` feature (the proxy is a tokio runtime).
    /// Without the feature this variant cannot be constructed, so requesting
    /// proxied networking on a tokio-less build is rejected at compile time.
    #[cfg(feature = "tokio")]
    Proxied {
        /// Domains the child is allowed to reach (exact or wildcard).
        allowed_domains: Vec<String>,
    },
}

/// Network configuration produced by [`NetworkBuilder`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkConfig {
    /// Network access mode.
    pub mode: NetworkMode,
}

impl NetworkConfig {
    /// Create a new [`NetworkBuilder`].
    pub fn builder() -> NetworkBuilder {
        NetworkBuilder::new()
    }

    /// Shorthand: no network access.
    pub fn none() -> Self {
        Self {
            mode: NetworkMode::None,
        }
    }

    /// Shorthand: use host network.
    pub fn host() -> Self {
        Self {
            mode: NetworkMode::Host,
        }
    }

    /// Shorthand: proxied network with domain whitelist. Requires the `tokio`
    /// feature.
    #[cfg(feature = "tokio")]
    pub fn proxied(domains: &[&str]) -> Self {
        Self {
            mode: NetworkMode::Proxied {
                allowed_domains: domains.iter().map(|s| s.to_string()).collect(),
            },
        }
    }
}

/// Fluent builder for [`NetworkConfig`].
#[derive(Clone)]
pub struct NetworkBuilder {
    config: NetworkConfig,
}

impl Default for NetworkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkBuilder {
    /// Create a new `NetworkBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            config: NetworkConfig::default(),
        }
    }

    /// Disable network access (default).
    pub fn none(mut self) -> Self {
        self.config.mode = NetworkMode::None;
        self
    }

    /// Use host network.
    pub fn host(mut self) -> Self {
        self.config.mode = NetworkMode::Host;
        self
    }

    /// Allow network access only to specified domains. Requires the `tokio`
    /// feature.
    #[cfg(feature = "tokio")]
    pub fn proxied(mut self, domains: &[&str]) -> Self {
        self.config.mode = NetworkMode::Proxied {
            allowed_domains: domains.iter().map(|s| s.to_string()).collect(),
        };
        self
    }

    /// Build the [`NetworkConfig`].
    pub fn build(self) -> crate::error::Result<NetworkConfig> {
        Ok(self.config)
    }
}
