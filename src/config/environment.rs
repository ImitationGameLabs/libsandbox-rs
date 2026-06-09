//! Environment configuration and builder.

use std::collections::HashMap;

/// Environment configuration produced by [`EnvironmentBuilder`].
#[derive(Clone, Debug)]
pub struct EnvironmentConfig {
    pub env: HashMap<String, String>,
    pub clear_env: bool,
    pub hostname: String,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            env: HashMap::new(),
            clear_env: true,
            hostname: "sandbox".into(),
        }
    }
}

impl EnvironmentConfig {
    /// Create a new [`EnvironmentBuilder`].
    pub fn builder() -> EnvironmentBuilder {
        EnvironmentBuilder::new()
    }
}

/// Fluent builder for [`EnvironmentConfig`].
#[derive(Clone)]
pub struct EnvironmentBuilder {
    config: EnvironmentConfig,
}

impl Default for EnvironmentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvironmentBuilder {
    /// Create a new `EnvironmentBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            config: EnvironmentConfig::default(),
        }
    }

    /// Set an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.env.insert(key.into(), value.into());
        self
    }

    /// Set multiple environment variables.
    pub fn envs(mut self, envs: impl IntoIterator<Item = (String, String)>) -> Self {
        self.config.env.extend(envs);
        self
    }

    /// Whether to clear inherited environment variables (default: true).
    pub fn clear_env(mut self, clear: bool) -> Self {
        self.config.clear_env = clear;
        self
    }

    /// Set hostname inside the sandbox.
    pub fn hostname(mut self, name: impl Into<String>) -> Self {
        self.config.hostname = name.into();
        self
    }

    /// Build the [`EnvironmentConfig`].
    pub fn build(self) -> crate::error::Result<EnvironmentConfig> {
        Ok(self.config)
    }
}
