//! Domain-specific configuration types and builders.
//!
//! Each sandbox domain (filesystem, resources, network, security, environment)
//! has its own config struct and fluent builder. These are consumed by
//! [`SandboxBuilder`](crate::SandboxBuilder) to compose the full sandbox
//! configuration.

pub mod environment;
pub mod filesystem;
pub mod network;
pub mod resource;
pub mod security;

// Re-export all config and builder types for convenience.
pub use environment::{EnvironmentBuilder, EnvironmentConfig};
pub use filesystem::{FilesystemBuilder, FilesystemConfig, Mount, MountOptions, Permission};
pub use network::{NetworkBuilder, NetworkConfig, NetworkMode};
pub use resource::{
    CgroupLimitRequests, ExecutionPolicy, ResourceBuilder, ResourceConfig, ResourceEnforcement,
};
pub use security::{SeccompProfile, SecurityBuilder, SecurityConfig};
