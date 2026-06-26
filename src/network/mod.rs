//! Network control module.
//!
//! Provides network isolation and domain whitelisting for sandboxed processes.
//!
//! With the `tokio` feature (default), [`ProxiedNetwork`] runs an HTTP proxy on
//! the host loopback and points the child at it via `HTTP_PROXY`/`HTTPS_PROXY`
//! env vars; only allowlisted domains are forwarded. Without the feature the
//! proxy is unavailable and [`NetworkMode::Proxied`](crate::config::NetworkMode)
//! cannot be constructed, so proxied networking is rejected at compile time.
//!
//! ## Architecture (with `tokio`)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Sandbox Process                                                 │
//! │  HTTP_PROXY=http://127.0.0.1:PORT                               │
//! │  HTTPS_PROXY=http://127.0.0.1:PORT                              │
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  HTTP Proxy                                                      │
//! │  - Check domain whitelist                                        │
//! │  - Allowed → Forward request                                     │
//! │  - Denied  → Return 403                                          │
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │
//!                              ▼
//!                         [Internet]
//! ```

#[cfg(feature = "tokio")]
mod manager;
#[cfg(feature = "tokio")]
mod proxy;

#[cfg(feature = "tokio")]
pub use manager::ProxiedNetwork;
#[cfg(feature = "tokio")]
pub use proxy::HttpProxy;

/// Placeholder [`ProxiedNetwork`] when the `tokio` feature is disabled.
///
/// Kept as a zero-sized type so that [`crate::process::Child`] has a stable
/// shape regardless of the feature; it is never actually constructed without
/// the feature (the `Proxied` network mode cannot be built).
#[cfg(not(feature = "tokio"))]
#[derive(Debug, Clone, Default)]
pub struct ProxiedNetwork;
