//! Network control module
//!
//! Provides network isolation and domain whitelisting for sandboxed processes.
//!
//! ## Architecture
//!
//! All platforms use an HTTP proxy for domain whitelisting:
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
//! │  Nanobox HTTP Proxy                                              │
//! │  - Check domain whitelist                                        │
//! │  - Allowed → Forward request                                     │
//! │  - Denied  → Return 403                                          │
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │
//!                              ▼
//!                         [Internet]
//! ```
//!
//! ## Platform-specific behavior
//!
//! | Platform | Network Isolation | Domain Whitelist |
//! |----------|-------------------|------------------|
//! | Linux    | network namespace | HTTP proxy       |

mod manager;
mod proxy;

pub use manager::ProxiedNetwork;
pub use proxy::HttpProxy;
