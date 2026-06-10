//! Shared helpers for libsandbox benchmarks.
//!
//! Imported via `mod common;` in each bench file.

use libsandbox::config::{FilesystemConfig, ResourceConfig};
use libsandbox::Sandbox;
use std::time::Duration;

/// Build a standard execution sandbox with the given wall-time limit.
pub fn exec_sandbox(timeout: Duration) -> Sandbox {
    Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(timeout)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}
