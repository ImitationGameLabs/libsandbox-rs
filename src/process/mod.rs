//! Process lifecycle: spawn, fd management, wait, and child handle.
//!
//! This module contains the core pipeline for creating and managing sandboxed
//! child processes. [`Child`] is the public handle for a spawned process; the
//! spawn, wait, and fd submodules provide the internal implementation.

mod child;
mod fd;
mod spawn;
mod wait;

// Public re-exports
pub use child::{Child, ExitStatus};

// Crate-internal re-exports
pub(crate) use fd::write_all_raw;
pub(crate) use spawn::spawn_isolated;
pub(crate) use wait::wait_with_timeout;
