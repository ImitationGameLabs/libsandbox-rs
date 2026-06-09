//! Mount namespace operations: filesystem setup, dynamic mounts, and validation.

pub(crate) mod ops;
pub(crate) mod syscalls;
pub(crate) mod validation;
pub mod handle;

// Public re-exports for convenience.
pub use handle::{DynamicMount, MountHandle};
