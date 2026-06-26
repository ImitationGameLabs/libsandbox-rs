//! Mount namespace operations: filesystem setup, dynamic mounts, and validation.

pub mod handle;
pub mod holes;
pub(crate) mod ops;
pub(crate) mod syscalls;
pub(crate) mod validation;

// Public re-exports for convenience.
pub use handle::{DynamicMount, MountHandle};
