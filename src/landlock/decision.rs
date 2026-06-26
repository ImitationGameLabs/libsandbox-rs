//! Per-spawn access decision consumed by landlock enforcement.
//!
//! This is the **mechanism contract** at the seam between caller policy (an agent
//! runtime, a CLI, tests) and the landlock mechanism in this module. It deliberately
//! carries no agent identity, tier, or policy labels: callers map their own policy onto
//! these mechanism types when they build the decision.
//!
//! # Read-only holes inside a writable tree
//!
//! Landlock rules only *grant* access; they cannot subtract it. So a read-only "hole"
//! inside a writable tree cannot be expressed in a single landlock ruleset (pinned by the
//! `writable_ancestor_cannot_be_narrowed_to_readonly` test in the module's `tests` submodule).
//!
//! When such a hole is required, realize it through the **mount layer** instead: add a
//! `Mount { source: hole, target: hole, permission: Permission::ReadOnly }` to the
//! sandbox's [`FilesystemConfig`](crate::config::FilesystemConfig). `bind_mount` performs
//! the bind + read-only remount that the landlock domain then resolves against.
//!
//! # Namespace prerequisite
//!
//! That mount-layer hole replacement relies on the spawn creating a user + mount
//! namespace (`NamespaceConfig { user: true, mount: true }` — the default). A caller that
//! disables either namespace forfeits the read-only-hole mechanism: `bind_mount` fails
//! `EPERM` (surfaced at [`ChildStage::Mount`](crate::error::ChildStage)).

#![cfg(all(target_os = "linux", feature = "landlock"))]

use std::path::PathBuf;

/// Read policy for a spawned process — the difference between the broad and narrow
/// (read-restricted) policies.
#[derive(Clone, Debug)]
pub enum ReadPolicy {
    /// Broad read+exec on `/`: the program and its libs load normally.
    ///
    /// **Secrets are NOT protected under `Broad`.** Granting `/` makes the entire host
    /// filesystem readable, including `~/.ssh`, `/etc`, `/proc` (and thus
    /// `/proc/self/environ`), and `/sys`. Use `Broad` only when the caller has already
    /// isolated secrets by other means — e.g. a `ReadOnly`/hidden mount over them, or
    /// when `clear_env` plus namespace isolation renders `/proc/self/environ` inert. For
    /// read confinement, use [`Narrow`](Self::Narrow).
    Broad,
    /// Narrow read: only `paths` are granted read; everything else — including `$HOME`
    /// and secrets — is denied by default (landlock's `handle_access(full)` is
    /// deny-default, so anything not listed is unreadable). `paths` must include enough
    /// for the program/libs to run (e.g. `/usr`, `/bin`, `/lib`) plus the workspace.
    Narrow { paths: Vec<PathBuf> },
}

/// Per-spawn access decision consumed by [`super::prepare_landlock`].
///
/// - `writable` is granted full read+write (the caller's write set + scratch + the
///   always-merged `baseline_writable` scratch/devices). For the narrow policy this is
///   typically just scratch.
///
/// Read-only holes are NOT carried here: see the module-level note on realizing them via
/// `FilesystemConfig` mounts.
#[derive(Clone, Debug)]
pub struct AccessDecision {
    /// What the spawned process may read.
    pub read: ReadPolicy,
    /// Paths granted write access (in addition to the merged baseline).
    pub writable: Vec<PathBuf>,
}
