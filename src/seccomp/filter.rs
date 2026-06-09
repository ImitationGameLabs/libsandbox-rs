//! SeccompFilter — compiled, immutable BPF program.

use crate::config::SeccompProfile;
use crate::error::Result;

use super::bpf::{load_filter, set_no_new_privs};
use super::builder::SeccompFilterBuilder;
use super::SeccompAction;

/// A compiled seccomp-BPF filter ready to be loaded into the kernel.
///
/// Created by [`SeccompFilterBuilder::build`]. Use [`apply`](SeccompFilter::apply)
/// to load it in the current process, or wrap it in
/// [`SeccompProfile::Custom`](crate::SeccompProfile) for use with the sandbox
/// builder.
#[derive(Clone, Debug)]
pub struct SeccompFilter {
    pub(super) default_action: SeccompAction,
    pub(super) program: Vec<libc::sock_filter>,
    pub(super) rule_count: usize,
}

impl SeccompFilter {
    /// Apply a built-in or custom seccomp profile.
    ///
    /// Called inside the sandboxed child process (after `clone`, before `exec`).
    /// Sets `PR_SET_NO_NEW_PRIVS` first, then loads the BPF filter.
    ///
    /// # Warning
    ///
    /// This sets `PR_SET_NO_NEW_PRIVS` before loading the filter. If the filter
    /// load fails, the flag remains set and **cannot be unset**. The calling
    /// process should treat a failure from this method as fatal and exit.
    pub fn apply(profile: &SeccompProfile) -> Result<()> {
        match profile {
            SeccompProfile::Disabled => Ok(()),
            SeccompProfile::Strict => {
                let filter = SeccompFilterBuilder::strict().build()?;
                filter.load()
            }
            SeccompProfile::Standard => {
                let filter = SeccompFilterBuilder::standard().build()?;
                filter.load()
            }
            SeccompProfile::Permissive => {
                let filter = SeccompFilterBuilder::permissive().build()?;
                filter.load()
            }
            SeccompProfile::Custom(filter) => filter.load(),
        }
    }

    /// Load this filter into the kernel for the current process.
    ///
    /// Sets `PR_SET_NO_NEW_PRIVS`, then installs the BPF program via
    /// `seccomp(2)` (falling back to `prctl(PR_SET_SECCOMP, ...)` if the
    /// `seccomp` syscall is unavailable).
    ///
    /// # Security note
    ///
    /// `PR_SET_NO_NEW_PRIVS` is a one-way operation. If `load_filter` fails
    /// after `set_no_new_privs` succeeds, the flag remains set permanently.
    /// Callers should treat failure as fatal.
    fn load(&self) -> Result<()> {
        set_no_new_privs()?;
        load_filter(&self.program)
    }

    /// Number of BPF instructions in the compiled program (diagnostic).
    pub fn program_len(&self) -> usize {
        self.program.len()
    }

    /// Number of rules that were compiled into this filter.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// The default action this filter was compiled with.
    pub fn default_action(&self) -> &SeccompAction {
        &self.default_action
    }
}

impl PartialEq for SeccompFilter {
    fn eq(&self, other: &Self) -> bool {
        self.default_action == other.default_action
            && self.rule_count == other.rule_count
            && self.program.len() == other.program.len()
            && self
                .program
                .iter()
                .zip(other.program.iter())
                .all(|(a, b)| a.code == b.code && a.jt == b.jt && a.jf == b.jf && a.k == b.k)
    }
}
