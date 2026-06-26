//! SeccompFilter — compiled, immutable BPF program.

use crate::error::Result;

use super::bpf::{load_filter, set_no_new_privs};
use super::SeccompAction;

/// A compiled seccomp-BPF filter ready to be loaded into the kernel.
///
/// Created by [`SeccompFilterBuilder::build`](super::SeccompFilterBuilder::build)
/// (or [`prepare_seccomp`](crate::prepare_seccomp) for a profile). Load it in
/// the sandboxed child via [`install`](SeccompFilter::install), or wrap it in
/// [`SeccompProfile::Custom`](crate::SeccompProfile) for use with the sandbox
/// builder.
#[derive(Clone, Debug)]
pub struct SeccompFilter {
    pub(super) default_action: SeccompAction,
    pub(super) program: Vec<libc::sock_filter>,
    pub(super) rule_count: usize,
}

impl SeccompFilter {
    /// Install this filter in the current process: set `PR_SET_NO_NEW_PRIVS`,
    /// then load the BPF program via `seccomp(2)` (falling back to
    /// `prctl(PR_SET_SECCOMP, ...)` if the `seccomp` syscall is unavailable).
    ///
    /// This is the child-side install primitive — call it inside the sandboxed
    /// child (after `clone`, before `exec`). It is allocation-free and
    /// async-signal-safe (raw syscalls only).
    ///
    /// # Security note
    ///
    /// `PR_SET_NO_NEW_PRIVS` is a one-way operation. If `load_filter` fails
    /// after `set_no_new_privs` succeeds, the flag remains set permanently.
    /// Callers should treat failure as fatal.
    pub fn install(&self) -> Result<()> {
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
