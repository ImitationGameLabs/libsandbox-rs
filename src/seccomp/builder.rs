//! SeccompFilterBuilder — declarative rule API.

use crate::error::{ErrorKind, Result, SandboxError};

use super::bpf::compile_bpf;
use super::filter::SeccompFilter;
use super::presets::{
    BLOCKED_SYSCALLS, BLOCKED_SYSCALLS_X86_ONLY, LANDLOCK_CHILD_SYSCALLS,
    PERMISSIVE_EXTRA_SYSCALLS, PERMISSIVE_EXTRA_SYSCALLS_X86_ONLY, STANDARD_SYSCALLS,
    STANDARD_SYSCALLS_X86_ONLY, STRICT_SYSCALLS, STRICT_SYSCALLS_X86_ONLY,
};
use super::syscalls::syscall_number;
use super::{Rule, SeccompAction};

/// Builder for constructing seccomp-BPF filters.
///
/// Rules are accumulated in insertion order and compiled into a sorted BPF
/// jump table by [`build`](SeccompFilterBuilder::build).
///
/// # Example
///
/// ```no_run
/// use libsandbox::seccomp::{SeccompAction, SeccompFilterBuilder};
///
/// let filter = SeccompFilterBuilder::standard()
///     .deny("socket")?
///     .build()?;
/// # Ok::<(), libsandbox::SandboxError>(())
/// ```
#[derive(Clone, Debug)]
pub struct SeccompFilterBuilder {
    default_action: SeccompAction,
    rules: Vec<Rule>,
}

impl SeccompFilterBuilder {
    // --- Constructors ---

    /// Create an empty builder with the given default action (applied when no
    /// rule matches).
    pub fn new(default_action: SeccompAction) -> Self {
        Self {
            default_action,
            rules: Vec::new(),
        }
    }

    /// Preset for strict sandboxing: essential syscalls allowed, everything
    /// else kills the process.
    ///
    /// **Security note**: The `ioctl` syscall is allowed to support terminal
    /// and file descriptor operations. This includes `TIOCSTI`, which can
    /// push characters into a shared terminal's input buffer. If the sandboxed
    /// process shares a terminal with the host, consider removing `ioctl` with
    /// `.remove("ioctl")` after constructing this preset.
    pub fn strict() -> Self {
        Self {
            default_action: SeccompAction::KillProcess,
            rules: STRICT_SYSCALLS
                .iter()
                .chain(STRICT_SYSCALLS_X86_ONLY.iter())
                .chain(LANDLOCK_CHILD_SYSCALLS.iter())
                .map(|&name| Rule {
                    syscall_nr: syscall_number(name)
                        .unwrap_or_else(|_| panic!("strict preset: unknown syscall '{name}'")),
                    action: SeccompAction::Allow.to_bpf_ret(),
                })
                .collect(),
        }
    }

    /// Preset for standard sandboxing: ~80 commonly-needed syscalls allowed,
    /// everything else kills the process.
    pub fn standard() -> Self {
        Self {
            default_action: SeccompAction::KillProcess,
            rules: STANDARD_SYSCALLS
                .iter()
                .chain(STANDARD_SYSCALLS_X86_ONLY.iter())
                .chain(LANDLOCK_CHILD_SYSCALLS.iter())
                .map(|&name| Rule {
                    syscall_nr: syscall_number(name)
                        .unwrap_or_else(|_| panic!("standard preset: unknown syscall '{name}'")),
                    action: SeccompAction::Allow.to_bpf_ret(),
                })
                .collect(),
        }
    }

    /// Preset for permissive sandboxing: ~150+ syscalls allowed, only the most
    /// dangerous ones are explicitly denied.
    pub fn permissive() -> Self {
        // In permissive mode we allow everything by default and explicitly
        // block the dangerous syscalls. We also add the standard allowed set
        // as explicit Allow rules for clarity, but the default is Allow.
        let mut rules: Vec<Rule> = STANDARD_SYSCALLS
            .iter()
            .chain(STANDARD_SYSCALLS_X86_ONLY.iter())
            .map(|&name| Rule {
                syscall_nr: syscall_number(name)
                    .unwrap_or_else(|_| panic!("permissive preset: unknown syscall '{name}'")),
                action: SeccompAction::Allow.to_bpf_ret(),
            })
            .collect();

        // Add permissive-only extras
        for &name in PERMISSIVE_EXTRA_SYSCALLS
            .iter()
            .chain(PERMISSIVE_EXTRA_SYSCALLS_X86_ONLY.iter())
        {
            rules.push(Rule {
                syscall_nr: syscall_number(name)
                    .unwrap_or_else(|_| panic!("permissive preset: unknown syscall '{name}'")),
                action: SeccompAction::Allow.to_bpf_ret(),
            });
        }

        // Deny dangerous syscalls (these take precedence because we sort by
        // syscall number and deduplicate, keeping the *last* entry for a given
        // number — we append denies *after* allows so they win).
        for &name in BLOCKED_SYSCALLS.iter().chain(BLOCKED_SYSCALLS_X86_ONLY.iter()) {
            rules.push(Rule {
                syscall_nr: syscall_number(name)
                    .unwrap_or_else(|_| panic!("permissive preset: unknown syscall '{name}'")),
                action: SeccompAction::KillProcess.to_bpf_ret(),
            });
        }

        Self {
            default_action: SeccompAction::Allow,
            rules,
        }
    }

    // --- Configuration ---

    /// Change the default action (applied when no rule matches).
    pub fn default_action(mut self, action: SeccompAction) -> Self {
        self.default_action = action;
        self
    }

    /// Add an Allow rule for the named syscall.
    pub fn allow(self, syscall: &str) -> Result<Self> {
        self.add_rule(syscall, SeccompAction::Allow)
    }

    /// Add a KillProcess rule for the named syscall.
    pub fn deny(self, syscall: &str) -> Result<Self> {
        self.add_rule(syscall, SeccompAction::KillProcess)
    }

    /// Add an Errno rule for the named syscall.
    pub fn deny_with_errno(self, syscall: &str, errno: u16) -> Result<Self> {
        self.add_rule(syscall, SeccompAction::Errno(errno))
    }

    /// Add a Log rule for the named syscall (allow + audit logging).
    pub fn log(self, syscall: &str) -> Result<Self> {
        self.add_rule(syscall, SeccompAction::Log)
    }

    /// Add Allow rules for multiple syscalls.
    pub fn allow_all(self, syscalls: &[&str]) -> Result<Self> {
        let mut builder = self;
        for &name in syscalls {
            builder = builder.allow(name)?;
        }
        Ok(builder)
    }

    /// Add KillProcess rules for multiple syscalls.
    pub fn deny_all(self, syscalls: &[&str]) -> Result<Self> {
        let mut builder = self;
        for &name in syscalls {
            builder = builder.deny(name)?;
        }
        Ok(builder)
    }

    /// Remove all rules for the named syscall.
    pub fn remove(mut self, syscall: &str) -> Result<Self> {
        let nr = syscall_number(syscall)?;
        self.rules.retain(|r| r.syscall_nr != nr);
        Ok(self)
    }

    // --- Compile ---

    /// Compile the accumulated rules into an immutable [`SeccompFilter`].
    ///
    /// Validates that `exit` and `exit_group` remain callable (otherwise the
    /// process cannot terminate cleanly).
    pub fn build(self) -> Result<SeccompFilter> {
        // Sort and dedup FIRST so exit validation operates on the effective
        // (post-dedup) rule set. This ensures last-wins semantics are respected
        // when checking that exit/exit_group remain callable.
        let sorted = dedup_rules(&self.rules);

        // Validate: exit and exit_group must be callable
        let exit_nr = syscall_number("exit")?;
        let exit_group_nr = syscall_number("exit_group")?;

        let allow_ret = SeccompAction::Allow.to_bpf_ret();
        let log_ret = SeccompAction::Log.to_bpf_ret();

        let exit_blocked = sorted
            .iter()
            .any(|r| r.syscall_nr == exit_nr && r.action != allow_ret && r.action != log_ret);
        let exit_group_blocked = sorted
            .iter()
            .any(|r| r.syscall_nr == exit_group_nr && r.action != allow_ret && r.action != log_ret);

        // If default action is NOT callable, then exit/exit_group must have
        // explicit callable rules.
        let default_allows = matches!(
            self.default_action,
            SeccompAction::Allow | SeccompAction::Log
        );
        let exit_has_allow = sorted
            .iter()
            .any(|r| r.syscall_nr == exit_nr && (r.action == allow_ret || r.action == log_ret));
        let exit_group_has_allow = sorted.iter().any(|r| {
            r.syscall_nr == exit_group_nr && (r.action == allow_ret || r.action == log_ret)
        });

        if exit_blocked
            || exit_group_blocked
            || (!default_allows && !exit_has_allow)
            || (!default_allows && !exit_group_has_allow)
        {
            return Err(SandboxError::new(
                ErrorKind::Seccomp,
                format!(
                    "seccomp filter build failed: {}",
                    "exit and exit_group must remain callable",
                ),
            ));
        }

        let unique_count = sorted.len();
        let program = compile_bpf(&self.default_action, &sorted)?;

        // Consistency check: BPF program length is deterministic.
        // With rules: 4 (header) + N (jump table) + 1 (JA) + N (rule RETs) + 1 (default) = 2N + 6
        // Without rules: 4 (header) + 1 (default RET) = 5
        debug_assert!(
            if sorted.is_empty() {
                program.len() == 5 && unique_count == 0
            } else {
                program.len() == 2 * unique_count + 6
            },
            "BPF program length ({}) inconsistent with rule_count ({})",
            program.len(),
            unique_count,
        );

        Ok(SeccompFilter {
            default_action: self.default_action,
            program,
            rule_count: unique_count,
        })
    }

    // --- Internal helpers ---

    fn add_rule(mut self, syscall: &str, action: SeccompAction) -> Result<Self> {
        let nr = syscall_number(syscall)?;
        self.rules.push(Rule {
            syscall_nr: nr,
            action: action.to_bpf_ret(),
        });
        Ok(self)
    }
}

/// Sort and deduplicate rules by syscall number, applying last-wins semantics.
///
/// When multiple rules target the same syscall, the last-inserted rule wins.
/// Uses sort → reverse → dedup → reverse (since `dedup_by` keeps the first
/// element).
pub(super) fn dedup_rules(rules: &[Rule]) -> Vec<&Rule> {
    let mut sorted: Vec<&Rule> = rules.iter().collect();
    sorted.sort_by_key(|r| r.syscall_nr);
    sorted.reverse();
    sorted.dedup_by(|a, b| a.syscall_nr == b.syscall_nr);
    sorted.reverse();
    sorted
}
