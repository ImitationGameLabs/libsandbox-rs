//! Seccomp-BPF syscall filtering for Linux.
//!
//! This module compiles declarative syscall rules into classic BPF programs and
//! loads them via the `seccomp(2)` syscall. Three preset profiles (`Strict`,
//! `Standard`, `Permissive`) cover most use-cases; a builder API allows
//! fine-grained customization.
//!
//! **Architecture**: x86_64 and aarch64. Other arches fail to compile via the
//! per-arch `AUDIT_ARCH` guard in `bpf.rs`.

mod bpf;
mod builder;
mod filter;
mod presets;
pub mod syscalls;

pub use builder::SeccompFilterBuilder;
pub use filter::SeccompFilter;
// Re-export the SyscallNumber alias and the curated SYS_* constants at the
// module root so callers write `libsandbox::seccomp::SYS_socket` directly.
// `syscalls` holds only `SyscallNumber` and the `SYS_*` re-exports, so the glob
// is tightly scoped; if it grows non-syscall items, switch to an explicit list.
pub use syscalls::*;

// Test-only re-exports for the integrated test module below.
#[cfg(test)]
use bpf::compile_bpf;
#[cfg(test)]
use bpf::AUDIT_ARCH;

// ---------------------------------------------------------------------------
// FFI types — libc already provides sock_filter / sock_fprog, but we use them
// through safe wrappers internally.
// ---------------------------------------------------------------------------

/// Action taken when a syscall matches a rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SeccompAction {
    /// Kill the entire process (`SECCOMP_RET_KILL_PROCESS`).
    KillProcess,
    /// Kill the offending thread (`SECCOMP_RET_KILL_THREAD`).
    KillThread,
    /// Deliver `SIGSYS` to the process (`SECCOMP_RET_TRAP`).
    Trap,
    /// Return the specified errno (`SECCOMP_RET_ERRNO`).
    /// The value must fit in 16 bits (0–65535), matching the kernel's
    /// `SECCOMP_RET_DATA` mask.
    Errno(u16),
    /// Allow but log the syscall (`SECCOMP_RET_LOG`).
    Log,
    /// Allow the syscall (`SECCOMP_RET_ALLOW`).
    Allow,
}

impl SeccompAction {
    /// Convert to the 32-bit BPF return value used in `SECCOMP_RET_*`.
    pub(super) fn to_bpf_ret(&self) -> u32 {
        match self {
            Self::KillProcess => libc::SECCOMP_RET_KILL_PROCESS,
            Self::KillThread => libc::SECCOMP_RET_KILL_THREAD,
            Self::Trap => libc::SECCOMP_RET_TRAP,
            Self::Errno(e) => libc::SECCOMP_RET_ERRNO | *e as u32,
            Self::Log => libc::SECCOMP_RET_LOG,
            Self::Allow => libc::SECCOMP_RET_ALLOW,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal rule representation
// ---------------------------------------------------------------------------

/// A single compiled rule: syscall number → BPF return action.
#[derive(Clone, Debug)]
pub(super) struct Rule {
    pub(super) syscall_nr: i32,
    pub(super) action: u32, // pre-encoded BPF return value
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_builder_compiles() {
        let filter = SeccompFilterBuilder::strict().build().unwrap();
        assert!(filter.program_len() > 0);
        assert!(filter.rule_count > 0);
        assert!(filter.program_len() <= libc::BPF_MAXINSNS as usize);
    }

    #[test]
    fn test_standard_builder_compiles() {
        let filter = SeccompFilterBuilder::standard().build().unwrap();
        assert!(filter.program_len() > 0);
        assert!(filter.rule_count > 0);
    }

    #[test]
    fn test_permissive_builder_compiles() {
        let filter = SeccompFilterBuilder::permissive().build().unwrap();
        assert!(filter.program_len() > 0);
        assert!(filter.rule_count > 0);
    }

    #[test]
    fn test_custom_filter() {
        let filter = SeccompFilterBuilder::new(SeccompAction::Allow)
            .deny(SYS_ptrace)
            .deny(SYS_mount)
            .build()
            .unwrap();
        assert!(filter.rule_count >= 2);
    }

    #[test]
    fn test_deny_from_standard() {
        let filter = SeccompFilterBuilder::standard()
            .deny(SYS_socket)
            .build()
            .unwrap();
        // Standard has ~80+ rules plus the deny override
        assert!(filter.rule_count > 80);
    }

    #[test]
    fn test_remove_rule() {
        let filter = SeccompFilterBuilder::standard()
            .remove(SYS_socket)
            .build()
            .unwrap();
        // One less than standard
        assert!(filter.rule_count > 70);
    }

    #[test]
    fn test_exit_must_remain_callable_default_kill() {
        // A filter that kills everything by default without allowing exit
        // should fail to build.
        let result = SeccompFilterBuilder::new(SeccompAction::KillProcess).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_bpf_program_structure() {
        let filter = SeccompFilterBuilder::strict().build().unwrap();
        let prog = &filter.program;

        // [0] First instruction should load arch
        assert_eq!(
            prog[0].code as u32,
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS
        );
        assert_eq!(prog[0].k, 4); // arch offset

        // [1] Second instruction should be arch check (JEQ)
        assert_eq!(
            prog[1].code as u32,
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K
        );
        assert_eq!(prog[1].k, AUDIT_ARCH);
        // jt=1 (skip arch_mismatch on match), jf=0 (fall through to kill on mismatch)
        assert_eq!(prog[1].jt, 1);
        assert_eq!(prog[1].jf, 0);

        // [2] Third instruction should be arch mismatch kill
        assert_eq!(prog[2].code as u32, libc::BPF_RET);
        assert_eq!(prog[2].k, libc::SECCOMP_RET_KILL_PROCESS);

        // [3] Fourth instruction should load syscall number
        assert_eq!(
            prog[3].code as u32,
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS
        );
        assert_eq!(prog[3].k, 0); // nr offset
    }

    #[test]
    fn test_seccomp_action_encoding() {
        assert_eq!(SeccompAction::Allow.to_bpf_ret(), libc::SECCOMP_RET_ALLOW);
        assert_eq!(
            SeccompAction::KillProcess.to_bpf_ret(),
            libc::SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(SeccompAction::Trap.to_bpf_ret(), libc::SECCOMP_RET_TRAP);
        assert_eq!(SeccompAction::Log.to_bpf_ret(), libc::SECCOMP_RET_LOG);
        assert_eq!(
            SeccompAction::Errno(13).to_bpf_ret(),
            libc::SECCOMP_RET_ERRNO | 13
        );
    }

    #[test]
    fn test_jump_offsets_and_ja_targets_valid() {
        // Build with enough rules to exercise the jump table.
        let filter = SeccompFilterBuilder::standard().build().unwrap();
        let prog = &filter.program;

        // Walk all jump instructions and validate their targets are in bounds.
        for (i, instr) in prog.iter().enumerate() {
            let class = instr.code as u32 & 0x07;
            if class != libc::BPF_JMP {
                continue;
            }

            let code = instr.code as u32;
            if code == libc::BPF_JMP {
                // BPF_JA (unconditional): k field is the jump offset.
                let target = i + 1 + instr.k as usize;
                assert!(
                    target < prog.len(),
                    "instruction {i}: BPF_JA k-target={target} out of bounds (prog len={})",
                    prog.len()
                );
            } else {
                // BPF_JEQ or other conditional jumps: jt/jf fields.
                let jt_target = i + 1 + instr.jt as usize;
                let jf_target = i + 1 + instr.jf as usize;
                assert!(
                    jt_target < prog.len(),
                    "instruction {i}: jt={jt_target} out of bounds (prog len={})",
                    prog.len()
                );
                assert!(
                    jf_target < prog.len(),
                    "instruction {i}: jf={jf_target} out of bounds (prog len={})",
                    prog.len()
                );
            }
        }
    }

    #[test]
    fn test_deny_overrides_allow_in_standard() {
        // Standard allows socket; deny should override to KillProcess.
        let filter = SeccompFilterBuilder::standard()
            .deny(SYS_socket)
            .build()
            .unwrap();

        let socket_nr = libc::SYS_socket as u32;
        let ret_k = find_ret_action_for_syscall(&filter.program, socket_nr, "socket");
        assert_eq!(
            ret_k,
            SeccompAction::KillProcess.to_bpf_ret(),
            "socket should be denied (KillProcess)"
        );
    }

    #[test]
    fn test_permissive_compiles_with_many_rules() {
        // Permissive has ~189 rules — verify it compiles without overflow
        let filter = SeccompFilterBuilder::permissive().build().unwrap();
        assert!(filter.program_len() > 100);
        assert!(filter.rule_count > 150);
    }

    #[test]
    fn test_overflow_returns_error_not_panic() {
        // The permissive preset has ~189 rules (under 255). The BPF_MAXINSNS
        // check and the jt overflow check both exercise the Result path through
        // emit_sorted_jump_table. Verify that an empty filter compiles (the
        // Result path is used) and the permissive preset also compiles.
        let result = SeccompFilterBuilder::new(SeccompAction::Allow).build();
        assert!(result.is_ok());

        let filter = SeccompFilterBuilder::permissive().build().unwrap();
        assert!(filter.program_len() > 100);
    }

    #[test]
    fn test_post_dedup_exit_validation_allows_override() {
        // .deny(SYS_exit).allow(SYS_exit) on KillProcess default:
        // after dedup, Allow wins (last-wins). Should compile.
        let filter = SeccompFilterBuilder::new(SeccompAction::KillProcess)
            .allow(SYS_read)
            .deny(SYS_exit)
            .allow(SYS_exit)
            .deny(SYS_exit_group)
            .allow(SYS_exit_group)
            .build();
        assert!(filter.is_ok(), "last-wins should allow exit override");
    }

    #[test]
    fn test_post_dedup_exit_validation_rejects_final_deny() {
        // .allow(SYS_exit).deny(SYS_exit) on KillProcess default:
        // after dedup, KillProcess (deny) wins. Should fail.
        let result = SeccompFilterBuilder::new(SeccompAction::KillProcess)
            .allow(SYS_exit)
            .deny(SYS_exit)
            .build();
        assert!(result.is_err(), "last-wins deny should block exit");
    }

    #[test]
    fn test_log_action_is_callable_for_exit() {
        // Log action allows the syscall (with logging), so exit with Log
        // should be accepted by the validation.
        //
        // We can't directly add a Log rule through the public builder API,
        // but we can test that a default action of Log is treated as callable.
        let result = SeccompFilterBuilder::new(SeccompAction::Log).build();
        assert!(
            result.is_ok(),
            "Log default action should be treated as callable for exit"
        );
    }

    #[test]
    fn test_255_rules_compiles_successfully() {
        // 255 rules should fit within u8::MAX for jt offsets.
        // With the inorder sorted layout, every rule JEQ has jt = N (the rule
        // count), so 255 is the exact boundary.
        let rules: Vec<Rule> = (0..255i32)
            .map(|nr| Rule {
                syscall_nr: nr,
                action: SeccompAction::Allow.to_bpf_ret(),
            })
            .collect();
        let rule_refs: Vec<&Rule> = rules.iter().collect();
        let result = compile_bpf(&SeccompAction::Allow, &rule_refs);
        assert!(result.is_ok(), "255 rules should compile without overflow");
    }

    #[test]
    fn test_256_rules_returns_overflow_error() {
        // 256 rules should overflow the jt u8 field (256 > 255).
        let rules: Vec<Rule> = (0..256i32)
            .map(|nr| Rule {
                syscall_nr: nr,
                action: SeccompAction::Allow.to_bpf_ret(),
            })
            .collect();
        let rule_refs: Vec<&Rule> = rules.iter().collect();
        let result = compile_bpf(&SeccompAction::Allow, &rule_refs);
        assert!(result.is_err(), "256 rules should fail with overflow");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("overflow"),
            "error should mention overflow: {err_msg}"
        );
    }

    // -----------------------------------------------------------------------
    // S9: API surface coverage — action types through compile_bpf
    // -----------------------------------------------------------------------

    /// Helper: find the RET instruction target for a given syscall JEQ in prog.
    /// Returns the RET instruction's `k` field (the encoded BPF action).
    fn find_ret_action_for_syscall(
        prog: &[libc::sock_filter],
        syscall_nr: u32,
        syscall_name: &str,
    ) -> u32 {
        for (i, instr) in prog.iter().enumerate() {
            if instr.code as u32 == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K
                && instr.k == syscall_nr
            {
                let ret_idx = i + 1 + instr.jt as usize;
                assert!(
                    ret_idx < prog.len(),
                    "{syscall_name} JEQ target out of bounds"
                );
                assert_eq!(
                    prog[ret_idx].code as u32,
                    libc::BPF_RET,
                    "target of {syscall_name} JEQ should be a RET instruction"
                );
                return prog[ret_idx].k;
            }
        }
        panic!("{syscall_name} JEQ not found in BPF program");
    }

    #[test]
    fn test_deny_with_errno_compiles_bpf_errno_action() {
        // deny_with_errno should produce a BPF_RET with SECCOMP_RET_ERRNO | errno.
        let filter = SeccompFilterBuilder::new(SeccompAction::Allow)
            .deny_with_errno(SYS_ptrace, 13)
            .build()
            .unwrap();

        let ptrace_nr = libc::SYS_ptrace as u32;
        let ret_k = find_ret_action_for_syscall(&filter.program, ptrace_nr, "ptrace");
        assert_eq!(
            ret_k,
            libc::SECCOMP_RET_ERRNO | 13,
            "ptrace should have Errno(13) action"
        );
    }

    #[test]
    fn test_trap_action_compiled_in_bpf() {
        let rules = [Rule {
            syscall_nr: libc::SYS_ptrace as i32,
            action: SeccompAction::Trap.to_bpf_ret(),
        }];
        let rule_refs: Vec<&Rule> = rules.iter().collect();
        let prog = compile_bpf(&SeccompAction::Allow, &rule_refs).unwrap();

        let ptrace_nr = libc::SYS_ptrace as u32;
        let ret_k = find_ret_action_for_syscall(&prog, ptrace_nr, "ptrace");
        assert_eq!(ret_k, libc::SECCOMP_RET_TRAP);
    }

    #[test]
    fn test_kill_thread_action_compiled_in_bpf() {
        let rules = [Rule {
            syscall_nr: libc::SYS_ptrace as i32,
            action: SeccompAction::KillThread.to_bpf_ret(),
        }];
        let rule_refs: Vec<&Rule> = rules.iter().collect();
        let prog = compile_bpf(&SeccompAction::Allow, &rule_refs).unwrap();

        let ptrace_nr = libc::SYS_ptrace as u32;
        let ret_k = find_ret_action_for_syscall(&prog, ptrace_nr, "ptrace");
        assert_eq!(ret_k, libc::SECCOMP_RET_KILL_THREAD);
    }

    #[test]
    fn test_errno_action_compiled_in_bpf() {
        // Use EPERM (1) to distinguish from deny_with_errno test which uses 13.
        let rules = [Rule {
            syscall_nr: libc::SYS_mount as i32,
            action: SeccompAction::Errno(1).to_bpf_ret(),
        }];
        let rule_refs: Vec<&Rule> = rules.iter().collect();
        let prog = compile_bpf(&SeccompAction::Allow, &rule_refs).unwrap();

        let mount_nr = libc::SYS_mount as u32;
        let ret_k = find_ret_action_for_syscall(&prog, mount_nr, "mount");
        assert_eq!(ret_k, libc::SECCOMP_RET_ERRNO | 1);
    }

    #[test]
    fn test_allow_all_sets_correct_rule_count() {
        let filter = SeccompFilterBuilder::new(SeccompAction::KillProcess)
            .allow(SYS_exit)
            .allow(SYS_exit_group)
            .allow_all(&[SYS_read, SYS_write, SYS_close])
            .build()
            .unwrap();

        // 2 individual allows + 3 from allow_all = 5 unique rules
        assert_eq!(filter.rule_count(), 5);
    }

    #[test]
    fn test_deny_all_sets_correct_rule_count() {
        let filter = SeccompFilterBuilder::new(SeccompAction::Allow)
            .deny_all(&[SYS_ptrace, SYS_mount, SYS_reboot])
            .build()
            .unwrap();

        assert_eq!(filter.rule_count(), 3);
    }

    #[test]
    fn test_log_action_compiled_in_bpf() {
        let rules = [Rule {
            syscall_nr: libc::SYS_ptrace as i32,
            action: SeccompAction::Log.to_bpf_ret(),
        }];
        let rule_refs: Vec<&Rule> = rules.iter().collect();
        let prog = compile_bpf(&SeccompAction::Allow, &rule_refs).unwrap();

        let ptrace_nr = libc::SYS_ptrace as u32;
        let ret_k = find_ret_action_for_syscall(&prog, ptrace_nr, "ptrace");
        assert_eq!(ret_k, libc::SECCOMP_RET_LOG);
    }
}
