//! BPF compilation and kernel loading.

use crate::error::{ErrorKind, Result, SandboxError};

use super::{Rule, SeccompAction};

// ---------------------------------------------------------------------------
// Audit architecture constant — not exported by libc; defined per targeted arch.
// ---------------------------------------------------------------------------

/// The native architecture value in `seccomp_data.arch` (`AUDIT_ARCH_*`).
#[cfg(target_arch = "x86_64")]
pub(super) const AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
/// The native architecture value in `seccomp_data.arch` (`AUDIT_ARCH_*`).
#[cfg(target_arch = "aarch64")]
pub(super) const AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("seccomp: AUDIT_ARCH not defined for this target arch (add it above)");

// ---------------------------------------------------------------------------
// BPF compilation
// ---------------------------------------------------------------------------

/// Compile pre-sorted, pre-deduped rules into a classic BPF program.
///
/// Expects `rules` to already be sorted by syscall number with last-wins
/// deduplication applied (via [`dedup_rules`](super::builder::dedup_rules)).
///
/// Program structure:
/// ```text
/// [0]       BPF_LD  abs=4           load arch field
/// [1]       BPF_JEQ k=ARCH          arch check (jt=1 → skip kill, jf=0 → fall through)
/// [2]       BPF_RET KILL_PROCESS    arch mismatch → kill
/// [3]       BPF_LD  abs=0           load syscall number
/// [4..4+N-1]  sorted inorder jump table (one BPF_JEQ per rule, ascending order)
/// [4+N]     BPF_JA                  skip over rule RETs to default
/// [4+N+1..4+2N]  BPF_RET per rule  one return per rule (action from rule.action)
/// [4+2N]    BPF_RET default         no rule matched → default action
///
/// Total: 2N + 6 instructions (N rules), or 5 instructions (no rules).
/// ```
pub(super) fn compile_bpf(
    default_action: &SeccompAction,
    sorted: &[&Rule],
) -> Result<Vec<libc::sock_filter>> {
    let mut prog = Vec::new();

    let default_ret = default_action.to_bpf_ret();
    let kill_ret = SeccompAction::KillProcess.to_bpf_ret();

    // --- Header ---
    // [0] Load arch (seccomp_data.arch at offset 4)
    // SAFETY: BPF_STMT is an unsafe extern "C" fn that constructs a sock_filter
    // struct — no I/O, no side effects beyond struct initialization.
    prog.push(unsafe {
        libc::BPF_STMT(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            4, // offset of arch field
        )
    });

    // [1] Compare arch; if match → skip arch_mismatch (jt=1);
    //     if not match → fall through to arch_mismatch (jf=0).
    //     This layout keeps both jt and jf small (0 and 1), avoiding u8
    //     overflow for large programs.
    // SAFETY: BPF_JUMP is an unsafe extern "C" fn that constructs a sock_filter
    // struct — no I/O, no side effects beyond struct initialization.
    prog.push(unsafe {
        libc::BPF_JUMP(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            AUDIT_ARCH,
            1, // jt: skip arch_mismatch, continue to syscall load
            0, // jf: fall through to arch_mismatch kill
        )
    });

    // [2] Arch mismatch → kill process
    // SAFETY: BPF_STMT constructs a sock_filter struct — no side effects.
    prog.push(unsafe { libc::BPF_STMT(libc::BPF_RET as u16, kill_ret) });

    // [3] Load syscall number (seccomp_data.nr at offset 0)
    // SAFETY: BPF_STMT constructs a sock_filter struct — no side effects.
    prog.push(unsafe {
        libc::BPF_STMT(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            0, // offset of nr field
        )
    });

    // [4..] Sorted jump table + rule returns + default
    if !sorted.is_empty() {
        emit_sorted_jump_table(&mut prog, sorted, default_ret)?;
    } else {
        // No rules: only the default action is needed
        // SAFETY: BPF_STMT constructs a sock_filter struct — no side effects.
        prog.push(unsafe { libc::BPF_STMT(libc::BPF_RET as u16, default_ret) });
    }

    // Validate BPF program length (kernel limit: 4096 instructions).
    if prog.len() > libc::BPF_MAXINSNS as usize {
        return Err(SandboxError::new(
            ErrorKind::Seccomp,
            format!(
                "filter build failed: BPF program too large: {} instructions (kernel limit: {})",
                prog.len(),
                libc::BPF_MAXINSNS
            ),
        ));
    }

    Ok(prog)
}

/// Emit a sorted inorder jump table of `BPF_JEQ` instructions over rules.
///
/// Rules are emitted in ascending syscall-number order via inorder traversal
/// of a balanced BST layout. Each node is a `BPF_JEQ` exact-match check.
/// When a syscall number matches, the jump lands on the corresponding
/// `BPF_RET` in the return table. When no match is found after scanning all
/// nodes, the fall-through lands on an unconditional `BPF_JA` that skips to
/// the default action.
///
/// **Note**: The inorder layout means non-matching syscalls scan every node
/// linearly (O(N)). A true binary search using `BPF_JGE` would be O(log N)
/// but is deferred as a future optimization.
fn emit_sorted_jump_table(
    prog: &mut Vec<libc::sock_filter>,
    rules: &[&Rule],
    default_ret: u32,
) -> Result<()> {
    let n = rules.len();

    // Record where the jump table starts.
    let table_start = prog.len();

    // Emit the sorted jump table recursively. The balanced BST is laid out so
    // that the "left" branch falls through to the next instruction and the
    // "right" branch is emitted after the current node. Each leaf is a BPF_RET.
    emit_table_node(prog, rules, 0, n);

    // After the jump table, emit an unconditional jump over the rule RETs
    // to the default action. This ensures that when no JEQ matches, we don't
    // fall through into the first rule RET (which might be a Kill action).
    // BPF_JA: BPF_JMP | 0x00, k = jump offset (number of instructions to skip).
    // Placeholder k — will be patched once we know the layout.
    let ja_idx = prog.len();
    // SAFETY: BPF_STMT constructs a sock_filter struct — no side effects.
    prog.push(unsafe { libc::BPF_STMT(libc::BPF_JMP as u16, 0) });

    // Now emit all the BPF_RET instructions for each rule.
    let ret_start = prog.len();
    for rule in rules {
        // SAFETY: BPF_STMT constructs a sock_filter struct — no side effects.
        prog.push(unsafe { libc::BPF_STMT(libc::BPF_RET as u16, rule.action) });
    }
    // Default action (for jump table miss — reached via the JA above).
    let default_idx = prog.len();
    // SAFETY: BPF_STMT constructs a sock_filter struct — no side effects.
    prog.push(unsafe { libc::BPF_STMT(libc::BPF_RET as u16, default_ret) });

    // Patch the unconditional jump: skip over all rule RETs.
    prog[ja_idx].k = (default_idx - ja_idx - 1) as u32;

    // Now patch the jump table: each node emitted a BPF_JEQ with a
    // placeholder jt value. Calculate the actual offset from each jump
    // to its corresponding RET instruction.
    patch_jump_offsets(prog, table_start, ret_start, rules)?;

    Ok(())
}

/// Recursively emit sorted jump table nodes for exact-match syscall lookups.
///
/// Emits an inorder traversal of a balanced BST layout using `BPF_JEQ` instructions.
/// The `jt` offset (matching) is patched later by `patch_jump_offsets`; the
/// `jf` offset (non-matching) is 0 (fall through to the next node).
fn emit_table_node(prog: &mut Vec<libc::sock_filter>, rules: &[&Rule], lo: usize, hi: usize) {
    if lo >= hi {
        return;
    }
    let mid = lo + (hi - lo) / 2;
    let nr = rules[mid].syscall_nr as u32;

    // Left subtree (emit first, falls through)
    emit_table_node(prog, rules, lo, mid);

    // This node: JEQ check for exact match at rules[mid].
    // jt = offset to the RET for this rule (will be patched).
    // jf = fall through to right subtree.
    // SAFETY: BPF_JUMP constructs a sock_filter struct — no side effects.
    prog.push(unsafe {
        libc::BPF_JUMP(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            nr,
            0, // jt: placeholder — will be patched to RET
            0, // jf: fall through to right subtree
        )
    });

    // Right subtree (emit after this node)
    emit_table_node(prog, rules, mid + 1, hi);
}

/// Patch the sorted jump table with correct jump offsets.
///
/// After the table is emitted, we know the absolute positions of both
/// the jump instructions and the RET instructions. We walk the table again and
/// fill in the correct relative offsets.
///
/// Returns `Err` if any jump offset exceeds the BPF `u8` limit (255).
fn patch_jump_offsets(
    prog: &mut Vec<libc::sock_filter>,
    table_start: usize,
    ret_start: usize,
    rules: &[&Rule],
) -> Result<()> {
    let n = rules.len();
    let mut node_idx = 0;
    patch_jump_node(prog, table_start, ret_start, rules, 0, n, &mut node_idx)
}

fn patch_jump_node(
    prog: &mut Vec<libc::sock_filter>,
    table_start: usize,
    ret_start: usize,
    rules: &[&Rule],
    lo: usize,
    hi: usize,
    node_idx: &mut usize,
) -> Result<()> {
    if lo >= hi {
        return Ok(());
    }
    let mid = lo + (hi - lo) / 2;

    // Left subtree
    patch_jump_node(prog, table_start, ret_start, rules, lo, mid, node_idx)?;

    // This node's jump instruction
    let jump_abs = table_start + *node_idx;
    let ret_abs = ret_start + mid; // RET for rules[mid]

    // jt = forward offset from (jump+1) to ret_abs
    let jt = ret_abs - jump_abs - 1;
    if jt > 255 {
        return Err(SandboxError::new(
            ErrorKind::Seccomp,
            format!(
                "filter build failed: BPF jump offset overflow: {jt} > 255 ({} rules) — reduce the number of syscall rules",
                rules.len()
            ),
        ));
    }
    prog[jump_abs].jt = jt as u8;

    *node_idx += 1;

    // Right subtree
    patch_jump_node(prog, table_start, ret_start, rules, mid + 1, hi, node_idx)
}

// ---------------------------------------------------------------------------
// Kernel loading
// ---------------------------------------------------------------------------

/// Set `PR_SET_NO_NEW_PRIVS` — required before installing a seccomp filter.
pub(super) fn set_no_new_privs() -> Result<()> {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) is safe — all arguments
    // are constants, no user pointers are dereferenced, and the kernel handles
    // the request atomically.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(SandboxError::new(
            ErrorKind::Seccomp,
            format!(
                "failed to load security filter: {}",
                "Failed to set PR_SET_NO_NEW_PRIVS",
            ),
        ));
    }
    Ok(())
}

/// Load a compiled BPF program into the kernel.
///
/// Tries `seccomp(SECCOMP_SET_MODE_FILTER)` first; falls back to
/// `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)` on `ENOSYS`.
pub(super) fn load_filter(program: &[libc::sock_filter]) -> Result<()> {
    // compile_bpf enforces the BPF_MAXINSNS (4096) limit, which fits in u16.
    // This assertion documents the invariant and catches misuse in debug
    // builds if load_filter is ever called outside compile_bpf's pipeline.
    debug_assert!(
        program.len() <= u16::MAX as usize,
        "BPF program length {} exceeds u16::MAX — compile_bpf should prevent this",
        program.len()
    );

    let fprog = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_ptr() as *mut libc::sock_filter,
    };

    // Try seccomp(2) syscall first
    // SAFETY: seccomp(2) via libc::syscall with SECCOMP_SET_MODE_FILTER, flag 0,
    // and a valid sock_fprog pointer. The fprog struct is stack-local and outlives
    // the call. The kernel copies the BPF program during the syscall and does not
    // retain the pointer after returning.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &fprog as *const libc::sock_fprog,
        )
    };

    if ret == 0 {
        return Ok(());
    }

    // SAFETY: __errno_location() returns a pointer to thread-local errno. Reading
    // the value is safe immediately after a syscall returns an error; no other
    // thread can modify this thread's errno between the syscall return and this read.
    let errno = unsafe { *libc::__errno_location() };
    if errno == libc::ENOSYS {
        // Kernel too old for seccomp(2) — fall back to prctl
        // SAFETY: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0)
        // passes a valid sock_fprog pointer. The kernel copies the BPF program
        // during the call and does not retain the pointer.
        let ret = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &fprog as *const libc::sock_fprog,
                0,
                0,
            )
        };
        if ret != 0 {
            return Err(SandboxError::new(
                ErrorKind::Seccomp,
                format!(
                    "failed to load security filter: prctl(PR_SET_SECCOMP) failed: errno {}", // SAFETY: same rationale as the errno read above — thread-local,
                    // read immediately after syscall error.
                    unsafe { *libc::__errno_location() }
                ),
            ));
        }
        return Ok(());
    }

    Err(SandboxError::new(ErrorKind::Seccomp, format!("failed to load security filter: seccomp(SECCOMP_SET_MODE_FILTER) failed: errno {errno}")))
}
