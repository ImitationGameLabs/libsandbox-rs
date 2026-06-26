//! Preset syscall lists for built-in seccomp profiles.
//!
//! Each preset is split into a cross-arch **base** (`*_SYSCALLS`) plus a
//! **x86-only companion** (`*_X86_ONLY`) holding legacy syscalls absent on
//! aarch64 (open/stat/fork/select/poll/...). The companion is `&[]` on non-x86
//! arches so the builder can chain it unconditionally — the same idiom as
//! [`LANDLOCK_CHILD_SYSCALLS`] below. On x86_64 the union `base ∪ companion`
//! is byte-identical to the historical single-list preset.
//!
//! The elements are `SYS_*` constants (re-exported via
//! [`super::syscalls`]), so the lists are checked at compile time — and a
//! constant dropped from that re-export is a compile error here too.

use super::syscalls::*;

/// Essential syscalls for strict mode — the minimum set needed for basic
/// command execution (dynamic linking, I/O, process spawning).
///
/// **Note**: `ioctl` is included for terminal and fd operations, which
/// implicitly allows `TIOCSTI`. Sandboxes sharing a terminal with the host
/// should be aware of this escape vector.
pub(super) const STRICT_SYSCALLS: &[SyscallNumber] = &[
    // Core I/O
    SYS_read,
    SYS_write,
    SYS_readv,
    SYS_writev,
    SYS_close,
    SYS_fstat,
    SYS_lseek,
    SYS_pread64,
    // File access (dynamic linker needs these)
    SYS_openat,
    SYS_faccessat,
    SYS_readlinkat,
    SYS_getdents64,
    SYS_newfstatat,
    // Memory management (dynamic linker, heap)
    SYS_brk,
    SYS_mmap,
    SYS_munmap,
    SYS_mprotect,
    SYS_mremap,
    SYS_madvise,
    // Process lifecycle
    SYS_execve,
    SYS_exit,
    SYS_exit_group,
    SYS_clone,
    SYS_clone3,
    SYS_wait4,
    // Identity queries
    SYS_getpid,
    SYS_getppid,
    SYS_getuid,
    SYS_getgid,
    SYS_geteuid,
    SYS_getegid,
    SYS_getresuid,
    SYS_getresgid,
    // Thread/process setup
    SYS_set_tid_address,
    SYS_set_robust_list,
    SYS_getrandom,
    SYS_prctl,
    SYS_rseq,
    SYS_uname,
    // Time
    SYS_clock_gettime,
    // Synchronization
    SYS_futex,
    SYS_sched_yield,
    // Resource limits
    SYS_prlimit64,
    // Signals
    SYS_rt_sigaction,
    SYS_rt_sigprocmask,
    SYS_rt_sigreturn,
    SYS_sigaltstack,
    // Pipe (for sh -c pipes)
    SYS_pipe2,
    // Descriptors
    SYS_dup,
    SYS_dup3,
    SYS_fcntl,
    // Miscellaneous
    SYS_ioctl,
];

/// x86-era legacy syscalls in the strict preset — absent on aarch64.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(super) const STRICT_SYSCALLS_X86_ONLY: &[SyscallNumber] = &[
    SYS_access,
    SYS_readlink,
    SYS_pipe,
    SYS_dup2,
    SYS_fork,
    SYS_getpgrp,
    SYS_arch_prctl,
];
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(super) const STRICT_SYSCALLS_X86_ONLY: &[SyscallNumber] = &[];

/// Syscalls allowed in standard mode.
pub(super) const STANDARD_SYSCALLS: &[SyscallNumber] = &[
    // File operations (cross-arch — open/stat/access/dup2/etc. are x86-only, in
    // STANDARD_SYSCALLS_X86_ONLY; aarch64 uses the *at / dup3 variants here).
    SYS_read,
    SYS_write,
    SYS_openat,
    SYS_close,
    SYS_fstat,
    SYS_newfstatat,
    SYS_faccessat,
    SYS_readlinkat,
    SYS_getcwd,
    SYS_dup,
    SYS_dup3,
    SYS_fcntl,
    SYS_flock,
    SYS_fsync,
    SYS_fdatasync,
    SYS_truncate,
    SYS_ftruncate,
    SYS_getdents64,
    SYS_lseek,
    // Memory
    SYS_mmap,
    SYS_munmap,
    SYS_mprotect,
    SYS_mremap,
    SYS_brk,
    SYS_madvise,
    // Process
    SYS_clone,
    SYS_clone3,
    SYS_execve,
    SYS_wait4,
    SYS_waitid,
    SYS_getpid,
    SYS_getppid,
    SYS_gettid,
    SYS_exit,
    SYS_exit_group,
    // Time
    SYS_clock_gettime,
    SYS_clock_getres,
    SYS_clock_nanosleep,
    SYS_nanosleep,
    SYS_gettimeofday,
    // Resource limits
    SYS_getrlimit,
    SYS_setrlimit,
    SYS_prlimit64,
    SYS_getrusage,
    // Signals
    SYS_rt_sigaction,
    SYS_rt_sigprocmask,
    SYS_rt_sigreturn,
    SYS_sigaltstack,
    SYS_rt_sigpending,
    SYS_rt_sigsuspend,
    SYS_kill,
    SYS_tgkill,
    // I/O
    SYS_readv,
    SYS_writev,
    SYS_pread64,
    SYS_pwrite64,
    SYS_ppoll,
    SYS_epoll_create1,
    SYS_epoll_ctl,
    SYS_epoll_pwait,
    // Pipes
    SYS_pipe2,
    // Sockets
    SYS_socket,
    SYS_connect,
    SYS_accept,
    SYS_accept4,
    SYS_sendto,
    SYS_recvfrom,
    SYS_sendmsg,
    SYS_recvmsg,
    SYS_bind,
    SYS_listen,
    SYS_getsockname,
    SYS_getpeername,
    SYS_setsockopt,
    SYS_getsockopt,
    SYS_socketpair,
    SYS_shutdown,
    // Futex / scheduling
    SYS_futex,
    SYS_sched_yield,
    // Miscellaneous
    SYS_set_tid_address,
    SYS_set_robust_list,
    SYS_get_robust_list,
    SYS_close_range,
    SYS_getrandom,
    SYS_prctl,
    SYS_uname,
    SYS_sysinfo,
    SYS_ioctl,
    SYS_rseq,
    SYS_splice,
    SYS_copy_file_range,
    SYS_umask,
    // User/group identity
    SYS_getuid,
    SYS_getgid,
    SYS_geteuid,
    SYS_getegid,
    SYS_getgroups,
    SYS_getresuid,
    SYS_getresgid,
];

/// x86-era legacy syscalls in the standard preset — absent on aarch64.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(super) const STANDARD_SYSCALLS_X86_ONLY: &[SyscallNumber] = &[
    SYS_open,
    SYS_stat,
    SYS_lstat,
    SYS_access,
    SYS_readlink,
    SYS_getdents,
    SYS_dup2,
    SYS_fork,
    SYS_vfork,
    SYS_getpgrp,
    SYS_select,
    SYS_poll,
    SYS_epoll_create,
    SYS_epoll_wait,
    SYS_pipe,
    SYS_arch_prctl,
    SYS_fadvise64,
];
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(super) const STANDARD_SYSCALLS_X86_ONLY: &[SyscallNumber] = &[];

/// Extra syscalls allowed in permissive mode (on top of STANDARD_SYSCALLS).
pub(super) const PERMISSIVE_EXTRA_SYSCALLS: &[SyscallNumber] = &[
    // More file operations (cross-arch — link/unlink/rename/mkdir/chmod/chown
    // legacy equivalents are x86-only, in PERMISSIVE_EXTRA_SYSCALLS_X86_ONLY).
    SYS_linkat,
    SYS_unlinkat,
    SYS_renameat,
    SYS_renameat2,
    SYS_mkdirat,
    SYS_fchmod,
    SYS_fchmodat,
    SYS_fchown,
    SYS_fchownat,
    SYS_utimensat,
    // More process
    SYS_execveat,
    SYS_pidfd_open,
    SYS_pidfd_send_signal,
    // More memory
    SYS_msync,
    SYS_mincore,
    // More I/O
    SYS_preadv,
    SYS_pwritev,
    SYS_tee,
    SYS_vmsplice,
    SYS_process_madvise,
    // Eventfd / timerfd
    SYS_eventfd2,
    SYS_timerfd_create,
    SYS_timerfd_settime,
    SYS_timerfd_gettime,
    SYS_timer_create,
    SYS_timer_settime,
    SYS_timer_gettime,
    SYS_timer_delete,
    // Time
    SYS_clock_adjtime,
    // Signalfd
    SYS_signalfd4,
    // Inotify
    SYS_inotify_init1,
    SYS_inotify_add_watch,
    SYS_inotify_rm_watch,
    // Scheduling
    SYS_sched_getaffinity,
    SYS_sched_setaffinity,
    SYS_sched_get_priority_max,
    SYS_sched_get_priority_min,
    // Misc
    SYS_syslog,
    SYS_futex_waitv,
    // User/namespace
    SYS_setgroups,
    SYS_epoll_pwait2,
    // Landlock (modern sandboxing)
    SYS_landlock_create_ruleset,
    SYS_landlock_add_rule,
    SYS_landlock_restrict_self,
];

/// x86-era legacy syscalls in the permissive-extras set — absent on aarch64.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(super) const PERMISSIVE_EXTRA_SYSCALLS_X86_ONLY: &[SyscallNumber] = &[
    SYS_link,
    SYS_unlink,
    SYS_rename,
    SYS_mkdir,
    SYS_rmdir,
    SYS_chmod,
    SYS_chown,
    SYS_lchown,
    SYS_time,
    SYS_eventfd,
    SYS_inotify_init,
    SYS_signalfd,
];
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(super) const PERMISSIVE_EXTRA_SYSCALLS_X86_ONLY: &[SyscallNumber] = &[];

/// Syscalls blocked in all modes.
pub(super) const BLOCKED_SYSCALLS: &[SyscallNumber] = &[
    SYS_ptrace,
    SYS_kcmp, // cross-process memory comparison — cross-agent info leak side-channel
    SYS_process_vm_readv,
    SYS_process_vm_writev,
    SYS_open_by_handle_at, // fd-handle open bypasses path resolution — chroot break-out
    SYS_kexec_load,
    SYS_kexec_file_load,
    SYS_init_module,
    SYS_finit_module,
    SYS_delete_module,
    SYS_reboot,
    SYS_swapon,
    SYS_swapoff,
    SYS_mount,
    SYS_umount2,
    SYS_pivot_root,
    SYS_chroot,
    SYS_setns,
    SYS_unshare,
    SYS_userfaultfd,
    SYS_bpf,             // eBPF subsystem — can bypass seccomp on older kernels
    SYS_perf_event_open, // performance counters — info leak / side-channel
    SYS_acct,            // process accounting — arbitrary filesystem write
    SYS_vhangup,         // virtual terminal hangup — DoS
    SYS_personality,     // execution domain — ABI manipulation
    // New mount API — defense-in-depth for dynamic mount operations.
    // These are blocked in the child so the sandboxed process cannot
    // interfere with dynamic mounts managed by the parent.
    SYS_open_tree,     // create detached mount (kernel 5.2+)
    SYS_move_mount,    // attach mount object (kernel 5.2+)
    SYS_mount_setattr, // change mount attributes (kernel 5.12+)
];

/// x86-only syscalls blocked in all modes — absent on aarch64.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(super) const BLOCKED_SYSCALLS_X86_ONLY: &[SyscallNumber] = &[
    SYS_iopl,       // I/O port access — ring 0 escalation
    SYS_ioperm,     // I/O port permissions — ring 0 escalation
    SYS_modify_ldt, // LDT manipulation — signal handler bypass
];
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(super) const BLOCKED_SYSCALLS_X86_ONLY: &[SyscallNumber] = &[];

/// Syscalls a sandboxed child needs to enter a landlock domain.
///
/// The landlock ruleset is built parent-side (in `prepare_landlock`), so the child only
/// issues `landlock_restrict_self` — and it does so from the `ChildSetup` hook, **after**
/// seccomp is installed. For `Standard`/`Strict` (default-deny) profiles to compose with
/// landlock, this syscall must be in their allowlists, or the child is killed the instant
/// the hook fires. It is therefore merged into both presets (see `builder.rs`).
///
/// Empty when the `landlock` feature is off, so non-landlock builds produce byte-identical
/// BPF programs.
#[cfg(feature = "landlock")]
pub(super) const LANDLOCK_CHILD_SYSCALLS: &[SyscallNumber] = &[SYS_landlock_restrict_self];
#[cfg(not(feature = "landlock"))]
pub(super) const LANDLOCK_CHILD_SYSCALLS: &[SyscallNumber] = &[];
