//! Syscall number constants — transparent re-exports of `libc::SYS_*`.
//!
//! These are libc's own constants, re-exported so downstream callers can name
//! syscalls without depending on `libc`: reach them as
//! `libsandbox::seccomp::SYS_read` (or `libsandbox::seccomp::syscalls::SYS_read`).
//! Pass them to the [`SeccompFilterBuilder`](super::SeccompFilterBuilder) methods,
//! which take a [`SyscallNumber`].
//!
//! Because the constants are compile-time resolved, a typo is a **compile error**,
//! not a runtime failure:
//!
//! ```compile_fail
//! // `SYS_soket` does not exist — this must not compile.
//! use libsandbox::seccomp;
//! let _ = seccomp::SYS_soket;
//! ```
//!
//! The set is *curated*: it is the union of syscalls the crate's presets
//! reference plus commonly-needed extras. The x86-era legacy constants
//! (`open`/`stat`/`fork`/...) are re-exported only on x86/x86_64, where libc
//! defines them — they are absent on aarch64/asm-generic, so they are cfg-gated
//! to match. Add a constant by extending the relevant block below.

/// The type of a syscall number — libc's own type for the `SYS_*` constants.
///
/// This is a transparent alias (not a newtype): `libc::SYS_read` *is* a
/// `SyscallNumber` with no wrapping. Note the alias resolves to `libc::c_long`,
/// so that type may surface in compiler diagnostics; downstream still does not
/// need to *name* syscalls via libc — the re-exported `SYS_*` constants suffice.
pub type SyscallNumber = libc::c_long;

// Cross-arch syscalls — defined on every Linux arch libc targets.
pub use libc::{
    // --- Sockets ---
    SYS_accept,
    SYS_accept4,
    // --- Miscellaneous ---
    SYS_acct,
    SYS_bind,
    SYS_bpf,
    // --- Memory ---
    SYS_brk,
    // --- Dangerous (for deny lists) ---
    SYS_chroot,
    // --- Time ---
    SYS_clock_adjtime,
    SYS_clock_getres,
    SYS_clock_gettime,
    SYS_clock_nanosleep,
    // --- Process ---
    SYS_clone,
    SYS_clone3,
    // --- File I/O ---
    SYS_close,
    // --- User/namespace ---
    SYS_close_range,
    SYS_connect,
    SYS_copy_file_range,
    SYS_delete_module,
    SYS_dup,
    SYS_dup3,
    // --- I/O multiplexing ---
    SYS_epoll_create1,
    SYS_epoll_ctl,
    SYS_epoll_pwait,
    SYS_epoll_pwait2,
    // --- Eventfd / timerfd ---
    SYS_eventfd2,
    SYS_execve,
    SYS_execveat,
    SYS_exit,
    SYS_exit_group,
    SYS_faccessat,
    SYS_fchmod,
    SYS_fchmodat,
    SYS_fchown,
    SYS_fchownat,
    SYS_fcntl,
    SYS_fdatasync,
    SYS_finit_module,
    SYS_flock,
    SYS_fstat,
    SYS_fsync,
    SYS_ftruncate,
    // --- Futex ---
    SYS_futex,
    SYS_futex_waitv,
    SYS_get_robust_list,
    SYS_getcwd,
    SYS_getdents64,
    SYS_getegid,
    SYS_geteuid,
    SYS_getgid,
    SYS_getgroups,
    SYS_getpeername,
    SYS_getpid,
    SYS_getppid,
    SYS_getrandom,
    SYS_getresgid,
    SYS_getresuid,
    // --- Resource limits ---
    SYS_getrlimit,
    SYS_getrusage,
    SYS_getsockname,
    SYS_getsockopt,
    SYS_gettid,
    SYS_gettimeofday,
    SYS_getuid,
    SYS_init_module,
    // --- Inotify ---
    SYS_inotify_add_watch,
    SYS_inotify_init1,
    SYS_inotify_rm_watch,
    SYS_ioctl,
    SYS_kcmp,
    SYS_kexec_file_load,
    SYS_kexec_load,
    // --- Signals ---
    SYS_kill,
    SYS_landlock_add_rule,
    SYS_landlock_create_ruleset,
    SYS_landlock_restrict_self,
    SYS_linkat,
    SYS_listen,
    SYS_lseek,
    SYS_madvise,
    SYS_mincore,
    SYS_mkdirat,
    SYS_mmap,
    SYS_mount,
    SYS_mount_setattr,
    SYS_move_mount,
    SYS_mprotect,
    SYS_mremap,
    SYS_msync,
    SYS_munmap,
    SYS_nanosleep,
    SYS_newfstatat,
    SYS_open_by_handle_at,
    SYS_open_tree,
    SYS_openat,
    SYS_perf_event_open,
    SYS_personality,
    SYS_pidfd_open,
    SYS_pidfd_send_signal,
    // --- Pipes ---
    SYS_pipe2,
    SYS_pivot_root,
    SYS_ppoll,
    SYS_prctl,
    SYS_pread64,
    SYS_preadv,
    SYS_prlimit64,
    SYS_process_madvise,
    SYS_process_vm_readv,
    SYS_process_vm_writev,
    SYS_ptrace,
    SYS_pwrite64,
    SYS_pwritev,
    SYS_read,
    SYS_readlinkat,
    SYS_readv,
    SYS_reboot,
    SYS_recvfrom,
    SYS_recvmsg,
    SYS_renameat,
    SYS_renameat2,
    SYS_rseq,
    SYS_rt_sigaction,
    SYS_rt_sigpending,
    SYS_rt_sigprocmask,
    SYS_rt_sigqueueinfo,
    SYS_rt_sigreturn,
    SYS_rt_sigsuspend,
    SYS_rt_tgsigqueueinfo,
    // --- Scheduling ---
    SYS_sched_get_priority_max,
    SYS_sched_get_priority_min,
    SYS_sched_getaffinity,
    SYS_sched_setaffinity,
    SYS_sched_yield,
    SYS_sendmsg,
    SYS_sendto,
    SYS_set_robust_list,
    SYS_set_tid_address,
    SYS_setgroups,
    SYS_setns,
    SYS_setrlimit,
    SYS_setsockopt,
    SYS_shutdown,
    SYS_sigaltstack,
    // --- Signalfd ---
    SYS_signalfd4,
    SYS_socket,
    SYS_socketpair,
    SYS_splice,
    SYS_swapoff,
    SYS_swapon,
    SYS_sysinfo,
    SYS_syslog,
    SYS_tee,
    SYS_tgkill,
    SYS_timer_create,
    SYS_timer_delete,
    SYS_timer_gettime,
    SYS_timer_settime,
    SYS_timerfd_create,
    SYS_timerfd_gettime,
    SYS_timerfd_settime,
    SYS_tkill,
    SYS_truncate,
    SYS_umask,
    SYS_umount2,
    SYS_uname,
    SYS_unlinkat,
    SYS_unshare,
    SYS_userfaultfd,
    SYS_utimensat,
    SYS_vhangup,
    SYS_vmsplice,
    SYS_wait4,
    SYS_waitid,
    SYS_write,
    SYS_writev,
};

/// x86-era legacy syscalls — defined only on x86/x86_64, absent on aarch64.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use libc::{
    // --- File I/O legacy (aarch64 uses the *at / *64 variants) ---
    SYS_access,
    // --- x86-specific subsystems ---
    SYS_arch_prctl,
    // --- Filesystem legacy (aarch64 uses the *at variants) ---
    SYS_chmod,
    SYS_chown,
    SYS_dup2,
    // --- I/O multiplexing legacy (aarch64 uses ppoll / epoll_*1 / epoll_pwait) ---
    SYS_epoll_create,
    SYS_epoll_wait,
    SYS_eventfd,
    SYS_fadvise64,
    // --- Process legacy (aarch64 uses clone) ---
    SYS_fork,
    SYS_getdents,
    SYS_getpgrp,
    // --- Other legacy ---
    SYS_inotify_init,
    SYS_ioperm,
    SYS_iopl,
    SYS_lchown,
    SYS_link,
    SYS_lstat,
    SYS_mkdir,
    SYS_modify_ldt,
    SYS_nfsservctl,
    SYS_open,
    SYS_pipe,
    SYS_poll,
    SYS_readlink,
    SYS_rename,
    SYS_rmdir,
    SYS_select,
    SYS_signalfd,
    SYS_stat,
    // --- Time legacy (aarch64 uses clock_gettime) ---
    SYS_time,
    SYS_unlink,
    SYS_uselib,
    SYS_vfork,
};
