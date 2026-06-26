//! Preset syscall lists for built-in seccomp profiles.
//!
//! Each preset is split into a cross-arch **base** (`*_SYSCALLS`) plus a
//! **x86-only companion** (`*_X86_ONLY`) holding legacy syscalls absent on
//! aarch64 (open/stat/fork/select/poll/...). The companion is `&[]` on non-x86
//! arches so the builder can chain it unconditionally — the same idiom as
//! [`LANDLOCK_CHILD_SYSCALLS`] below. On x86_64 the union `base ∪ companion`
//! is byte-identical to the historical single-list preset.

/// Essential syscalls for strict mode — the minimum set needed for basic
/// command execution (dynamic linking, I/O, process spawning).
///
/// **Note**: `ioctl` is included for terminal and fd operations, which
/// implicitly allows `TIOCSTI`. Sandboxes sharing a terminal with the host
/// should be aware of this escape vector.
pub(super) const STRICT_SYSCALLS: &[&str] = &[
    // Core I/O
    "read",
    "write",
    "readv",
    "writev",
    "close",
    "fstat",
    "lseek",
    "pread64",
    // File access (dynamic linker needs these)
    "openat",
    "faccessat",
    "readlinkat",
    "getdents64",
    "newfstatat",
    // Memory management (dynamic linker, heap)
    "brk",
    "mmap",
    "munmap",
    "mprotect",
    "mremap",
    "madvise",
    // Process lifecycle
    "execve",
    "exit",
    "exit_group",
    "clone",
    "clone3",
    "wait4",
    // Identity queries
    "getpid",
    "getppid",
    "getuid",
    "getgid",
    "geteuid",
    "getegid",
    "getresuid",
    "getresgid",
    // Thread/process setup
    "set_tid_address",
    "set_robust_list",
    "getrandom",
    "prctl",
    "rseq",
    "uname",
    // Time
    "clock_gettime",
    // Synchronization
    "futex",
    "sched_yield",
    // Resource limits
    "prlimit64",
    // Signals
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    // Pipe (for sh -c pipes)
    "pipe2",
    // Descriptors
    "dup",
    "dup3",
    "fcntl",
    // Miscellaneous
    "ioctl",
];

/// x86-era legacy syscalls in the strict preset — absent on aarch64.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(super) const STRICT_SYSCALLS_X86_ONLY: &[&str] =
    &["access", "readlink", "pipe", "dup2", "fork", "getpgrp", "arch_prctl"];
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(super) const STRICT_SYSCALLS_X86_ONLY: &[&str] = &[];

/// Syscalls allowed in standard mode.
pub(super) const STANDARD_SYSCALLS: &[&str] = &[
    // File operations (cross-arch — open/stat/access/dup2/etc. are x86-only, in
    // STANDARD_SYSCALLS_X86_ONLY; aarch64 uses the *at / dup3 variants here).
    "read",
    "write",
    "openat",
    "close",
    "fstat",
    "newfstatat",
    "faccessat",
    "readlinkat",
    "getcwd",
    "dup",
    "dup3",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "truncate",
    "ftruncate",
    "getdents64",
    "lseek",
    // Memory
    "mmap",
    "munmap",
    "mprotect",
    "mremap",
    "brk",
    "madvise",
    // Process
    "clone",
    "clone3",
    "execve",
    "wait4",
    "waitid",
    "getpid",
    "getppid",
    "gettid",
    "exit",
    "exit_group",
    // Time
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "nanosleep",
    "gettimeofday",
    // Resource limits
    "getrlimit",
    "setrlimit",
    "prlimit64",
    "getrusage",
    // Signals
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    "rt_sigpending",
    "rt_sigsuspend",
    "kill",
    "tgkill",
    // I/O
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "ppoll",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    // Pipes
    "pipe2",
    // Sockets
    "socket",
    "connect",
    "accept",
    "accept4",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "bind",
    "listen",
    "getsockname",
    "getpeername",
    "setsockopt",
    "getsockopt",
    "socketpair",
    "shutdown",
    // Futex / scheduling
    "futex",
    "sched_yield",
    // Miscellaneous
    "set_tid_address",
    "set_robust_list",
    "get_robust_list",
    "close_range",
    "getrandom",
    "prctl",
    "uname",
    "sysinfo",
    "ioctl",
    "rseq",
    "splice",
    "copy_file_range",
    "umask",
    // User/group identity
    "getuid",
    "getgid",
    "geteuid",
    "getegid",
    "getgroups",
    "getresuid",
    "getresgid",
];

/// x86-era legacy syscalls in the standard preset — absent on aarch64.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(super) const STANDARD_SYSCALLS_X86_ONLY: &[&str] = &[
    "open",
    "stat",
    "lstat",
    "access",
    "readlink",
    "getdents",
    "dup2",
    "fork",
    "vfork",
    "getpgrp",
    "select",
    "poll",
    "epoll_create",
    "epoll_wait",
    "pipe",
    "arch_prctl",
    "fadvise64",
];
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(super) const STANDARD_SYSCALLS_X86_ONLY: &[&str] = &[];

/// Extra syscalls allowed in permissive mode (on top of STANDARD_SYSCALLS).
pub(super) const PERMISSIVE_EXTRA_SYSCALLS: &[&str] = &[
    // More file operations (cross-arch — link/unlink/rename/mkdir/chmod/chown
    // legacy equivalents are x86-only, in PERMISSIVE_EXTRA_SYSCALLS_X86_ONLY).
    "linkat",
    "unlinkat",
    "renameat",
    "renameat2",
    "mkdirat",
    "fchmod",
    "fchmodat",
    "fchown",
    "fchownat",
    "utimensat",
    // More process
    "execveat",
    "pidfd_open",
    "pidfd_send_signal",
    // More memory
    "msync",
    "mincore",
    // More I/O
    "preadv",
    "pwritev",
    "tee",
    "vmsplice",
    "process_madvise",
    // Eventfd / timerfd
    "eventfd2",
    "timerfd_create",
    "timerfd_settime",
    "timerfd_gettime",
    "timer_create",
    "timer_settime",
    "timer_gettime",
    "timer_delete",
    // Time
    "clock_adjtime",
    // Signalfd
    "signalfd4",
    // Inotify
    "inotify_init1",
    "inotify_add_watch",
    "inotify_rm_watch",
    // Scheduling
    "sched_getaffinity",
    "sched_setaffinity",
    "sched_get_priority_max",
    "sched_get_priority_min",
    // Misc
    "syslog",
    "futex_waitv",
    // User/namespace
    "setgroups",
    "epoll_pwait2",
    // Landlock (modern sandboxing)
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
];

/// x86-era legacy syscalls in the permissive-extras set — absent on aarch64.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(super) const PERMISSIVE_EXTRA_SYSCALLS_X86_ONLY: &[&str] = &[
    "link", "unlink", "rename", "mkdir", "rmdir", "chmod", "chown", "lchown", "time", "eventfd",
    "inotify_init", "signalfd",
];
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(super) const PERMISSIVE_EXTRA_SYSCALLS_X86_ONLY: &[&str] = &[];

/// Syscalls blocked in all modes.
pub(super) const BLOCKED_SYSCALLS: &[&str] = &[
    "ptrace",
    "kcmp", // cross-process memory comparison — cross-agent info leak side-channel
    "process_vm_readv",
    "process_vm_writev",
    "open_by_handle_at", // fd-handle open bypasses path resolution — chroot break-out
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "reboot",
    "swapon",
    "swapoff",
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "setns",
    "unshare",
    "userfaultfd",
    "bpf",             // eBPF subsystem — can bypass seccomp on older kernels
    "perf_event_open", // performance counters — info leak / side-channel
    "acct",            // process accounting — arbitrary filesystem write
    "vhangup",         // virtual terminal hangup — DoS
    "personality",     // execution domain — ABI manipulation
    // New mount API — defense-in-depth for dynamic mount operations.
    // These are blocked in the child so the sandboxed process cannot
    // interfere with dynamic mounts managed by the parent.
    "open_tree",     // create detached mount (kernel 5.2+)
    "move_mount",    // attach mount object (kernel 5.2+)
    "mount_setattr", // change mount attributes (kernel 5.12+)
];

/// x86-only syscalls blocked in all modes — absent on aarch64.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(super) const BLOCKED_SYSCALLS_X86_ONLY: &[&str] = &[
    "iopl",       // I/O port access — ring 0 escalation
    "ioperm",     // I/O port permissions — ring 0 escalation
    "modify_ldt", // LDT manipulation — signal handler bypass
];
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(super) const BLOCKED_SYSCALLS_X86_ONLY: &[&str] = &[];

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
pub(super) const LANDLOCK_CHILD_SYSCALLS: &[&str] = &["landlock_restrict_self"];
#[cfg(not(feature = "landlock"))]
pub(super) const LANDLOCK_CHILD_SYSCALLS: &[&str] = &[];
