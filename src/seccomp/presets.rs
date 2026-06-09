//! Preset syscall lists for built-in seccomp profiles.

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
    "access",
    "faccessat",
    "readlink",
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
    "fork",
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
    "getpgrp",
    // Thread/process setup
    "arch_prctl",
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
    "pipe",
    "pipe2",
    // Descriptors
    "dup",
    "dup2",
    "dup3",
    "fcntl",
    // Miscellaneous
    "ioctl",
];

/// Syscalls allowed in standard mode.
pub(super) const STANDARD_SYSCALLS: &[&str] = &[
    // File operations
    "read",
    "write",
    "open",
    "openat",
    "close",
    "stat",
    "fstat",
    "newfstatat",
    "lstat",
    "access",
    "faccessat",
    "readlink",
    "readlinkat",
    "getcwd",
    "dup",
    "dup2",
    "dup3",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "truncate",
    "ftruncate",
    "getdents",
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
    "fork",
    "vfork",
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
    "select",
    "poll",
    "ppoll",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    // Pipes
    "pipe",
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
    "arch_prctl",
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
    "fadvise64",
    "umask",
    // User/group identity
    "getuid",
    "getgid",
    "geteuid",
    "getegid",
    "getgroups",
    "getresuid",
    "getresgid",
    "getpgrp",
];

/// Extra syscalls allowed in permissive mode (on top of STANDARD_SYSCALLS).
pub(super) const PERMISSIVE_EXTRA_SYSCALLS: &[&str] = &[
    // More file operations
    "link",
    "linkat",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "mkdir",
    "mkdirat",
    "rmdir",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "lchown",
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
    "eventfd",
    "eventfd2",
    "timerfd_create",
    "timerfd_settime",
    "timerfd_gettime",
    "timer_create",
    "timer_settime",
    "timer_gettime",
    "timer_delete",
    // Time
    "time",
    "clock_adjtime",
    // Signalfd
    "signalfd",
    "signalfd4",
    // Inotify
    "inotify_init",
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

/// Syscalls blocked in all modes.
pub(super) const BLOCKED_SYSCALLS: &[&str] = &[
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
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
    "iopl",            // I/O port access — ring 0 escalation
    "ioperm",          // I/O port permissions — ring 0 escalation
    "acct",            // process accounting — arbitrary filesystem write
    "vhangup",         // virtual terminal hangup — DoS
    "personality",     // execution domain — ABI manipulation
    "modify_ldt",      // LDT manipulation — signal handler bypass
    // New mount API — defense-in-depth for dynamic mount operations.
    // These are blocked in the child so the sandboxed process cannot
    // interfere with dynamic mounts managed by the parent.
    "open_tree",     // create detached mount (kernel 5.2+)
    "move_mount",    // attach mount object (kernel 5.2+)
    "mount_setattr", // change mount attributes (kernel 5.12+)
];
