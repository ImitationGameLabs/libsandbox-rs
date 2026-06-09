//! Syscall name → number mapping (x86_64).

use crate::error::{Result, SandboxError};

/// Map a syscall name to its number on x86_64.
///
/// Only covers syscalls used by the presets plus commonly-needed extras.
/// Returns `Err` for unknown names.
#[cfg(target_arch = "x86_64")]
pub(super) fn syscall_number(name: &str) -> Result<i32> {
    Ok(match name {
        // --- File I/O ---
        "read" => libc::SYS_read,
        "write" => libc::SYS_write,
        "open" => libc::SYS_open,
        "openat" => libc::SYS_openat,
        "close" => libc::SYS_close,
        "stat" => libc::SYS_stat,
        "fstat" => libc::SYS_fstat,
        "newfstatat" => libc::SYS_newfstatat,
        "lstat" => libc::SYS_lstat,
        "access" => libc::SYS_access,
        "faccessat" => libc::SYS_faccessat,
        "readlink" => libc::SYS_readlink,
        "readlinkat" => libc::SYS_readlinkat,
        "getcwd" => libc::SYS_getcwd,
        "dup" => libc::SYS_dup,
        "dup2" => libc::SYS_dup2,
        "dup3" => libc::SYS_dup3,
        "fcntl" => libc::SYS_fcntl,
        "flock" => libc::SYS_flock,
        "fsync" => libc::SYS_fsync,
        "fdatasync" => libc::SYS_fdatasync,
        "truncate" => libc::SYS_truncate,
        "ftruncate" => libc::SYS_ftruncate,
        "getdents" => libc::SYS_getdents,
        "getdents64" => libc::SYS_getdents64,
        "lseek" => libc::SYS_lseek,
        "pread64" => libc::SYS_pread64,
        "pwrite64" => libc::SYS_pwrite64,
        "link" => libc::SYS_link,
        "linkat" => libc::SYS_linkat,
        "unlink" => libc::SYS_unlink,
        "unlinkat" => libc::SYS_unlinkat,
        "rename" => libc::SYS_rename,
        "renameat" => libc::SYS_renameat,
        "renameat2" => libc::SYS_renameat2,
        "mkdir" => libc::SYS_mkdir,
        "mkdirat" => libc::SYS_mkdirat,
        "rmdir" => libc::SYS_rmdir,
        "chmod" => libc::SYS_chmod,
        "fchmod" => libc::SYS_fchmod,
        "fchmodat" => libc::SYS_fchmodat,
        "chown" => libc::SYS_chown,
        "fchown" => libc::SYS_fchown,
        "lchown" => libc::SYS_lchown,
        "fchownat" => libc::SYS_fchownat,
        "umask" => libc::SYS_umask,
        "ioctl" => libc::SYS_ioctl,
        "utimensat" => libc::SYS_utimensat,

        // --- Memory ---
        "brk" => libc::SYS_brk,
        "mmap" => libc::SYS_mmap,
        "munmap" => libc::SYS_munmap,
        "mprotect" => libc::SYS_mprotect,
        "mremap" => libc::SYS_mremap,
        "madvise" => libc::SYS_madvise,
        "msync" => libc::SYS_msync,
        "mincore" => libc::SYS_mincore,

        // --- Process ---
        "clone" => libc::SYS_clone,
        "fork" => libc::SYS_fork,
        "vfork" => libc::SYS_vfork,
        "execve" => libc::SYS_execve,
        "execveat" => libc::SYS_execveat,
        "wait4" => libc::SYS_wait4,
        "waitid" => libc::SYS_waitid,
        "exit" => libc::SYS_exit,
        "exit_group" => libc::SYS_exit_group,
        "getpid" => libc::SYS_getpid,
        "getppid" => libc::SYS_getppid,
        "gettid" => libc::SYS_gettid,
        "getuid" => libc::SYS_getuid,
        "getgid" => libc::SYS_getgid,
        "geteuid" => libc::SYS_geteuid,
        "getegid" => libc::SYS_getegid,
        "getgroups" => libc::SYS_getgroups,
        "setgroups" => libc::SYS_setgroups,
        "getresuid" => libc::SYS_getresuid,
        "getresgid" => libc::SYS_getresgid,
        "getpgrp" => libc::SYS_getpgrp,
        "prctl" => libc::SYS_prctl,
        "arch_prctl" => libc::SYS_arch_prctl,
        "set_tid_address" => libc::SYS_set_tid_address,
        "set_robust_list" => libc::SYS_set_robust_list,
        "get_robust_list" => libc::SYS_get_robust_list,

        // --- Time ---
        "time" => libc::SYS_time,
        "gettimeofday" => libc::SYS_gettimeofday,
        "clock_gettime" => libc::SYS_clock_gettime,
        "clock_getres" => libc::SYS_clock_getres,
        "clock_nanosleep" => libc::SYS_clock_nanosleep,
        "nanosleep" => libc::SYS_nanosleep,
        "clock_adjtime" => libc::SYS_clock_adjtime,

        // --- Resource limits ---
        "getrlimit" => libc::SYS_getrlimit,
        "setrlimit" => libc::SYS_setrlimit,
        "prlimit64" => libc::SYS_prlimit64,
        "getrusage" => libc::SYS_getrusage,

        // --- Signals ---
        "rt_sigaction" => libc::SYS_rt_sigaction,
        "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
        "rt_sigreturn" => libc::SYS_rt_sigreturn,
        "sigaltstack" => libc::SYS_sigaltstack,
        "rt_sigpending" => libc::SYS_rt_sigpending,
        "rt_sigsuspend" => libc::SYS_rt_sigsuspend,
        "rt_sigqueueinfo" => libc::SYS_rt_sigqueueinfo,
        "rt_tgsigqueueinfo" => libc::SYS_rt_tgsigqueueinfo,
        "kill" => libc::SYS_kill,
        "tgkill" => libc::SYS_tgkill,
        "tkill" => libc::SYS_tkill,

        // --- I/O multiplexing ---
        "select" => libc::SYS_select,
        "poll" => libc::SYS_poll,
        "ppoll" => libc::SYS_ppoll,
        "epoll_create" => libc::SYS_epoll_create,
        "epoll_create1" => libc::SYS_epoll_create1,
        "epoll_ctl" => libc::SYS_epoll_ctl,
        "epoll_wait" => libc::SYS_epoll_wait,
        "epoll_pwait" => libc::SYS_epoll_pwait,
        "epoll_pwait2" => libc::SYS_epoll_pwait2,

        // --- Pipes ---
        "pipe" => libc::SYS_pipe,
        "pipe2" => libc::SYS_pipe2,

        // --- Eventfd / timerfd ---
        "eventfd" => libc::SYS_eventfd,
        "eventfd2" => libc::SYS_eventfd2,
        "timerfd_create" => libc::SYS_timerfd_create,
        "timerfd_settime" => libc::SYS_timerfd_settime,
        "timerfd_gettime" => libc::SYS_timerfd_gettime,
        "timer_create" => libc::SYS_timer_create,
        "timer_settime" => libc::SYS_timer_settime,
        "timer_gettime" => libc::SYS_timer_gettime,
        "timer_delete" => libc::SYS_timer_delete,

        // --- Sockets ---
        "socket" => libc::SYS_socket,
        "connect" => libc::SYS_connect,
        "accept" => libc::SYS_accept,
        "accept4" => libc::SYS_accept4,
        "sendto" => libc::SYS_sendto,
        "recvfrom" => libc::SYS_recvfrom,
        "sendmsg" => libc::SYS_sendmsg,
        "recvmsg" => libc::SYS_recvmsg,
        "bind" => libc::SYS_bind,
        "listen" => libc::SYS_listen,
        "getsockname" => libc::SYS_getsockname,
        "getpeername" => libc::SYS_getpeername,
        "setsockopt" => libc::SYS_setsockopt,
        "getsockopt" => libc::SYS_getsockopt,
        "socketpair" => libc::SYS_socketpair,
        "shutdown" => libc::SYS_shutdown,

        // --- Futex ---
        "futex" => libc::SYS_futex,
        "futex_waitv" => libc::SYS_futex_waitv,

        // --- Scheduling ---
        "sched_yield" => libc::SYS_sched_yield,
        "sched_getaffinity" => libc::SYS_sched_getaffinity,
        "sched_setaffinity" => libc::SYS_sched_setaffinity,
        "sched_get_priority_max" => libc::SYS_sched_get_priority_max,
        "sched_get_priority_min" => libc::SYS_sched_get_priority_min,

        // --- Miscellaneous ---
        "getrandom" => libc::SYS_getrandom,
        "uname" => libc::SYS_uname,
        "sysinfo" => libc::SYS_sysinfo,
        "syslog" => libc::SYS_syslog,
        "rseq" => libc::SYS_rseq,
        "preadv" => libc::SYS_preadv,
        "pwritev" => libc::SYS_pwritev,
        "readv" => libc::SYS_readv,
        "writev" => libc::SYS_writev,
        "splice" => libc::SYS_splice,
        "tee" => libc::SYS_tee,
        "vmsplice" => libc::SYS_vmsplice,
        "copy_file_range" => libc::SYS_copy_file_range,
        "process_madvise" => libc::SYS_process_madvise,
        "fadvise64" => libc::SYS_fadvise64,

        // --- Dangerous (for deny lists) ---
        "ptrace" => libc::SYS_ptrace,
        "process_vm_readv" => libc::SYS_process_vm_readv,
        "process_vm_writev" => libc::SYS_process_vm_writev,
        "kexec_load" => libc::SYS_kexec_load,
        "kexec_file_load" => libc::SYS_kexec_file_load,
        "init_module" => libc::SYS_init_module,
        "finit_module" => libc::SYS_finit_module,
        "delete_module" => libc::SYS_delete_module,
        "reboot" => libc::SYS_reboot,
        "swapon" => libc::SYS_swapon,
        "swapoff" => libc::SYS_swapoff,
        "mount" => libc::SYS_mount,
        "umount2" => libc::SYS_umount2,
        "pivot_root" => libc::SYS_pivot_root,
        "chroot" => libc::SYS_chroot,
        "setns" => libc::SYS_setns,
        "unshare" => libc::SYS_unshare,
        // New mount API (kernel 5.2+)
        "open_tree" => libc::SYS_open_tree,
        "move_mount" => libc::SYS_move_mount,
        "mount_setattr" => libc::SYS_mount_setattr,
        "userfaultfd" => libc::SYS_userfaultfd,
        "bpf" => libc::SYS_bpf,
        "perf_event_open" => libc::SYS_perf_event_open,
        "iopl" => libc::SYS_iopl,
        "ioperm" => libc::SYS_ioperm,
        "acct" => libc::SYS_acct,
        "vhangup" => libc::SYS_vhangup,
        "personality" => libc::SYS_personality,
        "modify_ldt" => libc::SYS_modify_ldt,

        // --- User/namespace ---
        "clone3" => libc::SYS_clone3,
        "pidfd_open" => libc::SYS_pidfd_open,
        "pidfd_send_signal" => libc::SYS_pidfd_send_signal,
        "close_range" => libc::SYS_close_range,
        "landlock_create_ruleset" => libc::SYS_landlock_create_ruleset,
        "landlock_add_rule" => libc::SYS_landlock_add_rule,
        "landlock_restrict_self" => libc::SYS_landlock_restrict_self,

        // --- Inotify ---
        "inotify_init" => libc::SYS_inotify_init,
        "inotify_init1" => libc::SYS_inotify_init1,
        "inotify_add_watch" => libc::SYS_inotify_add_watch,
        "inotify_rm_watch" => libc::SYS_inotify_rm_watch,

        // --- Signalfd ---
        "signalfd" => libc::SYS_signalfd,
        "signalfd4" => libc::SYS_signalfd4,

        _ => {
            return Err(SandboxError::SeccompFilterBuild(format!(
                "unknown syscall: '{name}'"
            )))
        }
    } as i32)
}
