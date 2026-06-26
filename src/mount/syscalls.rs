//! Raw Linux syscall wrappers for the new mount API and dynamic mount operations.
//!
//! Provides safe-ish wrappers around `open_tree(2)`, `move_mount(2)`, and a
//! fork-based helper that satisfies the single-threaded `setns()` constraint.

use super::ops::permission_to_remount_flags;
use crate::config::Permission;
use crate::error::{ErrorKind, Result, SandboxError};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::Path;

// ---------------------------------------------------------------------------
// Syscall number constants (x86_64).
//
// `libc` may not expose these on all build environments, so we define them
// as raw constants to avoid depending on a minimum libc version.
// ---------------------------------------------------------------------------

const SYS_OPEN_TREE: i64 = 428;
const SYS_MOVE_MOUNT: i64 = 429;

// open_tree flags
const OPEN_TREE_CLONE: u32 = 0x01;
const OPEN_TREE_CLOEXEC: u32 = 0x00080000;

// move_mount flags
const MOVE_MOUNT_F_EMPTY_PATH: u64 = 0x00000004;

// AT_RECURSIVE for open_tree
const AT_RECURSIVE: libc::c_uint = 0x00008000;

// Status byte values for the fork helper pipe protocol.
const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;
// Status byte >= 2 encodes an errno value directly.

/// Helper to get the current errno as i32.
fn last_errno() -> i32 {
    nix::errno::Errno::last_raw()
}

/// Helper to format an errno value for error messages.
fn format_errno(errno: i32) -> String {
    nix::errno::Errno::from_raw(errno).to_string()
}

// ---------------------------------------------------------------------------
// Raw syscall wrappers (non-allocating, for use in fork helper)
// ---------------------------------------------------------------------------

// Note: sys_open_tree and sys_move_mount are inlined directly in
// dynamic_bind_mount's closures as raw libc::syscall() calls to avoid
// any allocation (format! etc.) in the forked child process.

// ---------------------------------------------------------------------------
// Fork helper infrastructure
// ---------------------------------------------------------------------------

/// Run an operation inside the child's namespaces by forking a single-threaded
/// helper process.
///
/// The helper:
/// 1. `setns(user_ns_fd, CLONE_NEWUSER)` — enters child's user namespace,
///    gaining `CAP_SYS_ADMIN` there.
/// 2. Optionally runs `pre_mnt_op` while still in the **parent's** mount
///    namespace (needed for `open_tree` to see host paths).
/// 3. `setns(mnt_ns_fd, CLONE_NEWNS)` — enters child's mount namespace.
/// 4. Runs `op` — performs the actual mount/unmount/move_mount.
/// 5. Writes a status byte to the pipe and exits.
///
/// # Safety
///
/// The closures MUST only use async-signal-safe functions (raw syscalls).
/// No allocations, no mutexes, no `std::fs`.
///
/// ## Fork in a multi-threaded parent
///
/// `libc::fork()` in a multi-threaded process only clones the calling thread.
/// This is safe here because the child (helper) process:
/// - Performs **no allocations** — all strings are pre-formatted before fork
///   or built on the stack inside the closures.
/// - Touches **no mutexes** — the parent's mutex state is inherited but
///   never accessed (no `Arc::clone`, no `std::fs`, no `println!`).
/// - Calls `_exit()` (not `exit()`), so no atexit handlers or TLS
///   destructors run.
/// - Uses only raw `libc::syscall()` and libc wrappers (`open`, `close`,
///   `mkdirat`, `umount2`) that are thin syscall wrappers with no internal
///   locking.
///
/// `last_errno()` reads `__errno_location()` — a simple TLS address
/// computation that is async-signal-safe in practice on glibc and musl.
///
/// ## `pre_mnt_op` and fd ownership
///
/// If `pre_mnt_op` is provided and returns nonzero, the helper calls
/// `_exit(1)`. The caller must ensure that any resources (fds) obtained
/// during `pre_mnt_op` are either cleaned up before returning the error
/// or are acceptable to leak (the kernel reclaims all fds on `_exit`).
fn fork_in_namespaces<F>(
    user_ns_fd: RawFd,
    mnt_ns_fd: RawFd,
    pre_mnt_op: Option<&dyn Fn() -> libc::c_int>,
    op: F,
) -> Result<()>
where
    F: FnOnce() -> libc::c_int,
{
    // Pre-format the /proc/self/fd/N paths before fork (no allocation in helper).
    let user_ns_proc = format!("/proc/self/fd/{}", user_ns_fd);
    let mnt_ns_proc = format!("/proc/self/fd/{}", mnt_ns_fd);
    let user_ns_cstr = CString::new(user_ns_proc.as_str()).expect("valid CString");
    let mnt_ns_cstr = CString::new(mnt_ns_proc.as_str()).expect("valid CString");

    // Create a status pipe for the helper to report results.
    let mut status_pipe: [RawFd; 2] = [-1, -1];
    let pipe_ret = unsafe { libc::pipe(status_pipe.as_mut_ptr()) };
    if pipe_ret < 0 {
        return Err(SandboxError::new(
            ErrorKind::Mount,
            format!(
                "dynamic mount operation failed: pipe() failed: {}",
                format_errno(last_errno())
            ),
        ));
    }
    let (status_r, status_w) = (status_pipe[0], status_pipe[1]);

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            let _ = unsafe { libc::close(status_r) };
            let _ = unsafe { libc::close(status_w) };
            Err(SandboxError::new(
                ErrorKind::Mount,
                format!(
                    "dynamic mount operation failed: fork() failed: {}",
                    format_errno(last_errno())
                ),
            ))
        }
        0 => {
            // --- Helper process (single-threaded after fork) ---
            // CAUTION: Only async-signal-safe functions from here on.
            // Entire helper body is in an unsafe block since we use raw syscalls.
            unsafe {
                libc::close(status_r);

                // Enter child's user namespace (gain CAP_SYS_ADMIN).
                let user_fd = libc::open(user_ns_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                if user_fd < 0 {
                    let _ = raw_write(status_w, STATUS_ERROR);
                    libc::_exit(1);
                }
                let ret = libc::syscall(
                    libc::SYS_setns,
                    user_fd as libc::c_ulong,
                    libc::CLONE_NEWUSER as libc::c_ulong,
                );
                libc::close(user_fd);
                if ret < 0 {
                    let _ = raw_write(status_w, STATUS_ERROR);
                    libc::_exit(1);
                }

                // Run pre-mount operation while still in parent's mount namespace.
                // Used by add_mount to call open_tree (source path is visible here).
                //
                // SAFETY: If pre_mnt_op returns nonzero, we _exit(1) immediately.
                // The current callers (dynamic_bind_mount) only store an fd in the
                // Cell on success (return 0), so no fd leak occurs on this path.
                // _exit also reclaims all fds as a last-resort fallback.
                if let Some(pre) = pre_mnt_op {
                    let pre_ret = pre();
                    if pre_ret != 0 {
                        let _ = raw_write(status_w, encode_errno(pre_ret));
                        libc::_exit(1);
                    }
                }

                // Enter child's mount namespace.
                let mnt_fd = libc::open(mnt_ns_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                if mnt_fd < 0 {
                    let _ = raw_write(status_w, STATUS_ERROR);
                    libc::_exit(1);
                }
                let ret = libc::syscall(
                    libc::SYS_setns,
                    mnt_fd as libc::c_ulong,
                    libc::CLONE_NEWNS as libc::c_ulong,
                );
                libc::close(mnt_fd);
                if ret < 0 {
                    let _ = raw_write(status_w, STATUS_ERROR);
                    libc::_exit(1);
                }

                // Run the actual operation (mount/umount/move_mount).
                let op_ret = op();
                let status = if op_ret == 0 {
                    STATUS_OK
                } else {
                    encode_errno(op_ret)
                };
                let _ = raw_write(status_w, status);
                libc::_exit(0);
            }
        }
        helper_pid => {
            // --- Parent process ---
            unsafe { libc::close(status_w) };

            // Wait for helper to finish.
            let mut wait_status: libc::c_int = 0;
            loop {
                let ret = unsafe { libc::waitpid(helper_pid, &mut wait_status, 0) };
                if ret == helper_pid {
                    break;
                }
                if ret < 0 {
                    let err = last_errno();
                    if err == libc::EINTR {
                        continue;
                    }
                    unsafe { libc::close(status_r) };
                    return Err(SandboxError::new(
                        ErrorKind::Mount,
                        format!(
                            "dynamic mount operation failed: waitpid failed: {}",
                            format_errno(err)
                        ),
                    ));
                }
            }

            // Read the status byte.
            let mut buf: [u8; 1] = [0];
            let n = unsafe { libc::read(status_r, buf.as_mut_ptr() as *mut libc::c_void, 1) };
            unsafe { libc::close(status_r) };

            if n != 1 {
                return Err(SandboxError::new(
                    ErrorKind::Mount,
                    format!(
                        "dynamic mount operation failed: {}",
                        "helper process did not report status"
                    ),
                ));
            }

            match buf[0] {
                STATUS_OK => Ok(()),
                STATUS_ERROR => Err(SandboxError::new(
                    ErrorKind::Mount,
                    format!(
                        "dynamic mount operation failed: {}",
                        "helper reported generic failure"
                    ),
                )),
                errno_byte if errno_byte >= 2 => {
                    let errno = (errno_byte - 2) as i32;
                    Err(SandboxError::new(
                        ErrorKind::Mount,
                        format!(
                            "dynamic mount operation failed: helper failed: {}",
                            format_errno(errno)
                        ),
                    ))
                }
                _ => Err(SandboxError::new(
                    ErrorKind::Mount,
                    format!(
                        "dynamic mount operation failed: helper reported unknown status: {}",
                        buf[0]
                    ),
                )),
            }
        }
    }
}

/// Encode an errno value into a status byte (>= 2 means errno).
fn encode_errno(errno: libc::c_int) -> u8 {
    // Linux errno values are positive and typically < 131. Clamp to
    // 0..=253 so that (errno + 2) fits in a u8, avoiding collision
    // with STATUS_OK (0) and STATUS_ERROR (1).
    debug_assert!(
        (0..=253).contains(&errno),
        "unexpected errno value: {errno}"
    );
    (errno.clamp(0, 253) as u8).saturating_add(2)
}

/// Async-signal-safe write of a single byte.
unsafe fn raw_write(fd: RawFd, byte: u8) -> libc::ssize_t {
    libc::write(fd, &byte as *const u8 as *const libc::c_void, 1)
}

/// Async-signal-safe `mkdir -p` using a component-by-component `mkdirat` loop.
///
/// `path` must be an absolute path. Each component is created with `mkdirat`.
/// `EEXIST` is silently ignored (component already exists).
///
/// # Limitations
///
/// This function follows symlinks in path components. A process inside the
/// sandbox could theoretically race to replace a component with a symlink
/// between `mkdirat` calls, redirecting the mount point. This risk is
/// mitigated by: (1) the operation runs inside the sandbox's mount namespace
/// (blast radius is contained), and (2) the TOCTOU window is extremely
/// narrow (microseconds between mkdirat calls).
unsafe fn raw_mkdir_p(dirfd: RawFd, path: &[u8]) -> libc::c_int {
    // Walk forward through the path, creating each directory component.
    // At each step, pass the accumulated path up to and including the
    // current component (e.g., "a", then "a/b", then "a/b/c") so that
    // mkdirat creates nested directories correctly.
    let mut end = 0;
    while end < path.len() {
        // Skip slashes to find start of next component.
        while end < path.len() && path[end] == b'/' {
            end += 1;
        }
        if end >= path.len() {
            break;
        }
        // Find end of current component.
        while end < path.len() && path[end] != b'/' {
            end += 1;
        }
        // Null-terminate the accumulated path up to `end` on the stack.
        let mut buf = [0u8; 4096];
        if end >= buf.len() {
            return libc::ENAMETOOLONG;
        }
        buf[..end].copy_from_slice(&path[..end]);
        buf[end] = 0;

        let ret = libc::mkdirat(dirfd, buf.as_ptr() as *const libc::c_char, 0o755);
        if ret < 0 {
            let err = last_errno();
            if err != libc::EEXIST {
                return err;
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// High-level dynamic mount operations
// ---------------------------------------------------------------------------

/// Probe for `open_tree` + `move_mount` kernel support.
///
/// Calls `open_tree` with an intentionally invalid fd. On kernel >= 5.2,
/// returns `EBADF` (fd invalid). On older kernels, returns `ENOSYS`
/// (syscall not implemented).
pub(crate) fn probe_mount_api() -> Result<()> {
    let empty = CString::new("").expect("valid CString");
    let ret = unsafe {
        libc::syscall(
            SYS_OPEN_TREE,
            -1i32 as libc::c_ulong,
            empty.as_ptr(),
            OPEN_TREE_CLONE as libc::c_uint,
        )
    };
    if ret < 0 {
        let err = last_errno();
        if err == libc::ENOSYS {
            return Err(SandboxError::new(
                ErrorKind::Mount,
                format!(
                    "dynamic mount operation failed: {}",
                    "open_tree syscall not available (kernel < 5.2)"
                ),
            ));
        }
        // EBADF or similar is expected — the probe succeeded.
    }
    Ok(())
}

/// Dynamically add a bind mount into a running sandbox.
///
/// The caller must ensure `source` exists on the host and `target` has been
/// validated. `user_ns_fd` and `mnt_ns_fd` are pre-opened namespace fds.
pub(crate) fn dynamic_bind_mount(
    source: &Path,
    target: &Path,
    permission: &Permission,
    user_ns_fd: RawFd,
    mnt_ns_fd: RawFd,
) -> Result<()> {
    probe_mount_api()?;

    let source_cstr = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        SandboxError::new(
            ErrorKind::Mount,
            format!(
                "dynamic mount operation failed: {}",
                "source path contains NUL byte"
            ),
        )
    })?;
    let target_bytes = target.as_os_str().as_bytes();
    let recursive = source.is_dir();

    // Pre-allocate the permission flags so the helper doesn't need to compute them.
    let remount_flags = match permission {
        Permission::ReadWrite => None,
        _ => Some(permission_to_remount_flags(permission, recursive)),
    };
    let need_remount = remount_flags.is_some();
    let flags_val = remount_flags.unwrap_or(nix::mount::MsFlags::empty());

    // Pre-op: runs in the forked child AFTER setns(user_ns) but BEFORE
    // setns(mnt_ns). Uses raw syscalls only (no allocation).
    // Calls open_tree while still in the parent's mount namespace
    // (source path is visible here), then the fd is passed to op
    // via the Cell on the stack.
    let source_ptr = source_cstr.as_ptr();
    let tree_flags = if recursive {
        OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE
    } else {
        OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC
    };

    // SAFETY: Stack-local Cell shared between pre_op and op closures.
    // Both closures run sequentially inside the same forked child process.
    // After fork(), the child gets an independent copy of the parent's
    // address space — the Cell in the child is unrelated to the parent's.
    // No synchronization is needed because: (1) only one thread exists
    // in the child after fork, and (2) pre_op completes before op starts
    // (guaranteed by fork_in_namespaces execution order).
    let detached_fd = std::cell::Cell::new(-1i32);

    let pre_op = {
        let detached_fd = &detached_fd;
        move || -> libc::c_int {
            // Raw open_tree syscall — returns fd directly, no allocation.
            let ret = unsafe {
                libc::syscall(
                    SYS_OPEN_TREE,
                    libc::AT_FDCWD as libc::c_ulong,
                    source_ptr,
                    tree_flags,
                )
            };
            if ret < 0 {
                last_errno()
            } else {
                detached_fd.set(ret as RawFd);
                0
            }
        }
    };

    let op = {
        let detached_fd = &detached_fd;
        move || -> libc::c_int {
            let fd = detached_fd.get();

            // Create mount point directory.
            let mkdir_ret = unsafe { raw_mkdir_p(libc::AT_FDCWD, target_bytes) };
            if mkdir_ret != 0 {
                // Close detached fd on early return.
                unsafe { libc::close(fd) };
                return mkdir_ret;
            }

            // Convert target to CString for move_mount.
            let mut target_buf = [0u8; 4096];
            if target_bytes.len() >= target_buf.len() {
                unsafe { libc::close(fd) };
                return libc::ENAMETOOLONG;
            }
            target_buf[..target_bytes.len()].copy_from_slice(target_bytes);
            target_buf[target_bytes.len()] = 0;

            // Attach the detached mount.
            let ret = unsafe {
                libc::syscall(
                    SYS_MOVE_MOUNT,
                    fd as libc::c_ulong,
                    c"".as_ptr(),
                    libc::AT_FDCWD as libc::c_ulong,
                    target_buf.as_ptr() as *const libc::c_char,
                    MOVE_MOUNT_F_EMPTY_PATH,
                )
            };
            // Close the detached fd regardless of move_mount result.
            unsafe { libc::close(fd) };

            if ret < 0 {
                return last_errno();
            }

            // Apply mount options via legacy remount.
            if need_remount {
                let ret = unsafe {
                    libc::syscall(
                        libc::SYS_mount,
                        std::ptr::null::<libc::c_char>(),
                        target_buf.as_ptr() as *const libc::c_char,
                        std::ptr::null::<libc::c_char>(),
                        flags_val.bits() as libc::c_ulong,
                        std::ptr::null::<libc::c_char>(),
                    )
                };
                if ret < 0 {
                    // Capture errno before the rollback umount overwrites it.
                    let remount_errno = last_errno();
                    // Rollback: detach the partially-configured mount so it
                    // does not persist with default (read-write) permissions.
                    unsafe {
                        libc::umount2(target_buf.as_ptr() as *const libc::c_char, libc::MNT_DETACH);
                    }
                    return remount_errno;
                }
            }

            0
        }
    };

    fork_in_namespaces(user_ns_fd, mnt_ns_fd, Some(&pre_op), op)
}

/// Dynamically remove a mount from a running sandbox.
pub(crate) fn dynamic_unmount(target: &Path, user_ns_fd: RawFd, mnt_ns_fd: RawFd) -> Result<()> {
    let target_bytes = target.as_os_str().as_bytes();

    let op = || -> libc::c_int {
        // Convert target to CString.
        let mut target_buf = [0u8; 4096];
        if target_bytes.len() >= target_buf.len() {
            return libc::ENAMETOOLONG;
        }
        target_buf[..target_bytes.len()].copy_from_slice(target_bytes);
        target_buf[target_bytes.len()] = 0;

        let ret =
            unsafe { libc::umount2(target_buf.as_ptr() as *const libc::c_char, libc::MNT_DETACH) };
        if ret < 0 {
            last_errno()
        } else {
            0
        }
    };

    fork_in_namespaces(user_ns_fd, mnt_ns_fd, None, op)
}

/// Dynamically change the permission of an existing mount (remount).
pub(crate) fn dynamic_remount(
    target: &Path,
    permission: &Permission,
    recursive: bool,
    user_ns_fd: RawFd,
    mnt_ns_fd: RawFd,
) -> Result<()> {
    let target_bytes = target.as_os_str().as_bytes();
    let flags = permission_to_remount_flags(permission, recursive);

    let op = move || -> libc::c_int {
        let mut target_buf = [0u8; 4096];
        if target_bytes.len() >= target_buf.len() {
            return libc::ENAMETOOLONG;
        }
        target_buf[..target_bytes.len()].copy_from_slice(target_bytes);
        target_buf[target_bytes.len()] = 0;

        let ret = unsafe {
            libc::syscall(
                libc::SYS_mount,
                std::ptr::null::<libc::c_char>(),
                target_buf.as_ptr() as *const libc::c_char,
                std::ptr::null::<libc::c_char>(),
                flags.bits() as libc::c_ulong,
                std::ptr::null::<libc::c_char>(),
            )
        };
        if ret < 0 {
            last_errno()
        } else {
            0
        }
    };

    fork_in_namespaces(user_ns_fd, mnt_ns_fd, None, op)
}

/// Dynamically add a tmpfs mount into a running sandbox.
pub(crate) fn dynamic_tmpfs(
    target: &Path,
    size_bytes: u64,
    user_ns_fd: RawFd,
    mnt_ns_fd: RawFd,
) -> Result<()> {
    let target_bytes = target.as_os_str().as_bytes();
    // Pre-format the options string before fork.
    let options = format!("size={size_bytes}");
    let options_bytes = options.as_bytes();

    let op = || -> libc::c_int {
        // Create mount point.
        let mkdir_ret = unsafe { raw_mkdir_p(libc::AT_FDCWD, target_bytes) };
        if mkdir_ret != 0 {
            return mkdir_ret;
        }

        // Prepare CStrings on stack.
        let mut target_buf = [0u8; 4096];
        if target_bytes.len() >= target_buf.len() {
            return libc::ENAMETOOLONG;
        }
        target_buf[..target_bytes.len()].copy_from_slice(target_bytes);
        target_buf[target_bytes.len()] = 0;

        let mut opts_buf = [0u8; 256];
        if options_bytes.len() >= opts_buf.len() {
            return libc::ENAMETOOLONG;
        }
        opts_buf[..options_bytes.len()].copy_from_slice(options_bytes);
        opts_buf[options_bytes.len()] = 0;

        let fstype = b"tmpfs\0";

        let ret = unsafe {
            libc::syscall(
                libc::SYS_mount,
                fstype.as_ptr() as *const libc::c_char,
                target_buf.as_ptr() as *const libc::c_char,
                fstype.as_ptr() as *const libc::c_char,
                0u64,
                opts_buf.as_ptr() as *const libc::c_void,
            )
        };
        if ret < 0 {
            last_errno()
        } else {
            0
        }
    };

    fork_in_namespaces(user_ns_fd, mnt_ns_fd, None, op)
}

/// Check if the child process is still alive using pidfd.
///
/// Returns `Ok(())` if alive, `Err(SandboxError::new(crate::error::ErrorKind::ChildGone, "child process has exited"))` if dead.
pub(crate) fn check_child_alive(pidfd: Option<RawFd>) -> Result<()> {
    if let Some(fd) = pidfd {
        // Use pidfd_send_signal with signal 0 to check existence.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd as libc::c_int,
                0 as libc::c_int,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if ret < 0 {
            let err = last_errno();
            if err == libc::ESRCH {
                return Err(SandboxError::new(
                    crate::error::ErrorKind::ChildGone,
                    "child process has exited",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_mount_api() {
        // Should succeed on kernel >= 5.2 (EBADF from invalid fd, not ENOSYS).
        // This test simply verifies the function runs without panic.
        let _ = probe_mount_api();
    }

    #[test]
    fn test_encode_errno() {
        assert_eq!(encode_errno(0), 2);
        assert_eq!(encode_errno(1), 3);
        assert_eq!(encode_errno(22), 24); // EINVAL
        assert_eq!(encode_errno(253), 255);
    }

    #[test]
    fn test_encode_errno_clamp() {
        // Verify the boundary: 253 is the last unclamped value.
        assert_eq!(encode_errno(252), 254);
        assert_eq!(encode_errno(253), 255);
        // Values outside the valid errno range are handled by the clamp
        // expression. Test the clamping logic directly (encode_errno has a
        // debug_assert that catches these values in debug builds).
        assert_eq!((-1i32).clamp(0, 253) as u8, 0u8);
        assert_eq!((-100i32).clamp(0, 253) as u8, 0u8);
        assert_eq!((254i32).clamp(0, 253) as u8, 253u8);
        assert_eq!((1000i32).clamp(0, 253) as u8, 253u8);
        // Verify saturating_add does not overflow for the max clamped value.
        assert_eq!(253u8.saturating_add(2), 255u8);
    }

    #[test]
    fn test_raw_mkdir_p_basic() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // raw_mkdir_p strips leading '/' and creates components relative to
        // dirfd, so pass the tempdir fd with a relative path.
        let dirfd = unsafe {
            libc::open(
                tmp.path().as_os_str().as_bytes().as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_DIRECTORY,
            )
        };
        assert!(dirfd >= 0, "failed to open tempdir");

        let ret = unsafe { raw_mkdir_p(dirfd, b"a/b/c") };
        unsafe { libc::close(dirfd) };
        assert_eq!(ret, 0, "raw_mkdir_p failed: {}", format_errno(ret));
        assert!(
            tmp.path().join("a/b/c").is_dir(),
            "directory was not created"
        );
    }

    #[test]
    fn test_raw_mkdir_p_existing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let existing = tmp.path().join("already_exists");
        std::fs::create_dir_all(&existing).expect("create_dir_all");

        let dirfd = unsafe {
            libc::open(
                tmp.path().as_os_str().as_bytes().as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_DIRECTORY,
            )
        };
        assert!(dirfd >= 0);

        let ret = unsafe { raw_mkdir_p(dirfd, b"already_exists") };
        unsafe { libc::close(dirfd) };
        assert_eq!(ret, 0, "raw_mkdir_p should succeed on existing dirs");
    }

    #[test]
    fn test_raw_mkdir_p_deep() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Create a deeply nested path (20 components).
        let relative: String = (0..20).map(|i| format!("level{i}/")).collect();
        let relative_bytes = relative.trim_end_matches('/').as_bytes();

        let dirfd = unsafe {
            libc::open(
                tmp.path().as_os_str().as_bytes().as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_DIRECTORY,
            )
        };
        assert!(dirfd >= 0);

        let ret = unsafe { raw_mkdir_p(dirfd, relative_bytes) };
        unsafe { libc::close(dirfd) };
        assert_eq!(ret, 0, "raw_mkdir_p deep failed: {}", format_errno(ret));

        let expected: std::path::PathBuf =
            (0..20).fold(tmp.path().into(), |p, i| p.join(format!("level{i}")));
        assert!(expected.is_dir(), "deep directory was not created");
    }

    #[test]
    fn test_raw_mkdir_p_too_long() {
        // Path exceeding 4096 bytes (single component > 4096).
        let long_component = "a".repeat(5000);
        let path = format!("/tmp/{long_component}");
        let ret = unsafe { raw_mkdir_p(libc::AT_FDCWD, path.as_bytes()) };
        assert_eq!(ret, libc::ENAMETOOLONG);
    }
}
