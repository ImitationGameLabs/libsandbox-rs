//! Best-effort recursive kill for the non-cgroup path.
//!
//! When a sandboxed child has no cgroup, killing the root PID alone (or even
//! `kill(-pgid)`) misses descendants that called `setpgid()` to escape the
//! process group — the documented hole in the legacy kill path. `kill_tree`
//! walks `/proc/<pid>/task/<tid>/children` to enumerate the whole descendant
//! tree and signals each via `pidfd_send_signal` (race-tolerant).
//!
//! This is **best-effort**: reparented orphans (whose parent died before the
//! walk) can escape, and a fork racing the enumeration may briefly survive.
//! The walk is iterated to a fixpoint with bounded rounds to close the common
//! races. For untrusted workloads, prefer a cgroup-backed sandbox
//! (`CgroupManager::kill_all`, or the atomic `cgroup.kill` file on ≥5.14).

use std::collections::HashSet;
use std::time::Duration;

/// Read the direct child tgids of `pid` from `/proc/<pid>/task/<pid>/children`.
fn read_children(pid: i32) -> Vec<i32> {
    let path = format!("/proc/{pid}/task/{pid}/children");
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .split_whitespace()
            .filter_map(|t| t.parse::<i32>().ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Collect the root pid and all live descendants (BFS over `/proc/.../children`).
fn collect_descendants(root_pid: i32) -> Vec<i32> {
    let mut seen = HashSet::new();
    let mut stack = vec![root_pid];
    let mut out = Vec::new();
    while let Some(pid) = stack.pop() {
        if !seen.insert(pid) {
            continue;
        }
        out.push(pid);
        for child in read_children(pid) {
            stack.push(child);
        }
    }
    out
}

/// Signal a single pid via `pidfd_open` + `pidfd_send_signal` (avoids PID
/// recycling), falling back to `kill(pid)` if `pidfd_open` is unavailable.
/// `ESRCH` (already dead) is tolerated silently.
fn kill_pid(pid: i32) {
    // SAFETY: pidfd_open(pid, 0) returns a pidfd or -1 on error.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if pidfd >= 0 {
        // SAFETY: pidfd_send_signal with a valid pidfd, SIGKILL, null siginfo.
        let _ = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd as libc::c_int,
                libc::SIGKILL as libc::c_int,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        // SAFETY: close the pidfd we just opened.
        unsafe { libc::close(pidfd as libc::c_int) };
    } else {
        // SAFETY: kill(pid, SIGKILL); errors (ESRCH etc.) ignored.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

/// Kill `root_pid` and all of its descendants by iteratively walking
/// `/proc/.../children` to a fixpoint. Best-effort; see the module docs.
pub(crate) fn kill_tree(root_pid: i32) {
    // Re-walk each round so descendants forked between rounds are caught.
    // 5 rounds × 10 ms mirrors CgroupManager::kill_all's fallback cadence.
    for _ in 0..5 {
        let live = collect_descendants(root_pid);
        if live.is_empty() {
            break;
        }
        for pid in &live {
            kill_pid(*pid);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_descendants_of_self_is_just_self() {
        // The current process has itself as root; children may include the
        // test runner, but the root must always be present.
        let live = collect_descendants(std::process::id() as i32);
        assert!(live.contains(&(std::process::id() as i32)));
    }

    #[test]
    fn read_children_returns_vec_for_live_process() {
        // Should not panic for a live pid; content is environment-dependent.
        let _ = read_children(std::process::id() as i32);
    }
}
