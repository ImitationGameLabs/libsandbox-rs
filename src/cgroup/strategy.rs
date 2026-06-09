//! Cgroup v2 access strategy detection (root vs delegated vs unavailable).

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};

use super::{CgroupController, CgroupFile, CGROUP_ROOT, NANOBOX_DIR};

// ---- Strategy types ----

/// How we access cgroup v2
#[derive(Debug, Clone)]
pub(super) enum CgroupStrategy {
    /// Running as root: use /sys/fs/cgroup/libsandbox/
    Root { base: std::path::PathBuf },
    /// Non-root with delegated subtree
    Delegated { base: std::path::PathBuf },
    /// No cgroup access possible
    Unavailable,
}

#[derive(Debug, Clone)]
pub(super) struct DelegatedBaseProbe {
    pub(super) base: std::path::PathBuf,
}

static CGROUP_STRATEGY: OnceLock<CgroupStrategy> = OnceLock::new();
static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(super) fn get_cgroup_strategy() -> CgroupStrategy {
    // Delegation and our current cgroup path are effectively process-wide for
    // the lifetime of the test binary / application, so probing on every
    // sandbox creation only adds filesystem churn and more race surface.
    CGROUP_STRATEGY.get_or_init(detect_cgroup_strategy).clone()
}

// ---- Detection functions ----

/// Detect the cgroup v2 access strategy for the current process.
pub(super) fn detect_cgroup_strategy() -> CgroupStrategy {
    if nix::unistd::geteuid().is_root() {
        return CgroupStrategy::Root {
            base: std::path::PathBuf::from(CGROUP_ROOT).join(NANOBOX_DIR),
        };
    }

    let cgroup_self = match fs::read_to_string("/proc/self/cgroup") {
        Ok(s) => s,
        Err(_) => return CgroupStrategy::Unavailable,
    };

    // cgroup v2 format: "0::/path\n"
    let cgroup_path = match cgroup_self
        .lines()
        .find(|l| l.starts_with("0::"))
        .map(|l| l.trim_start_matches("0::").trim())
    {
        Some(p) if p != "/" && !p.is_empty() => p,
        _ => return CgroupStrategy::Unavailable,
    };

    let base = std::path::PathBuf::from(CGROUP_ROOT).join(cgroup_path.trim_start_matches('/'));

    if !base.exists() {
        return CgroupStrategy::Unavailable;
    }

    // Without threaded subtree support, rootless delegation needs an empty,
    // writable "domain" cgroup before we can safely fan out resource control to
    // child sandboxes.
    let base = match find_usable_cgroup_base(&base) {
        Some(probe) => probe.base,
        None => return CgroupStrategy::Unavailable,
    };

    CgroupStrategy::Delegated { base }
}

/// Find a usable delegated base, walking up until we find a writable, empty
/// domain cgroup suitable for spawning managed child cgroups.
fn find_usable_cgroup_base(initial: &Path) -> Option<DelegatedBaseProbe> {
    let mut candidate = initial.to_path_buf();

    loop {
        if let Some(probe) = probe_delegated_base(&candidate) {
            return Some(probe);
        }

        candidate = candidate.parent()?.to_path_buf();
        if !candidate.starts_with(CGROUP_ROOT) || candidate == Path::new(CGROUP_ROOT) {
            return None;
        }
    }
}

fn probe_cgroup_writable(path: &Path) -> bool {
    let probe_id = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let probe = path.join(format!(
        ".libsandbox_probe_{}_{}",
        std::process::id(),
        probe_id
    ));
    match fs::create_dir(&probe) {
        Ok(()) => {
            let _ = fs::remove_dir(&probe);
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match fs::remove_dir(&probe) {
            Ok(()) => true,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        },
        Err(_) => false,
    }
}

fn file_writable(path: &Path) -> bool {
    OpenOptions::new().write(true).open(path).is_ok()
}

fn read_cgroup_type(path: &Path) -> String {
    fs::read_to_string(path.join("cgroup.type"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn cgroup_is_populated(path: &Path) -> bool {
    let events = fs::read_to_string(path.join("cgroup.events")).unwrap_or_default();
    for line in events.lines() {
        let mut parts = line.split_whitespace();
        if matches!(parts.next(), Some("populated")) {
            return matches!(parts.next(), Some("1"));
        }
    }

    fs::read_to_string(path.join(CgroupFile::Procs.filename()))
        .map(|procs| !procs.trim().is_empty())
        .unwrap_or(false)
}

fn probe_delegated_base(path: &Path) -> Option<DelegatedBaseProbe> {
    if !probe_cgroup_writable(path) {
        return None;
    }

    if !file_writable(&path.join(CgroupFile::Procs.filename()))
        || !file_writable(&path.join(CgroupFile::SubtreeControl.filename()))
    {
        return None;
    }

    if read_cgroup_type(path) != "domain" || cgroup_is_populated(path) {
        return None;
    }

    Some(DelegatedBaseProbe {
        base: path.to_path_buf(),
    })
}

/// Read the list of controllers available at a given cgroup path
pub(super) fn read_controllers(path: &Path) -> Vec<CgroupController> {
    let controllers_file = path.join(CgroupFile::Controllers.filename());
    let raw = fs::read_to_string(&controllers_file).unwrap_or_default();
    let mut controllers = Vec::new();
    for c in raw.split_whitespace() {
        match c {
            "memory" => controllers.push(CgroupController::Memory),
            "cpu" => controllers.push(CgroupController::Cpu),
            "pids" => controllers.push(CgroupController::Pids),
            _ => {}
        }
    }
    controllers
}

/// Try to enable controllers in cgroup.subtree_control at the given path
pub(super) fn try_enable_controllers(
    path: &Path,
    controllers: &[CgroupController],
) -> Vec<(CgroupController, std::io::Result<()>)> {
    let subtree = path.join(CgroupFile::SubtreeControl.filename());
    let mut results = Vec::with_capacity(controllers.len());

    for controller in controllers {
        let enabled = fs::read_to_string(&subtree).unwrap_or_default();
        let already_enabled = enabled
            .split_whitespace()
            .any(|name| name == controller.as_str());
        if already_enabled {
            results.push((*controller, Ok(())));
            continue;
        }

        results.push((
            *controller,
            fs::write(&subtree, format!("+{}", controller.as_str())),
        ));
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_detect_strategy_root_path() {
        if nix::unistd::geteuid().is_root() {
            let strategy = detect_cgroup_strategy();
            assert!(matches!(strategy, CgroupStrategy::Root { .. }));
        }
    }

    #[test]
    fn test_detect_strategy_nonroot() {
        if !nix::unistd::geteuid().is_root() {
            let strategy = detect_cgroup_strategy();
            match &strategy {
                CgroupStrategy::Delegated { base } => {
                    assert!(base.starts_with(CGROUP_ROOT));
                    assert!(base.exists());
                }
                CgroupStrategy::Unavailable => {}
                CgroupStrategy::Root { .. } => {
                    panic!("Non-root should not get Root strategy")
                }
            }
        }
    }

    #[test]
    fn test_delegated_cgroup_flow() {
        if !nix::unistd::geteuid().is_root() {
            let strategy = detect_cgroup_strategy();
            let CgroupStrategy::Delegated { base } = &strategy else {
                return;
            };

            let cgroup_type = fs::read_to_string(base.join("cgroup.type")).unwrap_or_default();

            assert_eq!(
                cgroup_type.trim(),
                "domain",
                "base must be 'domain' type, got: {:?}",
                cgroup_type.trim()
            );

            // Create a child cgroup and verify we can write processes to it
            let child = base.join(format!("test_leaf_{}", std::process::id()));
            fs::create_dir(&child).expect("create child cgroup");

            let mut fds = [0; 2];
            assert_eq!(
                unsafe { libc::pipe(fds.as_mut_ptr()) },
                0,
                "create sync pipe"
            );
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe {
                    libc::close(fds[1]);
                }
                let mut buf = [0u8; 1];
                unsafe {
                    libc::read(fds[0], buf.as_mut_ptr() as *mut _, 1);
                    libc::close(fds[0]);
                    libc::_exit(0);
                }
            } else if pid > 0 {
                unsafe {
                    libc::close(fds[0]);
                }
                let procs_res = fs::write(child.join("cgroup.procs"), pid.to_string());
                unsafe {
                    libc::close(fds[1]);
                }
                assert!(
                    procs_res.is_ok(),
                    "should be able to add process to cgroup: {:?}",
                    procs_res
                );

                let mut status: i32 = 0;
                unsafe {
                    libc::waitpid(pid, &mut status, 0);
                }
            }

            let _ = fs::remove_dir(&child);
        }
    }
}
