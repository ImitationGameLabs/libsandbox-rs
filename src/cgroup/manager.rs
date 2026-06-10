//! Cgroup v2 manager with rootless support.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Result, SandboxError};

use super::strategy::{
    get_cgroup_strategy, read_controllers, try_enable_controllers, CgroupStrategy,
};
use super::{CgroupController, CgroupFile, CGROUP_ROOT, NANOBOX_DIR};

// ---- Public types ----

/// Memory statistics from cgroup
#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub current: u64,
    pub peak: u64,
}

/// CPU statistics from cgroup
#[derive(Debug, Clone)]
pub struct CpuStats {
    pub total_usec: u64,
    pub user_usec: u64,
    pub system_usec: u64,
}

/// Memory events from cgroup (for OOM detection)
#[derive(Debug, Clone, Default)]
pub struct MemoryEvents {
    pub oom: u64,
    pub oom_kill: u64,
    pub oom_group_kill: u64,
}

/// Cgroup v2 manager with rootless support
pub struct CgroupManager {
    path: PathBuf,
    available_controllers: Vec<CgroupController>,
    _strategy: CgroupStrategy,
}

/// Snapshot of cgroup support for the current process.
#[derive(Debug, Clone)]
pub struct CgroupSupport {
    pub mounted: bool,
    pub accessible: bool,
    pub available_controllers: Vec<CgroupController>,
}

impl CgroupSupport {
    pub fn controller_available(&self, controller: CgroupController) -> bool {
        self.available_controllers.contains(&controller)
    }

    pub fn can_enforce(&self, controller: CgroupController) -> bool {
        self.mounted && self.accessible && self.controller_available(controller)
    }

    pub fn available_controllers_string(&self) -> String {
        self.available_controllers
            .iter()
            .map(CgroupController::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn unavailable_reason(&self, controller: Option<CgroupController>) -> String {
        if !self.mounted {
            return "cgroups v2 not available. Resource limits require cgroup v2".into();
        }

        if !self.accessible {
            return "cgroup not writable or delegated base is unsuitable. Non-root requires a writable, empty delegated cgroup v2 parent or root access".into();
        }

        if let Some(controller) = controller {
            return format!(
                "cgroup controller '{}' not available. Available: {}",
                controller.as_str(),
                self.available_controllers_string()
            );
        }

        "cgroup support unavailable".into()
    }
}

impl CgroupManager {
    // ---- Internal helpers ----

    fn read_file(&self, file: CgroupFile) -> std::io::Result<String> {
        fs::read_to_string(self.path.join(file.filename()))
    }

    fn write_file(&self, file: CgroupFile, value: &str) -> std::io::Result<()> {
        fs::write(self.path.join(file.filename()), value)
    }

    fn require_controller(&self, controller: CgroupController) -> Result<()> {
        if self.available_controllers.contains(&controller) {
            Ok(())
        } else {
            let available = self
                .available_controllers
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Err(SandboxError::CgroupControllerUnavailable {
                controller: controller.as_str().into(),
                available,
            })
        }
    }

    // ---- Creation ----

    /// Create a new cgroup for a sandbox.
    /// Automatically detects root vs delegated cgroup path.
    pub fn create(sandbox_id: &str, requested: &[CgroupController]) -> Result<Self> {
        let strategy = get_cgroup_strategy();
        match &strategy {
            CgroupStrategy::Root { base } => {
                Self::create_root(base, sandbox_id, requested, strategy.clone())
            }
            CgroupStrategy::Delegated { base } => {
                Self::create_delegated(base, sandbox_id, requested, strategy.clone())
            }
            CgroupStrategy::Unavailable => Err(SandboxError::CgroupCreation(
                "No usable cgroup access. Non-root requires a writable, empty delegated \
                 cgroup v2 parent (for example a pre-prepared scope), or run as root, or omit \
                 unsupported resource limits."
                    .into(),
            )),
        }
    }

    fn create_root(
        base: &Path,
        sandbox_id: &str,
        requested: &[CgroupController],
        strategy: CgroupStrategy,
    ) -> Result<Self> {
        fs::create_dir_all(base).map_err(|e| {
            SandboxError::CgroupCreation(format!("Failed to create base cgroup: {}", e))
        })?;

        let _ = try_enable_controllers(Path::new(CGROUP_ROOT), requested);
        let _ = try_enable_controllers(base, requested);

        let path = base.join(sandbox_id);
        fs::create_dir_all(&path).map_err(|e| {
            SandboxError::CgroupCreation(format!("Failed to create cgroup {}: {}", sandbox_id, e))
        })?;

        let controllers = read_controllers(&path);
        Ok(Self {
            path,
            available_controllers: controllers,
            _strategy: strategy,
        })
    }

    fn create_delegated(
        base: &Path,
        sandbox_id: &str,
        requested: &[CgroupController],
        strategy: CgroupStrategy,
    ) -> Result<Self> {
        let _ = try_enable_controllers(base, requested);

        let nanobox_dir = base.join(NANOBOX_DIR);
        match fs::create_dir(&nanobox_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(SandboxError::CgroupCreation(format!(
                    "Failed to create libsandbox dir: {}",
                    e
                )));
            }
        }
        // Always ensure controllers are enabled in libsandbox/, even if another
        // concurrent sandbox created it and hasn't finished enabling yet.
        let _ = try_enable_controllers(&nanobox_dir, requested);

        let path = nanobox_dir.join(sandbox_id);
        fs::create_dir(&path).map_err(|e| {
            SandboxError::CgroupCreation(format!("Failed to create cgroup {}: {}", sandbox_id, e))
        })?;

        let controllers = read_controllers(&path);
        Ok(Self {
            path,
            available_controllers: controllers,
            _strategy: strategy,
        })
    }

    // ---- Resource limits ----

    /// Set memory limit in bytes
    pub fn set_memory_limit(&self, bytes: u64) -> Result<()> {
        self.require_controller(CgroupController::Memory)?;

        self.write_file(CgroupFile::MemoryMax, &bytes.to_string())
            .map_err(|e| SandboxError::CgroupSetting {
                controller: "memory".into(),
                setting: "max".into(),
                value: bytes.to_string(),
                reason: e.to_string(),
            })?;

        // Soft limit at 90%
        let high = (bytes as f64 * 0.9) as u64;
        let _ = self.write_file(CgroupFile::MemoryHigh, &high.to_string());

        Ok(())
    }

    /// Set CPU limit (0.0 - N.0 where N is number of cores)
    pub fn set_cpu_limit(&self, cpus: f64) -> Result<()> {
        self.require_controller(CgroupController::Cpu)?;

        let period = 100_000u64;
        let quota = (cpus * period as f64) as u64;
        let value = format!("{} {}", quota, period);

        self.write_file(CgroupFile::CpuMax, &value)
            .map_err(|e| SandboxError::CgroupSetting {
                controller: "cpu".into(),
                setting: "max".into(),
                value: value.clone(),
                reason: e.to_string(),
            })?;

        Ok(())
    }

    /// Set maximum number of PIDs
    pub fn set_pids_limit(&self, max: u32) -> Result<()> {
        self.require_controller(CgroupController::Pids)?;

        self.write_file(CgroupFile::PidsMax, &max.to_string())
            .map_err(|e| SandboxError::CgroupSetting {
                controller: "pids".into(),
                setting: "max".into(),
                value: max.to_string(),
                reason: e.to_string(),
            })?;

        Ok(())
    }

    // ---- Process management ----

    /// Add a process to this cgroup
    pub fn add_process(&self, pid: u32) -> Result<()> {
        self.write_file(CgroupFile::Procs, &pid.to_string())
            .map_err(|e| {
                SandboxError::CgroupCreation(format!("Failed to add PID {} to cgroup: {}", pid, e))
            })
    }

    // ---- Statistics ----

    /// Get memory statistics
    pub fn get_memory_stats(&self) -> Result<MemoryStats> {
        let current = self
            .read_file(CgroupFile::MemoryCurrent)
            .map_err(|e| SandboxError::Internal(format!("Failed to read memory.current: {}", e)))?
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        let peak = self
            .read_file(CgroupFile::MemoryPeak)
            .map_err(|e| SandboxError::Internal(format!("Failed to read memory.peak: {}", e)))?
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        Ok(MemoryStats { current, peak })
    }

    /// Get CPU statistics
    pub fn get_cpu_stats(&self) -> Result<CpuStats> {
        let stat = self
            .read_file(CgroupFile::CpuStat)
            .map_err(|e| SandboxError::Internal(format!("Failed to read cpu.stat: {}", e)))?;

        let mut usage_usec = 0u64;
        let mut user_usec = 0u64;
        let mut system_usec = 0u64;

        for line in stat.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "usage_usec" => usage_usec = parts[1].parse().unwrap_or(0),
                    "user_usec" => user_usec = parts[1].parse().unwrap_or(0),
                    "system_usec" => system_usec = parts[1].parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        Ok(CpuStats {
            total_usec: usage_usec,
            user_usec,
            system_usec,
        })
    }

    /// Get memory events (for OOM detection)
    pub fn get_memory_events(&self) -> Result<MemoryEvents> {
        let events = self
            .read_file(CgroupFile::MemoryEvents)
            .map_err(|e| SandboxError::Internal(format!("Failed to read memory.events: {}", e)))?;

        let mut result = MemoryEvents::default();

        for line in events.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "oom" => result.oom = parts[1].parse().unwrap_or(0),
                    "oom_kill" => result.oom_kill = parts[1].parse().unwrap_or(0),
                    "oom_group_kill" => result.oom_group_kill = parts[1].parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        Ok(result)
    }

    /// Check if any process in the cgroup was killed by OOM
    pub fn was_oom_killed(&self) -> bool {
        self.get_memory_events()
            .map(|e| e.oom_kill > 0 || e.oom_group_kill > 0)
            .unwrap_or(false)
    }

    /// Get all PIDs in this cgroup
    pub fn get_pids(&self) -> Vec<u32> {
        self.read_file(CgroupFile::Procs)
            .map(|s| {
                s.lines()
                    .filter_map(|line| line.trim().parse::<u32>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    // ---- Lifecycle ----

    /// Kill all processes in the cgroup
    pub fn kill_all(&self) {
        let _ = self.write_file(CgroupFile::Freeze, "1");

        // 5 iterations × 10 ms = 50 ms max. Processes overwhelmingly die
        // within milliseconds of SIGKILL.
        for _ in 0..5 {
            let pids = self.get_pids();
            if pids.is_empty() {
                break;
            }
            for pid in &pids {
                unsafe {
                    libc::kill(*pid as i32, libc::SIGKILL);
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let _ = self.write_file(CgroupFile::Freeze, "0");
    }

    /// Get the cgroup path
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Clean up the cgroup
    pub fn cleanup(&self) {
        self.kill_all();

        // 20 iterations × 5 ms = 100 ms max drain wait.
        for _ in 0..20 {
            if self.get_pids().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        let _ = fs::remove_dir(&self.path);

        // Keep the shared delegated libsandbox/ parent in place. Removing it when
        // it temporarily looks empty races with concurrent sandbox creation.
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ---- Public helpers ----

/// Check if cgroup v2 is accessible (either as root or via delegation)
pub fn is_cgroup_accessible() -> bool {
    matches!(
        get_cgroup_strategy(),
        CgroupStrategy::Root { .. } | CgroupStrategy::Delegated { .. }
    )
}

/// Check if cgroup v2 is mounted on the system
pub fn is_cgroup_v2_mounted() -> bool {
    Path::new(CGROUP_ROOT)
        .join(CgroupFile::Controllers.filename())
        .exists()
}

/// Probe cgroup support and available controllers for the current process.
pub fn probe_cgroup_support() -> CgroupSupport {
    if !is_cgroup_v2_mounted() {
        return CgroupSupport {
            mounted: false,
            accessible: false,
            available_controllers: Vec::new(),
        };
    }

    match get_cgroup_strategy() {
        CgroupStrategy::Root { .. } => CgroupSupport {
            mounted: true,
            accessible: true,
            available_controllers: read_controllers(Path::new(CGROUP_ROOT)),
        },
        CgroupStrategy::Delegated { base } => CgroupSupport {
            mounted: true,
            accessible: true,
            available_controllers: read_controllers(&base),
        },
        CgroupStrategy::Unavailable => CgroupSupport {
            mounted: true,
            accessible: false,
            available_controllers: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_controller_as_str() {
        assert_eq!(CgroupController::Memory.as_str(), "memory");
        assert_eq!(CgroupController::Cpu.as_str(), "cpu");
        assert_eq!(CgroupController::Pids.as_str(), "pids");
    }

    #[test]
    fn test_cgroup_file_filenames() {
        assert_eq!(CgroupFile::Procs.filename(), "cgroup.procs");
        assert_eq!(CgroupFile::MemoryMax.filename(), "memory.max");
        assert_eq!(CgroupFile::CpuMax.filename(), "cpu.max");
        assert_eq!(CgroupFile::PidsMax.filename(), "pids.max");
        assert_eq!(CgroupFile::Controllers.filename(), "cgroup.controllers");
        assert_eq!(
            CgroupFile::SubtreeControl.filename(),
            "cgroup.subtree_control"
        );
    }
}
