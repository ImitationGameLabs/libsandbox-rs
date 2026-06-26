//! Cgroup v2 management for Linux.
//!
//! Provides resource limiting using cgroups v2 with rootless support.

mod limits;
mod manager;
mod strategy;

// ---- Shared constants ----

pub(super) const CGROUP_ROOT: &str = "/sys/fs/cgroup";
pub(super) const NANOBOX_DIR: &str = "libsandbox";

// ---- Shared types (used by submodules) ----

/// Cgroup controllers used for resource limiting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupController {
    /// The memory controller (`memory.current` / `memory.max`).
    Memory,
    /// The CPU controller (`cpu.max`).
    Cpu,
    /// The pids controller (`pids.max`).
    Pids,
}

impl CgroupController {
    /// Lowercase cgroup name of this controller (`"memory"` / `"cpu"` / `"pids"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Cpu => "cpu",
            Self::Pids => "pids",
        }
    }
}

/// Well-known cgroup v2 control files
#[derive(Debug, Clone, Copy)]
pub(super) enum CgroupFile {
    Procs,
    Controllers,
    SubtreeControl,
    MemoryMax,
    MemoryHigh,
    MemoryCurrent,
    MemoryPeak,
    MemoryEvents,
    CpuMax,
    CpuStat,
    PidsMax,
    Freeze,
    /// `cgroup.kill` (kernel ≥5.14): writing "1" atomically kills every
    /// process in the cgroup.
    Kill,
}

impl CgroupFile {
    pub(super) fn filename(&self) -> &'static str {
        match self {
            Self::Procs => "cgroup.procs",
            Self::Controllers => "cgroup.controllers",
            Self::SubtreeControl => "cgroup.subtree_control",
            Self::MemoryMax => "memory.max",
            Self::MemoryHigh => "memory.high",
            Self::MemoryCurrent => "memory.current",
            Self::MemoryPeak => "memory.peak",
            Self::MemoryEvents => "memory.events",
            Self::CpuMax => "cpu.max",
            Self::CpuStat => "cpu.stat",
            Self::PidsMax => "pids.max",
            Self::Freeze => "cgroup.freeze",
            Self::Kill => "cgroup.kill",
        }
    }
}

// ---- Re-exports ----

pub use manager::{
    is_cgroup_accessible, is_cgroup_v2_mounted, probe_cgroup_support, CgroupManager, CgroupSupport,
    CpuStats, MemoryEvents, MemoryStats,
};

pub(crate) use limits::{collect_linux_metrics, configure_cgroup, needs_cgroup, LimitPlan};
