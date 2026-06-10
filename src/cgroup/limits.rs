//! Cgroup limit planning, enforcement, and resource limit application.
//!
//! Contains the cgroup limit orchestration logic (plan → configure → collect
//! metrics) and the rlimit-based fallback for file size / open files / CPU
//! time limits.

use std::time::Duration;

use crate::builder::SandboxConfig;
use crate::config::{ExecutionPolicy, ResourceEnforcement};
use crate::error::{Result, SandboxError};
use crate::result::{LimitDiagnostics, LimitStatus, MetricDiagnostics, MetricStatus};

use super::{probe_cgroup_support, CgroupController, CgroupManager};

// ---------------------------------------------------------------------------
// Enforcement planning
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnforcementMode {
    NotRequested,
    Strict,
    BestEffort,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LimitPlan {
    pub(crate) memory: EnforcementMode,
    pub(crate) cpu: EnforcementMode,
    pub(crate) pids: EnforcementMode,
}

impl LimitPlan {
    pub(crate) fn from(config: &SandboxConfig, policy: &ExecutionPolicy) -> Self {
        Self {
            memory: limit_mode(
                config.resources.memory_limit.is_some(),
                policy.cgroup_limit_requests.memory,
                policy.resource_enforcement.clone(),
            ),
            cpu: limit_mode(
                config.resources.cpu_limit.is_some(),
                policy.cgroup_limit_requests.cpu,
                policy.resource_enforcement.clone(),
            ),
            pids: limit_mode(
                config.resources.max_pids.is_some(),
                policy.cgroup_limit_requests.pids,
                policy.resource_enforcement.clone(),
            ),
        }
    }

    pub(crate) fn first_strict_limit(&self) -> Option<(&'static str, CgroupController)> {
        if self.memory == EnforcementMode::Strict {
            Some(("memory", CgroupController::Memory))
        } else if self.cpu == EnforcementMode::Strict {
            Some(("cpu", CgroupController::Cpu))
        } else if self.pids == EnforcementMode::Strict {
            Some(("pids", CgroupController::Pids))
        } else {
            None
        }
    }

    pub(crate) fn requested_controllers(&self) -> Vec<CgroupController> {
        let mut requested = Vec::new();
        if self.memory != EnforcementMode::NotRequested {
            requested.push(CgroupController::Memory);
        }
        if self.cpu != EnforcementMode::NotRequested {
            requested.push(CgroupController::Cpu);
        }
        if self.pids != EnforcementMode::NotRequested {
            requested.push(CgroupController::Pids);
        }
        requested
    }
}

fn limit_mode(
    configured: bool,
    explicit: bool,
    enforcement: ResourceEnforcement,
) -> EnforcementMode {
    if !configured {
        EnforcementMode::NotRequested
    } else if explicit && enforcement == ResourceEnforcement::Strict {
        EnforcementMode::Strict
    } else {
        EnforcementMode::BestEffort
    }
}

// ---------------------------------------------------------------------------
// Cgroup configuration
// ---------------------------------------------------------------------------

pub(crate) fn needs_cgroup(config: &SandboxConfig) -> bool {
    config.resources.memory_limit.is_some()
        || config.resources.cpu_limit.is_some()
        || config.resources.max_pids.is_some()
}

pub(crate) fn configure_cgroup(
    config: &SandboxConfig,
    limit_plan: &LimitPlan,
    sandbox_id: &str,
    child_pid: u32,
) -> Result<(Option<CgroupManager>, LimitDiagnostics)> {
    let support = probe_cgroup_support();
    let requested_controllers = limit_plan.requested_controllers();
    let require_rootless_memory = rootless_memory_required(config);
    let mut diagnostics = LimitDiagnostics {
        memory: limit_status(limit_plan.memory),
        cpu: limit_status(limit_plan.cpu),
        pids: limit_status(limit_plan.pids),
    };

    if !support.mounted || !support.accessible {
        if require_rootless_memory {
            return Err(SandboxError::ResourceLimitUnavailable {
                limit: "memory".into(),
                reason: support.unavailable_reason(Some(CgroupController::Memory)),
            });
        }
        if let Some((limit, controller)) = limit_plan.first_strict_limit() {
            return Err(SandboxError::ResourceLimitUnavailable {
                limit: limit.into(),
                reason: support.unavailable_reason(Some(controller)),
            });
        }

        let reason = support.unavailable_reason(None);
        set_best_effort_unavailable(&mut diagnostics, *limit_plan, &reason);
        return Ok((None, diagnostics));
    }

    let cg = match CgroupManager::create(sandbox_id, &requested_controllers) {
        Ok(cg) => cg,
        Err(e) => {
            let reason = format!("failed to create cgroup: {e}");
            if require_rootless_memory {
                return Err(SandboxError::ResourceLimitUnavailable {
                    limit: "memory".into(),
                    reason,
                });
            }
            if let Some((limit, _)) = limit_plan.first_strict_limit() {
                return Err(SandboxError::ResourceLimitUnavailable {
                    limit: limit.into(),
                    reason,
                });
            }

            set_best_effort_unavailable(&mut diagnostics, *limit_plan, &reason);
            return Ok((None, diagnostics));
        }
    };

    let mut memory_configured = false;
    let mut cpu_configured = false;
    let mut pids_configured = false;

    if let Some(memory) = config.resources.memory_limit {
        match cg.set_memory_limit(memory) {
            Ok(()) => memory_configured = true,
            Err(e) => {
                if require_rootless_memory {
                    return Err(SandboxError::ResourceLimitUnavailable {
                        limit: "memory".into(),
                        reason: e.to_string(),
                    });
                }
                handle_limit_error(
                    &mut diagnostics.memory,
                    limit_plan.memory,
                    "memory",
                    e.to_string(),
                )?
            }
        }
    }

    if let Some(cpu) = config.resources.cpu_limit {
        match cg.set_cpu_limit(cpu) {
            Ok(()) => cpu_configured = true,
            Err(e) => {
                handle_limit_error(&mut diagnostics.cpu, limit_plan.cpu, "cpu", e.to_string())?
            }
        }
    }

    if let Some(pids) = config.resources.max_pids {
        match cg.set_pids_limit(pids) {
            Ok(()) => pids_configured = true,
            Err(e) => handle_limit_error(
                &mut diagnostics.pids,
                limit_plan.pids,
                "pids",
                e.to_string(),
            )?,
        }
    }

    if let Err(e) = cg.add_process(child_pid) {
        let reason = format!("failed to add process to cgroup: {e}");
        if require_rootless_memory {
            cg.cleanup();
            return Err(SandboxError::ResourceLimitUnavailable {
                limit: "memory".into(),
                reason,
            });
        }
        if let Some((limit, _)) = limit_plan.first_strict_limit() {
            cg.cleanup();
            return Err(SandboxError::ResourceLimitUnavailable {
                limit: limit.into(),
                reason,
            });
        }

        if memory_configured {
            diagnostics.memory = LimitStatus::NotEnforced {
                reason: reason.clone(),
            };
        }
        if cpu_configured {
            diagnostics.cpu = LimitStatus::NotEnforced {
                reason: reason.clone(),
            };
        }
        if pids_configured {
            diagnostics.pids = LimitStatus::NotEnforced { reason };
        }
        cg.cleanup();
        return Ok((None, diagnostics));
    }

    if memory_configured {
        diagnostics.memory = LimitStatus::Enforced;
    }
    if cpu_configured {
        diagnostics.cpu = LimitStatus::Enforced;
    }
    if pids_configured {
        diagnostics.pids = LimitStatus::Enforced;
    }

    Ok((Some(cg), diagnostics))
}

fn rootless_memory_required(config: &SandboxConfig) -> bool {
    config.resources.memory_limit.is_some() && !nix::unistd::geteuid().is_root()
}

fn limit_status(mode: EnforcementMode) -> LimitStatus {
    match mode {
        EnforcementMode::NotRequested => LimitStatus::NotRequested,
        EnforcementMode::Strict | EnforcementMode::BestEffort => LimitStatus::Unknown {
            reason: "Limit requested but not evaluated yet".into(),
        },
    }
}

fn handle_limit_error(
    status: &mut LimitStatus,
    mode: EnforcementMode,
    limit: &'static str,
    reason: String,
) -> Result<()> {
    match mode {
        EnforcementMode::Strict => Err(SandboxError::ResourceLimitUnavailable {
            limit: limit.into(),
            reason,
        }),
        EnforcementMode::BestEffort => {
            *status = LimitStatus::NotEnforced { reason };
            Ok(())
        }
        EnforcementMode::NotRequested => Ok(()),
    }
}

fn set_best_effort_unavailable(
    diagnostics: &mut LimitDiagnostics,
    limit_plan: LimitPlan,
    reason: &str,
) {
    if limit_plan.memory == EnforcementMode::BestEffort {
        diagnostics.memory = LimitStatus::NotEnforced {
            reason: reason.into(),
        };
    }
    if limit_plan.cpu == EnforcementMode::BestEffort {
        diagnostics.cpu = LimitStatus::NotEnforced {
            reason: reason.into(),
        };
    }
    if limit_plan.pids == EnforcementMode::BestEffort {
        diagnostics.pids = LimitStatus::NotEnforced {
            reason: reason.into(),
        };
    }
}

// ---------------------------------------------------------------------------
// Metrics collection
// ---------------------------------------------------------------------------

pub(crate) fn collect_linux_metrics(
    cgroup: Option<&CgroupManager>,
) -> (Option<u64>, Option<Duration>, bool, MetricDiagnostics) {
    if let Some(cg) = cgroup {
        let (peak_memory, peak_status) = match cg.get_memory_stats() {
            Ok(stats) => (Some(stats.peak), MetricStatus::Collected),
            Err(e) => (
                None,
                MetricStatus::Unavailable {
                    reason: e.to_string(),
                },
            ),
        };
        let (cpu_time, cpu_status) = match cg.get_cpu_stats() {
            Ok(stats) => (
                Some(Duration::from_micros(stats.total_usec)),
                MetricStatus::Collected,
            ),
            Err(e) => (
                None,
                MetricStatus::Unavailable {
                    reason: e.to_string(),
                },
            ),
        };

        (
            peak_memory,
            cpu_time,
            cg.was_oom_killed(),
            MetricDiagnostics {
                peak_memory: peak_status,
                cpu_time: cpu_status,
            },
        )
    } else {
        (
            None,
            None,
            false,
            MetricDiagnostics {
                peak_memory: MetricStatus::Unavailable {
                    reason:
                        "peak memory collection requires a cgroup-backed execution path on Linux"
                            .into(),
                },
                cpu_time: MetricStatus::Unavailable {
                    reason: "cpu time collection requires a cgroup-backed execution path on Linux"
                        .into(),
                },
            },
        )
    }
}

// ---------------------------------------------------------------------------
// rlimit-based resource limits (applied inside the child)
// ---------------------------------------------------------------------------

pub(crate) fn apply_resource_limits(config: &SandboxConfig) {
    if let Some(max_files) = config.resources.max_open_files {
        let rlim = libc::rlimit {
            rlim_cur: max_files as libc::rlim_t,
            rlim_max: max_files as libc::rlim_t,
        };
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
        }
    }

    if let Some(max_file_size) = config.resources.max_file_size {
        let rlim = libc::rlimit {
            rlim_cur: max_file_size as libc::rlim_t,
            rlim_max: max_file_size as libc::rlim_t,
        };
        unsafe {
            libc::setrlimit(libc::RLIMIT_FSIZE, &rlim);
        }
    }

    if let Some(cpu_time) = config.resources.cpu_time_limit {
        let secs = cpu_time.as_secs();
        if secs > 0 {
            let rlim = libc::rlimit {
                rlim_cur: secs as libc::rlim_t,
                rlim_max: secs as libc::rlim_t,
            };
            unsafe {
                libc::setrlimit(libc::RLIMIT_CPU, &rlim);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CgroupLimitRequests, ResourceConfig};

    #[test]
    fn test_limit_plan_requested_controllers() {
        let config = SandboxConfig {
            resources: ResourceConfig::builder()
                .memory_limit(1)
                .max_pids(5)
                .build()
                .unwrap(),
            ..SandboxConfig::default()
        };
        let plan = LimitPlan::from(
            &config,
            &ExecutionPolicy {
                resource_enforcement: ResourceEnforcement::BestEffort,
                cgroup_limit_requests: CgroupLimitRequests {
                    memory: true,
                    cpu: false,
                    pids: true,
                },
            },
        );

        assert_eq!(
            plan.requested_controllers(),
            vec![CgroupController::Memory, CgroupController::Pids]
        );
    }
}
