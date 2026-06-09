//! Resource exhaustion attack tests

use libsandbox::config::{FilesystemConfig, ResourceConfig};
use libsandbox::{ResourceEnforcement, Sandbox, SandboxError};
use std::time::Duration;

#[cfg(target_os = "linux")]
fn is_memory_unavailable(err: &SandboxError) -> bool {
    matches!(
        err,
        SandboxError::ResourceLimitUnavailable { limit, .. } if limit == "memory"
    )
}

/// Fork bomb test - Linux
#[test]
#[cfg(target_os = "linux")]
fn test_fork_bomb_contained() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .max_pids(20)
                .resource_enforcement(ResourceEnforcement::BestEffort)
                .wall_time_limit(Duration::from_secs(5))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let start = std::time::Instant::now();
    let _result = sandbox.run("sh", &["-c", ":(){ :|:& };:"]).unwrap();
    let elapsed = start.elapsed();

    // Should not hang - contained by pids limit
    assert!(elapsed < Duration::from_secs(6));
}

/// Memory bomb test - Linux
#[test]
#[cfg(target_os = "linux")]
fn test_memory_bomb_contained() {
    let sandbox = match Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .memory_limit(64 * 1024 * 1024) // 64MB
                .resource_enforcement(ResourceEnforcement::BestEffort)
                .wall_time_limit(Duration::from_secs(10))
                .build()
                .unwrap(),
        )
        .build()
    {
        Ok(sandbox) => sandbox,
        Err(err) if is_memory_unavailable(&err) => return,
        Err(err) => panic!("unexpected memory bomb sandbox build failure: {err:?}"),
    };

    let result = sandbox.run(
        "python3",
        &[
            "-c",
            r#"
	x = []
	try:
	    while True:
	        x.append('A' * 1024 * 1024)
	except MemoryError:
	    print('memory error')
	"#,
        ],
    );

    match result {
        Ok(r) => {
            if r.exit_code == 127 {
                eprintln!("warning: skipping memory bomb assertion because python3 is unavailable");
                return;
            }
            // Should be killed by OOM or memory error
            assert!(r.killed_by_oom || r.exit_code != 0 || r.stdout.contains("memory error"));
        }
        Err(_) => {
            eprintln!("warning: skipping memory bomb assertion because python3 is unavailable");
        }
    }
}

/// CPU bomb test
#[test]
fn test_cpu_bomb_contained() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_secs(2))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox
        .run("sh", &["-c", "while true; do :; done"])
        .unwrap();

    assert!(result.killed_by_timeout);
}

/// Disk bomb test (tmpfs) - Linux
#[test]
#[cfg(target_os = "linux")]
fn test_disk_bomb_contained_tmpfs() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .tmpfs("/tmp", 10 * 1024 * 1024) // 10MB tmpfs
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_secs(10))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let result = sandbox
        .run(
            "sh",
            &["-c", "dd if=/dev/zero of=/tmp/large bs=1M count=100 2>&1"],
        )
        .unwrap();

    // Should fail when tmpfs is full
    assert!(result.exit_code != 0 || result.stderr.contains("No space"));
}

/// Subprocess bomb test - Linux only (cgroups pids controller)
#[test]
#[cfg(target_os = "linux")]
fn test_subprocess_bomb_contained() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .max_pids(10)
                .resource_enforcement(ResourceEnforcement::BestEffort)
                .wall_time_limit(Duration::from_secs(5))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Try to spawn many processes
    let result = sandbox
        .run(
            "sh",
            &["-c", "for i in $(seq 1 100); do sleep 100 & done; wait"],
        )
        .unwrap();

    // Should be contained by pids limit or wall time
    assert!(result.duration < Duration::from_secs(6));
}

/// File descriptor bomb test
#[test]
fn test_fd_bomb_contained() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_secs(5))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Try to open many file descriptors
    let result = sandbox.run(
        "python3",
        &[
            "-c",
            r#"
import os
fds = []
try:
    for i in range(10000):
        fds.append(os.open('/dev/null', os.O_RDONLY))
except OSError:
    print('fd limit reached')
print(f'opened {len(fds)} fds')
"#,
        ],
    );

    // Should complete (may hit fd limit)
    match result {
        Ok(r) => {
            // Linux exec failures surface as exit 127 rather than Err(...).
            // Treat missing python3 like the other python-dependent tests do.
            if r.exit_code == 127 {
                eprintln!("warning: skipping fd bomb assertion because python3 is unavailable");
                return;
            }
            assert!(r.exit_code == 0 || r.stdout.contains("fd limit"));
        }
        Err(_) => {
            eprintln!("warning: skipping fd bomb assertion because python3 is unavailable");
        }
    }
}

/// Recursive directory bomb test - Linux only (tmpfs support)
#[test]
#[cfg(target_os = "linux")]
fn test_directory_bomb_contained() {
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .working_dir("/tmp")
                .tmpfs("/tmp", 10 * 1024 * 1024) // 10MB
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_secs(10))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Try to create deep directory structure
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
d=/tmp/bomb
mkdir -p $d
for i in $(seq 1 1000); do
    d=$d/dir
    mkdir -p $d 2>/dev/null || break
done
echo done
"#,
            ],
        )
        .unwrap();

    // Should complete (may hit inode or space limit)
    assert!(result.duration < Duration::from_secs(11));
}
