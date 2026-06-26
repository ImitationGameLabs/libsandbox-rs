//! Composed agent sandbox with a `child_setup` hook.
//!
//! Demonstrates the v0.2 extensibility seam: a caller-supplied
//! [`ChildSetup`](libsandbox::ChildSetup) hook runs inside the sandboxed child
//! after seccomp install and before `exec`. This is exactly the hook an agent
//! runtime (e.g. just-agent) uses to layer its own setup (landlock, privilege
//! drop, extra mounts) onto a sandboxed child without forking libsandbox's
//! spawn pipeline.
//!
//! Run with: cargo run --example agent_composed

use libsandbox::config::{
    FilesystemConfig, ResourceConfig, ResourceEnforcement, SeccompProfile, SecurityConfig,
};
use libsandbox::Sandbox;
use std::time::Duration;

fn main() {
    println!("=== Composed Agent + child_setup hook ===\n");

    let workspace = std::env::temp_dir().join("libsandbox_agent_composed");
    std::fs::create_dir_all(&workspace).unwrap();
    let _ = &workspace; // kept for a real agent; this demo runs in /tmp.

    // Compose the sandbox configuration explicitly via the builder — presets
    // were removed in v0.2 in favor of explicit composition. Uses /tmp (which
    // exists) as the working dir so the demo runs rootless without a bind
    // mount to a host path that may not exist.
    let sandbox = Sandbox::builder()
        .filesystem(
            FilesystemConfig::builder()
                .tmpfs("/tmp", 256 * 1024 * 1024)
                .working_dir("/tmp")
                .build()
                .unwrap(),
        )
        .resources(
            ResourceConfig::builder()
                .wall_time_limit(Duration::from_secs(10))
                .max_pids(64)
                // Best-effort so the example builds/runs even without a
                // delegated cgroup (cold rootless environments).
                .resource_enforcement(ResourceEnforcement::BestEffort)
                .build()
                .unwrap(),
        )
        .security(
            SecurityConfig::builder()
                .seccomp_profile(SeccompProfile::Standard)
                .build()
                .unwrap(),
        )
        .build()
        .expect("failed to build sandbox");

    // Spawn a child with a `child_setup` hook. The hook runs in the child
    // after seccomp is installed and before exec — here it just emits a marker
    // to stderr showing the hook executed with the resolved child context.
    // (A real agent runtime would install landlock / drop privileges here.)
    let mut child = sandbox
        .build_spawn("sh", &["-c", "echo hello from the sandboxed child"])
        .child_setup(|ctx| {
            // This runs INSIDE the sandboxed child, post-seccomp, pre-exec.
            eprintln!(
                "[child_setup hook] ran in child: mapped uid={}, has_mount_ns={}",
                ctx.uid, ctx.has_mount_ns
            );
            Ok(())
        })
        .start()
        .expect("spawn failed");

    // Drain stdout/stderr to avoid pipe-buffer deadlock, then wait.
    let stdout = child.take_stdout_fd();
    let stderr = child.take_stderr_fd();
    if let Some(fd) = stdout {
        use std::io::Read;
        let mut buf = String::new();
        let _ = std::fs::File::from(fd).read_to_string(&mut buf);
        print!("{buf}");
    }
    if let Some(fd) = stderr {
        use std::io::Read;
        let mut buf = String::new();
        let _ = std::fs::File::from(fd).read_to_string(&mut buf);
        eprint!("{buf}");
    }
    let status = child.wait().expect("wait failed");
    println!("\nchild exit: {status}");

    std::fs::remove_dir_all(&workspace).ok();
    println!("\n=== done ===");
}
