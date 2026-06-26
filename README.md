# libsandbox

A Linux-only sandbox primitives library providing namespace isolation, cgroup v2 resource limits, seccomp-BPF syscall filtering, and network isolation for sandboxed process execution.

## What It Provides

- **Namespace isolation** -- user, PID, mount, network, UTS, and IPC namespaces via `clone()`
- **Filesystem isolation** -- bind mounts, tmpfs, optional rootfs with `pivot_root()`
- **Resource limits** -- memory, CPU, wall time, CPU time, PID count, FD count via cgroup v2 and rlimit
- **Seccomp-BPF** -- preset and custom syscall filtering profiles
- **Network isolation** -- network namespace with optional HTTP proxy for domain-based whitelisting

## What It Does NOT Do

libsandbox is a **primitives library**, not a container runtime or session manager. It does not provide:

- PTY management, shell sessions, or interactive terminal handling
- Authorization policies or scope revision tracking
- Cross-platform support (Linux only; kernel 5.10+)
- Language bindings (Python, Node.js, etc.)

Consumers (such as AI agent runtimes) are expected to layer their own orchestration on top of the spawn API.

## Quick Start

### One-Shot Execution

```rust
use libsandbox::{Sandbox, Permission, MB};
use libsandbox::config::{FilesystemConfig, ResourceConfig, NetworkConfig};
use std::time::Duration;

let sandbox = Sandbox::builder()
    .filesystem(
        FilesystemConfig::builder()
            .mount("/data/input", "/input", Permission::ReadOnly)
            .working_dir("/tmp")
            .build()
            .unwrap()
    )
    .resources(
        ResourceConfig::builder()
            .memory_limit(256 * MB)
            .wall_time_limit(Duration::from_secs(30))
            .build()
            .unwrap()
    )
    .network(NetworkConfig::none())
    .build()
    .unwrap();

let result = sandbox.run("python3", &["-c", "print(\"hello\")"])?;
assert!(result.success());
```

### Spawn (Persistent Process)

```rust
use libsandbox::{Sandbox, Stdio};

let sandbox = Sandbox::builder().build().unwrap();
let child = sandbox.spawn("bash", &["--login"])?;
// interact via child.stdout_fd(), child.stdin_fd(), etc.
let status = child.wait()?;
println!("exit: {}", status.code());
```

## Feature Highlights

- **Rootless operation** -- user namespace UID/GID mapping + cgroup v2 delegation
- **Composable domain configs** -- filesystem / resources / network / security / environment / namespace builders
- **Caller-provided stdio** -- `Stdio` enum supports pipes, inheritance, null, and owned FDs (e.g., PTY slave)
- **Dynamic mounts** -- add, remove, and remount in running sandboxes via `MountHandle`
- **Execution diagnostics** -- `ExecutionReport` provides per-limit enforcement status and metric collection status

## Requirements

- Linux kernel 5.10+ (for cgroup v2 and pidfd)
- x86_64 or aarch64 (for seccomp BPF compilation)
- cgroup v2 mounted at `/sys/fs/cgroup`
- Unprivileged user namespaces enabled (`kernel.unprivileged_userns_clone=1`)

## Building

```bash
cargo build
cargo test
cargo bench
```

Tests require the kernel prerequisites listed above.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) -- internal design and implementation details
- [Benchmarks](docs/BENCHMARKS.md) -- performance data and comparisons

## Attribution

This project is based on [nanosandbox](https://github.com/Erio-Harrison/nanosandbox) by Erio Harrison.
