# libsandbox

A Linux-only sandbox primitives library providing namespace isolation, cgroup v2
resource limits, seccomp-BPF syscall filtering, and network isolation for
sandboxed process execution.

[![crates.io](https://img.shields.io/crates/v/libsandbox.svg)](https://crates.io/crates/libsandbox)
[![documentation](https://docs.rs/libsandbox/badge.svg)](https://docs.rs/libsandbox)

## Requirements

libsandbox is Linux-only; it fails to compile on other platforms.

- Linux kernel 5.10+ (cgroup v2 + pidfd); some sub-features such as `cgroup.kill` prefer newer kernels and degrade gracefully on older ones
- x86_64 or aarch64 (for seccomp BPF compilation)
- cgroup v2 mounted at `/sys/fs/cgroup`
- Unprivileged user namespaces enabled (`kernel.unprivileged_userns_clone=1`)
- **MSRV:** Rust 1.78

Probe unprivileged-user-namespace availability at runtime with
`libsandbox::is_supported()`. (This checks userns support only; cgroup v2
availability is validated lazily when a sandbox is configured.)

## What It Provides

- **Namespace isolation** -- user, PID, mount, network, UTS, and IPC namespaces via `clone()`
- **Filesystem isolation** -- bind mounts, tmpfs, optional rootfs with `pivot_root()`; add / remove / remount dynamically in running sandboxes via `MountHandle`
- **Network isolation** -- network namespace with optional HTTP proxy for domain-based whitelisting
- **Resource limits** -- memory, CPU, wall time, CPU time, PID count, FD count via cgroup v2 and rlimit; per-limit enforcement status and metrics surfaced via `ExecutionReport`
- **Seccomp-BPF** -- preset and custom syscall filtering profiles
- **Landlock LSM** *(optional, `landlock` feature)* -- filesystem-access enforcement via the Linux Landlock LSM

All of this runs rootless through user-namespace UID/GID mapping and cgroup v2
delegation. The public surface is a composable builder API (filesystem /
resources / network / security / environment / namespace), and spawned children
accept caller-provided stdio via the `Stdio` enum (pipes, null, inheritance, or
a pre-opened file descriptor such as a PTY slave).

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
println!("{}", result.stdout_lossy());
assert!(result.success());
```

> **Resource limits fail closed.** On hosts without a usable delegated cgroup v2
> parent (the common rootless case), explicitly requested cgroup-backed limits
> error rather than run unbounded. Inspect per-limit status and degradation via
> `sandbox.run_cmd(cmd, args).run_detailed()`.

### Spawn (Persistent Process)

```rust
use libsandbox::Sandbox;

let sandbox = Sandbox::builder().build().unwrap();
let child = sandbox.spawn("bash", &["--login"])?;

// `spawn()` pipes stdout/stderr by default. Calling `wait()` on undrained pipes
// returns `ErrorKind::WouldDeadlock`, so collect output with `wait_with_output()`
// (or read `child.stdout_fd()` concurrently before calling `wait()`). For an
// async wait, enable the `tokio` feature and use `Child::wait_async()`.
let output = child.wait_with_output()?;
println!("exit: {}", output.status.code());
```

## Cargo Features

- `tokio` *(default)* -- enables the HTTP network proxy (`NetworkMode::Proxied`)
  for domain-based whitelisting and `Child::wait_async()`. Disable with
  `--no-default-features` for a pure-sync, no-network build that avoids the tokio
  compile-time and binary-size cost.
- `landlock` *(optional)* -- enables the `landlock` module
  (`prepare_landlock` / `install_landlock` + a `ChildSetup` hook) and widens the
  `Standard` / `Strict` seccomp allowlists with `landlock_restrict_self` so the
  child can enter its domain. Independent of `tokio`.

```toml
# Pure-sync build, no network proxy, plus landlock enforcement:
libsandbox = { version = "0.1", default-features = false, features = ["landlock"] }
```

## Examples

The `examples/` directory demonstrates common usage:

- `agent_composed.rs` -- composed agent sandbox using a `ChildSetup` hook
- `code_judge.rs` -- online-judge style: strict resource limits + security isolation, network disabled
- `custom_process.rs` -- bring-your-own `std::process::Command` using the child-side `prepare_*` / `install_*` primitives
- `demo.rs` -- basic smoke test of `Sandbox::builder()` + `run()`
- `network_allow.rs` -- network domain whitelist via `NetworkConfig::proxied` (requires the `tokio` feature)
- `spawn_demo.rs` -- interactive `spawn()` API (read / write / wait / kill)

Run one with `cargo run --example demo` (add `--features landlock` where needed).

## Documentation

- [API reference (docs.rs)](https://docs.rs/libsandbox)
- [Architecture](docs/ARCHITECTURE.md) -- internal design and implementation details

## Credits

- This project is a fork of [nanosandbox](https://github.com/Erio-Harrison/nanosandbox)
  by Erio Harrison. The code has since been fully rewritten: significant, more
  complex functionality has been added, so the project no longer considers itself
  "nano". All non-Linux platform support was removed to focus on Linux and reduce
  maintenance cost.
- libsandbox is largely driven by the sandboxing needs of
  [just-agent](https://github.com/ImitationGameLabs/just-agent), which serves as
  the primary consumer, providing usage feedback and exercising experimental
  features.
