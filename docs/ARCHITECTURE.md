# libsandbox Architecture

## Overview

libsandbox is a Linux-only sandbox primitives library written in Rust. It provides process isolation through kernel namespaces, resource limits through cgroup v2, syscall filtering through seccomp-BPF, and network isolation through network namespaces with an optional HTTP proxy. The library is designed as a building block -- it does not manage PTYs, shell sessions, or authorization policies. Consumers (such as `just-agent`) are expected to layer their own orchestration on top.

## Layered Design

The library is structured in three layers:

**Public API layer** -- the types and methods that consumers interact with directly: `Sandbox`, `SandboxBuilder`, `SpawnBuilder`, `Child`, `Stdio`, `ExecutionResult`, `ExecutionReport`, and the preset factory methods (`code_judge`, `agent_executor`, etc.). Defined in `src/sandbox.rs` and `src/builder.rs`.

**Configuration layer** -- domain-specific builders that produce validated configuration structs. Each domain (filesystem, resources, network, security, environment) has its own builder and config type. The top-level `SandboxBuilder` aggregates these domain configs into a single `SandboxConfig`. Defined in `src/config/`.

**Implementation layer** -- a concrete `LinuxExecutor` struct (not a trait) that carries out sandbox creation via `clone()` with namespace flags, cgroup setup, mount namespace construction, seccomp filter loading, and network proxy management. Defined in `src/executor.rs`, `src/process/`, `src/cgroup/`, `src/mount/`, `src/namespace.rs`, `src/seccomp/`, and `src/network/`.

## Configuration Architecture

`SandboxConfig` is a composition of five domain config structs:

```rust
pub struct SandboxConfig {
    pub filesystem: FilesystemConfig,   // mounts, tmpfs, working_dir, rootfs
    pub resources: ResourceConfig,      // memory, cpu, time, pid, fd limits
    pub network: NetworkConfig,         // None, Host, or Proxied
    pub security: SecurityConfig,       // seccomp profile, uid/gid
    pub environment: EnvironmentConfig, // env vars, hostname
}
```

`SandboxBuilder` consumes domain configs via methods that each accept a complete, validated domain struct:

```rust
Sandbox::builder()
    .filesystem(filesystem_config)
    .resources(resource_config)
    .network(network_config)
    .security(security_config)
    .environment(environment_config)
    .build()
```

Each domain has its own builder with per-field validation. For example, `ResourceBuilder` rejects zero or negative limits at `build()` time. The preset factory methods (`Sandbox::code_judge`, `Sandbox::agent_executor`, etc.) return a `SandboxBuilder` pre-configured with sensible defaults for each use case; callers can override specific domains by passing a replacement config.

This design replaces the earlier flat builder where all options were methods on a single builder type. The domain separation ensures that related options are grouped, validated together, and can be reasoned about independently.

## Namespace Isolation

libsandbox uses six Linux namespace types to isolate sandboxed processes:

| Namespace | Clone Flag      | Purpose                                                  |
| --------- | --------------- | -------------------------------------------------------- |
| User      | `CLONE_NEWUSER` | UID/GID mapping, enables rootless operation              |
| PID       | `CLONE_NEWPID`  | Process ID isolation; child becomes PID 1                |
| Mount     | `CLONE_NEWNS`   | Private mount table; pivot_root for filesystem isolation |
| Network   | `CLONE_NEWNET`  | Empty network stack (no interfaces by default)           |
| UTS       | `CLONE_NEWUTS`  | Hostname isolation                                       |
| IPC       | `CLONE_NEWIPC`  | Isolation of System V IPC and POSIX message queues       |

Implementation is in `src/namespace.rs` (user and UTS namespace setup) and `src/process/spawn.rs` (clone orchestration).

### User Namespace

User namespace is the most important for rootless operation. It maps the host user's UID/GID to UID 0 (root) inside the sandbox. The mapping is written to `/proc/{pid}/uid_map` and `/proc/{pid}/gid_map` after `clone()` returns. `setgroups` is denied via `/proc/{pid}/setgroups` to prevent privilege escalation.

### Mount Namespace

The mount namespace provides filesystem isolation through a three-step process:

1. **Private propagation** -- `mount(None, "/", None, MS_REC | MS_PRIVATE, None)` makes all mount events private to the new namespace.
2. **Root filesystem** -- if `rootfs` is configured, the builder bind-mounts it and calls `pivot_root()` to make it the new root. The old root is unmounted with `MNT_DETACH`.
3. **User mounts** -- bind mounts and tmpfs mounts from `FilesystemConfig` are applied after pivot. `/proc` is mounted automatically.

The mount operations module (`src/mount/ops.rs`) handles recursive bind mounts with correct propagation flags. Mount validation (`src/mount/validation.rs`) rejects path traversal and unsafe mount targets.

## Cgroup v2 Resource Management

libsandbox uses cgroup v2 to enforce resource limits. The `CgroupManager` (`src/cgroup/manager.rs`) manages the full cgroup lifecycle:

**Creation** -- a cgroup directory is created under a delegated parent path. For rootful operation, this is `/sys/fs/cgroup/libsandbox-{id}/`. For rootless operation, the manager discovers the systemd-delegated subtree by reading `/proc/self/cgroup` and creates sandbox cgroups under it.

**Limit application** -- the manager writes to cgroup control files:

| Controller | File          | Purpose                                                |
| ---------- | ------------- | ------------------------------------------------------ |
| memory     | `memory.max`  | Hard memory limit (bytes)                              |
| memory     | `memory.high` | Soft limit (90% of max, triggers reclaim)              |
| cpu        | `cpu.max`     | CPU quota/period (e.g., "150000 100000" for 1.5 cores) |
| pids       | `pids.max`    | Maximum process count                                  |

**Process assignment** -- the child PID is written to `cgroup.procs`.

**Metric collection** -- before cleanup, the manager reads:

- `memory.peak` for peak memory usage
- `cpu.stat` (`usage_usec`) for CPU time
- `memory.events` (`oom_kill` counter) for OOM detection

**Cleanup** -- the manager freezes the cgroup (`cgroup.freeze`), sends SIGKILL to all processes, waits briefly, and removes the cgroup directory.

### Rootless Operation

Rootless cgroup support is implemented through a strategy abstraction (`src/cgroup/strategy.rs`). On startup, the manager probes for a usable cgroup v2 delegation:

1. Read `/proc/self/cgroup` to find the current cgroup path.
2. Check if `cgroup.subtree_control` is writable (indicates delegation).
3. If delegated, create sandbox cgroups under the current cgroup path.
4. If not delegated and no limits are set, skip cgroup entirely.
5. If not delegated but limits are requested, the behavior depends on `ResourceEnforcement`.

### Resource Enforcement

`ResourceEnforcement` controls how the library handles limits that cannot be enforced:

- **Strict** (default) -- fail closed. If a requested limit cannot be set (e.g., no cgroup delegation), the operation returns an error.
- **BestEffort** -- degrade gracefully. Limits that cannot be set are skipped, and the degradation is reported via `ExecutionDiagnostics` (see the Diagnostics section).

The `CgroupLimitRequests` struct tracks which controllers are actually needed based on the limits configured in `ResourceConfig`. The `ExecutionPolicy` bundles enforcement mode and limit requests.

## Seccomp-BPF Filtering

libsandbox compiles declarative syscall rules into classic BPF (cBPF) programs loaded via the `seccomp(2)` syscall. The pipeline is:

1. **Build rules** -- `SeccompFilterBuilder` collects rules via methods like `allow(syscall)`, `deny(syscall)` (applies `KillProcess`), `deny_with_errno(syscall, errno)`, and `log(syscall)`. Internally, each rule pairs a syscall number with one of six actions (`Allow`, `KillProcess`, `KillThread`, `Trap`, `Errno(n)`, `Log`). The builder also supports `default_action(action)` to set the action for unmatched syscalls.
2. **Compile to BPF** -- the builder produces a sorted jump table of BPF instructions. The program first validates the architecture (x86_64), then binary-searches the syscall number.
3. **Load** -- `PR_SET_NO_NEW_PRIVS` is set first (prevents privilege escalation), then `seccomp(2)` installs the filter.

### Preset Profiles

Four preset profiles are provided via `SeccompProfile`:

| Profile    | Description                                     |
| ---------- | ----------------------------------------------- |
| Strict     | Minimal syscall set; for compute-only workloads |
| Standard   | Common safe syscalls for typical programs       |
| Permissive | Most syscalls allowed; dangerous ones blocked   |
| Disabled   | No seccomp filter installed                     |

The `Custom(SeccompFilter)` variant accepts a manually constructed filter for fine-grained control.

**Current status:** The BPF compilation pipeline is structurally complete and produces valid programs on x86_64. Enforcement effectiveness depends on the completeness of each preset's syscall list. See `src/seccomp/` for implementation details.

## Network Isolation

Three network modes are available via `NetworkMode`:

**None** (default) -- the sandbox runs in a new network namespace with no interfaces. All network access is blocked.

**Host** -- the sandbox shares the host's network namespace. No isolation is applied.

**Proxied** -- the sandbox runs in a new network namespace, but a veth pair connects it to the host. An HTTP proxy running in the parent process filters outbound connections by domain. The proxy supports exact matches (e.g., `api.example.com`) and wildcard subdomains (e.g., `*.example.com`). The child receives `HTTP_PROXY` and `HTTPS_PROXY` environment variables pointing to the proxy.

**Known limitation:** Direct IP address connections bypass the proxy since it operates at the HTTP layer. Mitigation requires iptables/nftables rules at the network namespace level. Implementation is in `src/network/`.

## One-Shot Execution (run)

The `run()`, `run_with_input()`, `run_detailed()`, and `run_with_input_detailed()` methods provide one-shot command execution. Internally, they are thin wrappers around the spawn API:

1. Spawn the child process with `Stdio::Pipe` for stdout/stderr (and optionally stdin).
2. Write stdin data if provided.
3. Wait with the configured wall-time limit.
4. Read stdout and stderr from the pipes.
5. Collect metrics from the cgroup.
6. Clean up the cgroup.
7. Return `ExecutionResult` (or `ExecutionReport` for the `_detailed` variants).

The flow is implemented in `src/executor.rs` and `src/process/wait.rs`.

## Spawn Execution (spawn)

The `spawn()` and `build_spawn()` methods provide persistent child process handles:

1. `Sandbox::spawn(cmd, args)` creates a `Child` with default stdio (stdin: Null, stdout: Pipe, stderr: Pipe).
2. `Sandbox::build_spawn(cmd, args)` returns a `SpawnBuilder` for custom stdio configuration.
3. `SpawnBuilder::start()` performs the actual `clone()` and returns a `Child` handle.

### Child Handle

`Child` (defined in `src/process/child.rs`) owns the sandboxed process and its resources:

- **PID and pidfd** -- the child's process ID and, on Linux 5.3+, a pidfd file descriptor for race-free signal delivery.
- **Stdio pipes** -- parent-end file descriptors for stdin, stdout, and stderr (when `Stdio::Pipe` is used).
- **Cgroup manager** -- the cgroup instance for this sandbox, available for metric collection.
- **Proxy guard** -- keeps the HTTP proxy alive for the child's lifetime.
- **Namespace fds** -- file descriptors for the user and mount namespaces, enabling dynamic mount operations.

Key methods on `Child`:

| Method                                                      | Description                                   |
| ----------------------------------------------------------- | --------------------------------------------- |
| `pid()`                                                     | Child PID in the parent's PID namespace       |
| `stdin_fd()` / `stdout_fd()` / `stderr_fd()`                | Parent-end pipe fds                           |
| `cgroup()`                                                  | Access the cgroup for metric collection       |
| `mount_handle()`                                            | Obtain a `MountHandle` for dynamic mounts     |
| `kill()`                                                    | SIGKILL via pidfd (or process group fallback) |
| `try_wait()`                                                | Non-blocking exit check                       |
| `wait(self)`                                                | Blocking wait; consumes the child             |
| `detach(self)`                                              | Release ownership without killing             |
| `close_stdin()`                                             | Close stdin pipe (signal EOF)                 |
| `take_stdin_fd()` / `take_stdout_fd()` / `take_stderr_fd()` | Take ownership of pipe fds                    |

`Child` implements `Drop`: if the child has not been `wait()`-ed or `detach()`-ed, the destructor kills and reaps it to prevent zombie processes.

### Stdio

The `Stdio` enum (defined in `src/stdio.rs`) mirrors `std::process::Stdio`:

| Variant          | Behavior                                                     |
| ---------------- | ------------------------------------------------------------ |
| `Inherit`        | Inherit the stream from the parent process                   |
| `Null`           | Redirect to `/dev/null`                                      |
| `Pipe`           | Create a pipe pair; parent end is accessible via `Child`     |
| `Owned(OwnedFd)` | Use a caller-provided file descriptor (e.g., a PTY slave fd) |

## Dynamic Mount Operations

`MountHandle` (defined in `src/mount/handle.rs`) allows adding, removing, and modifying mounts in a running sandbox. It is obtained via `Child::mount_handle()`.

The handle uses pre-opened file descriptors for the child's user and mount namespaces. It enters those namespaces via `setns()` to perform mount operations from the parent process. The namespace fds remain valid as long as the kernel holds a reference to the namespace, even after the child exits.

| Method                                  | Description                                |
| --------------------------------------- | ------------------------------------------ |
| `add_mount(source, target, permission)` | Bind-mount a host path into the sandbox    |
| `add_tmpfs(target, size_bytes)`         | Add a tmpfs mount                          |
| `remount(target, permission)`           | Change the permission of an existing mount |
| `remove_mount(handle)`                  | Remove a previously added dynamic mount    |

`DynamicMount` is a RAII guard for a dynamic mount. Dropping it without calling `remove()` logs a warning.

## Diagnostics

The `_detailed()` variants of `run()` return `ExecutionReport`, which pairs the standard `ExecutionResult` with `ExecutionDiagnostics`:

```rust
pub struct ExecutionReport {
    pub result: ExecutionResult,
    pub diagnostics: ExecutionDiagnostics,
}
```

`ExecutionDiagnostics` contains:

- **LimitDiagnostics** -- per-controller enforcement status (`LimitStatus`):
  - `NotRequested` -- the limit was not configured
  - `Enforced` -- the limit was successfully applied
  - `NotEnforced { reason }` -- the limit could not be applied (BestEffort mode)
  - `Unknown { reason }` -- enforcement status could not be determined
- **MetricDiagnostics** -- per-metric collection status (`MetricStatus`):
  - `Collected` -- the metric was successfully read
  - `Unavailable { reason }` -- the metric could not be collected
  - `Unknown { reason }` -- collection status uncertain

The `degradation_summary()` method returns a human-readable string listing all limits and metrics that were not enforced or collected, useful for logging in BestEffort mode.

## Error Handling

`SandboxError` (defined in `src/error.rs`) has 31 variants grouped by domain:

- **Platform** -- `PlatformNotSupported`, `PlatformFeatureUnavailable`
- **Namespace** -- `UserNamespaceDisabled`, `NamespaceCreation`, `NamespaceEnter`
- **Mount** -- `MountFailed`, `PathNotFound`, `InvalidMountPermission`, `DynamicMountFailed`, `InvalidMountPath`
- **Cgroup** -- `CgroupV2Unavailable`, `CgroupCreation`, `CgroupSetting`, `CgroupControllerUnavailable`, `ResourceLimitUnavailable`
- **Seccomp** -- `SecurityFilterLoad`, `SeccompFilterBuild`, `SyscallBlocked`
- **Execution** -- `Timeout`, `MemoryExceeded`, `ProcessLimitExceeded`, `Killed`, `CommandNotFound`, `ExecutionFailed`
- **Network** -- `NetworkDenied`
- **Spawn** -- `SetupFailed`, `ChildExited`
- **Configuration** -- `Config`
- **I/O** -- `Io`, `NulError`
- **Other** -- `Internal`

All variants carry context (strings, paths, numeric values) to aid debugging. The type implements `std::error::Error` via `thiserror`.

## Thread Safety

- `Sandbox` is `Send + Sync`.
- Each sandbox has independent resources (cgroup directory, namespace, proxy port).
- The global sandbox ID counter uses `AtomicU64`.
- Concurrent executions on the same `Sandbox` instance are safe but serialized per-execution (each call creates a new child process with its own cgroup).
