# libsandbox API Reference

Complete API documentation for the libsandbox sandbox library.

## Table of Contents

- [Crate-Level Exports](#crate-level-exports)
- [Sandbox](#sandbox)
- [SandboxBuilder](#sandboxbuilder)
- [Preset Configurations](#preset-configurations)
- [SpawnBuilder](#spawnbuilder)
- [Stdio](#stdio)
- [Child](#child)
- [ExitStatus](#exitstatus)
- [MountHandle and DynamicMount](#mounthandle-and-dynamicmount)
- [Domain Configuration Types](#domain-configuration-types)
  - [FilesystemConfig](#filesystemconfig)
  - [ResourceConfig](#resourceconfig)
  - [NetworkConfig](#networkconfig)
  - [SecurityConfig](#securityconfig)
  - [EnvironmentConfig](#environmentconfig)
- [Seccomp Customization](#seccomp-customization)
- [Result Types](#result-types)
- [Error Types](#error-types)
- [Free Functions and Constants](#free-functions-and-constants)
- [Thread Safety](#thread-safety)

---

## Crate-Level Exports

The `libsandbox` crate re-exports the following types at the root level:

```rust
// Core types
pub use sandbox::{Sandbox, SpawnBuilder};
pub use builder::{SandboxBuilder, SandboxConfig};
pub use process::{Child, ExitStatus};
pub use stdio::Stdio;
pub use mount::{DynamicMount, MountHandle};

// Result and diagnostics
pub use result::{
    ExecutionDiagnostics, ExecutionReport, ExecutionResult,
    LimitDiagnostics, LimitStatus, MetricDiagnostics, MetricStatus,
};

// Error types
pub use error::{Result, SandboxError};

// Configuration types (also available via libsandbox::config::*)
pub use config::{
    CgroupLimitRequests, EnvironmentBuilder, EnvironmentConfig, ExecutionPolicy,
    FilesystemBuilder, FilesystemConfig, Mount, MountOptions, NetworkBuilder,
    NetworkConfig, NetworkMode, Permission, ResourceConfig, ResourceEnforcement,
    SeccompProfile, SecurityBuilder, SecurityConfig,
};

// Constants
pub const KB: u64 = 1024;
pub const MB: u64 = 1024 * 1024;
pub const GB: u64 = 1024 * 1024 * 1024;
```

**Note:** `ResourceBuilder` is accessible via `libsandbox::config::ResourceBuilder` (not re-exported at the crate root). `SeccompFilter`, `SeccompFilterBuilder`, and `SeccompAction` are accessible via `libsandbox::seccomp::*`.

---

## Sandbox

The main entry point for sandbox operations.

### Creating a Sandbox

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
```

### Methods

#### `builder`

```rust
pub fn builder() -> SandboxBuilder
```

Create a new `SandboxBuilder` with default configuration.

#### `run`

```rust
pub fn run(&self, cmd: &str, args: &[&str]) -> Result<ExecutionResult>
```

Execute a command in the sandbox. Blocks until the command completes or times out.

```rust
let result = sandbox.run("python3", &["-c", "print('hello')"])?;
println!("stdout: {}", result.stdout);
println!("exit code: {}", result.exit_code);
```

#### `run_with_input`

```rust
pub fn run_with_input(
    &self,
    cmd: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<ExecutionResult>
```

Execute a command with optional stdin input.

```rust
let result = sandbox.run_with_input("cat", &[], Some(b"hello world"))?;
assert_eq!(result.stdout, "hello world");
```

#### `run_detailed`

```rust
pub fn run_detailed(&self, cmd: &str, args: &[&str]) -> Result<ExecutionReport>
```

Execute a command and return an `ExecutionReport` containing both the result and diagnostics about limit enforcement and metric collection.

```rust
let report = sandbox.run_detailed("python3", &["script.py"])?;
println!("exit code: {}", report.result.exit_code);
if let Some(summary) = report.diagnostics.degradation_summary() {
    eprintln!("Diagnostics: {}", summary);
}
```

#### `run_with_input_detailed`

```rust
pub fn run_with_input_detailed(
    &self,
    cmd: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<ExecutionReport>
```

Execute a command with stdin and return an `ExecutionReport`.

#### `spawn`

```rust
pub fn spawn(&self, cmd: &str, args: &[&str]) -> Result<Child>
```

Spawn a sandboxed process and return a `Child` handle. Defaults: stdin to `Null`, stdout to `Pipe`, stderr to `Pipe`.

```rust
let child = sandbox.spawn("bash", &["--login"])?;
println!("child pid: {}", child.pid());
let status = child.wait()?;
println!("exit: {}", status.code());
```

#### `build_spawn`

```rust
pub fn build_spawn(&self, cmd: &str, args: &[&str]) -> SpawnBuilder<'_>
```

Begin building a spawned process with custom stdio configuration. Returns a `SpawnBuilder`.

```rust
use libsandbox::Stdio;

let child = sandbox.build_spawn("cat", &[])
    .stdin(Stdio::Pipe)
    .stdout(Stdio::Pipe)
    .start()?;
```

#### `id`

```rust
pub fn id(&self) -> &str
```

Get the sandbox's unique identifier.

#### `platform`

```rust
pub fn platform(&self) -> &'static str
```

Get the platform name. Always returns `"linux"`.

---

## SandboxBuilder

Builder for composing domain configs into a sandbox.

### Creation

```rust
let builder = Sandbox::builder();
// or
let builder = SandboxBuilder::new();
```

### Domain Consume Methods

Each method accepts a fully validated domain config struct and returns `Self` for chaining.

```rust
pub fn filesystem(self, config: FilesystemConfig) -> Self
pub fn resources(self, config: ResourceConfig) -> Self
pub fn network(self, config: NetworkConfig) -> Self
pub fn security(self, config: SecurityConfig) -> Self
pub fn environment(self, config: EnvironmentConfig) -> Self
```

### build

```rust
pub fn build(self) -> Result<Sandbox>
```

Validate the composed configuration and create the `Sandbox`. Returns an error if the platform does not support the requested features.

---

## Preset Configurations

Static factory methods on `Sandbox` that return a `SandboxBuilder` pre-configured for common use cases. Callers can override any domain by passing a replacement config.

#### `Sandbox::code_judge`

```rust
pub fn code_judge(code_dir: impl Into<PathBuf>) -> SandboxBuilder
```

Preset for online judge systems. Strict limits, no network.

```rust
let sandbox = Sandbox::code_judge("/submissions/123")
    .resources(
        ResourceConfig::builder()
            .wall_time_limit(Duration::from_secs(5))
            .build()
            .unwrap()
    )
    .build()?;
```

#### `Sandbox::agent_executor`

```rust
pub fn agent_executor(workspace: impl Into<PathBuf>) -> SandboxBuilder
```

Preset for AI agent code execution. Moderate limits, optional network.

#### `Sandbox::data_analysis`

```rust
pub fn data_analysis(
    input_dir: impl Into<PathBuf>,
    output_dir: impl Into<PathBuf>,
) -> SandboxBuilder
```

Preset for data analysis workloads. Higher memory and time limits.

#### `Sandbox::interactive`

```rust
pub fn interactive(workspace: impl Into<PathBuf>) -> SandboxBuilder
```

Preset for interactive and REPL sessions. Permissive security profile.

---

## SpawnBuilder

Builder for configuring a spawned child process. Obtained via `Sandbox::build_spawn()`.

### Methods

```rust
pub fn stdin(self, stdio: Stdio) -> Self
pub fn stdout(self, stdio: Stdio) -> Self
pub fn stderr(self, stdio: Stdio) -> Self
pub fn start(self) -> Result<Child>
```

Each stdio method sets the corresponding stream configuration. `start()` performs the actual `clone()` and returns a `Child` handle.

```rust
use libsandbox::{Sandbox, Stdio};

let child = sandbox.build_spawn("bash", &[])
    .stdin(Stdio::Pipe)
    .stdout(Stdio::Pipe)
    .stderr(Stdio::Inherit)
    .start()?;
```

---

## Stdio

Controls how the child process's standard streams are connected. Mirrors `std::process::Stdio`.

```rust
pub enum Stdio {
    Inherit,              // Inherit from parent process
    Null,                 // Redirect to /dev/null
    Pipe,                 // Create a pipe pair
    Owned(OwnedFd),       // Use a caller-provided fd (e.g., PTY slave)
}
```

**Defaults:** stdin defaults to `Null`, stdout and stderr default to `Pipe`.

`Stdio` implements `From<OwnedFd>` and `From<std::fs::File>`.

```rust
use std::os::unix::io::AsFd;

// Pass a PTY slave fd for interactive use
let slave_fd: OwnedFd = /* ... */;
let child = sandbox.build_spawn("bash", &[])
    .stdin(Stdio::Owned(slave_fd))
    .stdout(Stdio::Pipe)
    .start()?;
```

---

## Child

A handle to a sandboxed child process. Owns the PID, pipe fds, cgroup, and namespace fds.

### Methods

| Method           | Signature                                                  | Description                             |
| ---------------- | ---------------------------------------------------------- | --------------------------------------- |
| `pid`            | `pub fn pid(&self) -> u32`                                 | Child PID in parent's namespace         |
| `stdin_fd`       | `pub fn stdin_fd(&self) -> Option<&OwnedFd>`               | Parent-end stdin pipe fd                |
| `stdout_fd`      | `pub fn stdout_fd(&self) -> Option<&OwnedFd>`              | Parent-end stdout pipe fd               |
| `stderr_fd`      | `pub fn stderr_fd(&self) -> Option<&OwnedFd>`              | Parent-end stderr pipe fd               |
| `cgroup`         | `pub fn cgroup(&self) -> Option<&CgroupManager>`           | Access cgroup for metric collection     |
| `mount_handle`   | `pub fn mount_handle(&self) -> Result<MountHandle>`        | Get a handle for dynamic mounts         |
| `kill`           | `pub fn kill(&self) -> Result<()>`                         | Send SIGKILL via pidfd or process group |
| `try_wait`       | `pub fn try_wait(&mut self) -> Result<Option<ExitStatus>>` | Non-blocking exit check                 |
| `wait`           | `pub fn wait(self) -> Result<ExitStatus>`                  | Block until exit; consumes self         |
| `detach`         | `pub fn detach(self) -> u32`                               | Release without killing; returns PID    |
| `close_stdin`    | `pub fn close_stdin(&mut self)`                            | Close stdin pipe (idempotent)           |
| `take_stdin_fd`  | `pub fn take_stdin_fd(&mut self) -> Option<OwnedFd>`       | Take ownership of stdin fd              |
| `take_stdout_fd` | `pub fn take_stdout_fd(&mut self) -> Option<OwnedFd>`      | Take ownership of stdout fd             |
| `take_stderr_fd` | `pub fn take_stderr_fd(&mut self) -> Option<OwnedFd>`      | Take ownership of stderr fd             |

### Drop Behavior

If `Child` is dropped without calling `wait()` or `detach()`, the destructor kills the child process (SIGKILL) and waits for it to prevent zombie processes.

### Example

```rust
let mut child = sandbox.build_spawn("cat", &[])
    .stdin(Stdio::Pipe)
    .start()?;

// Write to stdin
if let Some(fd) = child.stdin_fd() {
    nix::unistd::write(fd.as_fd(), b"hello\n")?;
}
child.close_stdin();

// Wait for exit
let status = child.wait()?;
println!("exit: {}", status.code());
```

---

## ExitStatus

The exit status of a sandboxed process.

```rust
pub struct ExitStatus { /* fields are private */ }
```

### Methods

| Method    | Signature                             | Description                                   |
| --------- | ------------------------------------- | --------------------------------------------- |
| `code`    | `pub fn code(&self) -> i32`           | Exit code (0 = success; 128+signal if killed) |
| `signal`  | `pub fn signal(&self) -> Option<i32>` | Signal number if killed by signal             |
| `success` | `pub fn success(&self) -> bool`       | True if exit code is 0 and no signal          |

`ExitStatus` implements `Display` and `Clone`.

---

## MountHandle and DynamicMount

### MountHandle

Obtained via `Child::mount_handle()`. Allows mount operations on a running sandbox by entering the child's mount namespace via pre-opened file descriptors.

| Method         | Signature                                                                                               | Description             |
| -------------- | ------------------------------------------------------------------------------------------------------- | ----------------------- |
| `add_mount`    | `pub fn add_mount(&self, source: &Path, target: &Path, permission: Permission) -> Result<DynamicMount>` | Bind-mount a host path  |
| `add_tmpfs`    | `pub fn add_tmpfs(&self, target: &Path, size_bytes: u64) -> Result<DynamicMount>`                       | Add a tmpfs mount       |
| `remount`      | `pub fn remount(&self, target: &Path, permission: Permission) -> Result<()>`                            | Change mount permission |
| `remove_mount` | `pub fn remove_mount(&self, handle: DynamicMount) -> Result<()>`                                        | Remove a dynamic mount  |

### DynamicMount

RAII guard for a dynamic mount. Dropping without calling `remove()` logs a warning.

| Method   | Signature                                | Description                          |
| -------- | ---------------------------------------- | ------------------------------------ |
| `remove` | `pub fn remove(&mut self) -> Result<()>` | Remove the mount (lazy `MNT_DETACH`) |
| `target` | `pub fn target(&self) -> &Path`          | Target path inside the sandbox       |
| `source` | `pub fn source(&self) -> Option<&Path>`  | Host source path (None for tmpfs)    |

---

## Domain Configuration Types

Each domain has its own builder with per-field validation. Builders are accessed via the config type's `::builder()` method.

### FilesystemConfig

```rust
pub struct FilesystemConfig {
    pub mounts: Vec<Mount>,
    pub tmpfs_mounts: Vec<(PathBuf, u64)>,
    pub working_dir: PathBuf,      // default: "/"
    pub rootfs: Option<PathBuf>,   // default: None
}
```

#### FilesystemBuilder

```rust
FilesystemConfig::builder()
    .mount("/host/path", "/sandbox/path", Permission::ReadOnly)
    .mount("/host/data", "/data", Permission::ReadWrite)
    .tmpfs("/tmp", 64 * MB)
    .working_dir("/workspace")
    .rootfs("/path/to/rootfs")
    .build()
```

| Method                              | Description                          |
| ----------------------------------- | ------------------------------------ |
| `mount(source, target, permission)` | Add a bind mount                     |
| `tmpfs(path, size_bytes)`           | Add a tmpfs mount (size must be > 0) |
| `working_dir(path)`                 | Set working directory                |
| `rootfs(path)`                      | Set root filesystem for pivot_root   |
| `build()`                           | Validate and create config           |

#### Mount

```rust
pub struct Mount {
    pub source: PathBuf,
    pub target: PathBuf,
    pub permission: Permission,
}
```

#### Permission

```rust
pub enum Permission {
    ReadOnly,
    ReadWrite,
    Custom(MountOptions),
}
```

#### MountOptions

```rust
pub struct MountOptions {
    pub read_only: bool,    // default: false
    pub no_exec: bool,      // default: false
    pub no_suid: bool,      // default: true
    pub no_dev: bool,       // default: true
}
```

`Permission` and `MountOptions` implement `Serialize` and `Deserialize`.

### ResourceConfig

```rust
pub struct ResourceConfig {
    pub memory_limit: Option<u64>,           // bytes, default: None
    pub cpu_limit: Option<f64>,              // cores, default: None
    pub max_pids: Option<u32>,               // default: Some(64)
    pub wall_time_limit: Option<Duration>,   // default: None
    pub cpu_time_limit: Option<Duration>,    // default: None
    pub max_file_size: Option<u64>,          // bytes, default: None
    pub max_open_files: Option<u32>,         // default: None
}
```

#### ResourceConfig Methods

| Method         | Signature                             | Description                                   |
| -------------- | ------------------------------------- | --------------------------------------------- |
| `needs_cgroup` | `pub fn needs_cgroup(&self) -> bool`  | Whether any cgroup-backed limit is configured |
| `builder`      | `pub fn builder() -> ResourceBuilder` | Create a new builder                          |

#### ResourceBuilder

Accessed via `libsandbox::config::ResourceBuilder`:

```rust
use libsandbox::config::ResourceBuilder;
use libsandbox::ResourceEnforcement;

ResourceBuilder::new()
    .memory_limit(512 * MB)
    .cpu_limit(2.0)
    .wall_time_limit(Duration::from_secs(30))
    .cpu_time_limit(Duration::from_secs(20))
    .max_pids(64)
    .max_file_size(100 * MB)
    .max_open_files(256)
    .resource_enforcement(ResourceEnforcement::BestEffort)
    .build()
```

| Method                       | Description                                               |
| ---------------------------- | --------------------------------------------------------- |
| `memory_limit(bytes)`        | Hard memory limit via cgroup `memory.max`                 |
| `cpu_limit(cpus)`            | CPU core limit via cgroup `cpu.max`                       |
| `wall_time_limit(duration)`  | Wall-clock timeout                                        |
| `cpu_time_limit(duration)`   | CPU time limit                                            |
| `max_pids(n)`                | Process limit via cgroup `pids.max`                       |
| `max_file_size(bytes)`       | Maximum file size via RLIMIT_FSIZE                        |
| `max_open_files(n)`          | FD limit via RLIMIT_NOFILE                                |
| `resource_enforcement(mode)` | Set enforcement mode (default: Strict)                    |
| `build()`                    | Validate and create config (rejects zero/negative limits) |

#### ResourceEnforcement

```rust
pub enum ResourceEnforcement {
    Strict,       // Fail if a limit cannot be enforced (default)
    BestEffort,   // Degrade gracefully, report via diagnostics
}
```

#### ExecutionPolicy

```rust
pub struct ExecutionPolicy {
    pub resource_enforcement: ResourceEnforcement,
    pub cgroup_limit_requests: CgroupLimitRequests,
}
```

#### CgroupLimitRequests

```rust
pub struct CgroupLimitRequests {
    pub memory: bool,
    pub cpu: bool,
    pub pids: bool,
}
```

Automatically set to `true` when the corresponding limit is configured via `ResourceBuilder`.

### NetworkConfig

```rust
pub struct NetworkConfig {
    pub mode: NetworkMode,
}
```

#### Shorthand Constructors

```rust
NetworkConfig::none()                          // No network (default)
NetworkConfig::host()                          // Full host network
NetworkConfig::proxied(&["api.example.com"])   // Proxied with domain whitelist
```

#### NetworkBuilder

```rust
NetworkConfig::builder()
    .proxied(&["api.example.com", "*.github.com"])
    .build()
```

| Method             | Description                      |
| ------------------ | -------------------------------- |
| `none()`           | No network access                |
| `host()`           | Full host network access         |
| `proxied(domains)` | HTTP proxy with domain whitelist |
| `build()`          | Create config                    |

#### NetworkMode

```rust
pub enum NetworkMode {
    None,                                    // No network (default)
    Host,                                    // Full host network
    Proxied { allowed_domains: Vec<String> }, // Proxy with domain whitelist
}
```

Domain patterns support exact match (`api.example.com`) and wildcard subdomains (`*.example.com`).

### SecurityConfig

```rust
pub struct SecurityConfig {
    pub seccomp_profile: SeccompProfile,   // default: Standard
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}
```

#### SecurityBuilder

```rust
SecurityConfig::builder()
    .seccomp_profile(SeccompProfile::Strict)
    .uid(1000)
    .gid(1000)
    .build()
```

| Method                     | Description                |
| -------------------------- | -------------------------- |
| `seccomp_profile(profile)` | Set seccomp profile        |
| `uid(uid)`                 | Set UID inside the sandbox |
| `gid(gid)`                 | Set GID inside the sandbox |
| `build()`                  | Create config              |

#### SeccompProfile

```rust
pub enum SeccompProfile {
    Disabled,                          // No filter
    Strict,                            // Minimal syscall set
    Standard,                          // Common safe syscalls (default)
    Permissive,                        // Most syscalls, block dangerous ones
    Custom(SeccompFilter),             // User-defined filter
}
```

### EnvironmentConfig

```rust
pub struct EnvironmentConfig {
    pub env: HashMap<String, String>,
    pub clear_env: bool,       // default: true
    pub hostname: String,      // default: "sandbox"
}
```

#### EnvironmentBuilder

```rust
EnvironmentConfig::builder()
    .env("PATH", "/usr/bin:/bin")
    .env("HOME", "/tmp")
    .envs(vec![("LANG".into(), "en_US.UTF-8".into())])
    .clear_env(true)
    .hostname("mybox")
    .build()
```

| Method             | Description                                       |
| ------------------ | ------------------------------------------------- |
| `env(key, value)`  | Set a single env var                              |
| `envs(pairs)`      | Set multiple env vars                             |
| `clear_env(clear)` | Whether to clear the parent's env (default: true) |
| `hostname(name)`   | Set the hostname inside the sandbox               |
| `build()`          | Create config                                     |

---

## Seccomp Customization

For fine-grained syscall filtering beyond the preset profiles, use `SeccompFilterBuilder` (accessible via `libsandbox::seccomp::SeccompFilterBuilder`). Syscalls are identified by `libc`'s own `SYS_*` number constants, re-exported at `libsandbox::seccomp::SYS_*` so you don't need to depend on `libc` yourself — typos are caught at compile time:

```rust
use libsandbox::seccomp::{SeccompFilterBuilder, SYS_mount, SYS_ptrace, SYS_read};
use libsandbox::SeccompProfile;

let filter = SeccompFilterBuilder::standard()
    .deny(SYS_ptrace)                        // KillProcess (default deny action)
    .deny_with_errno(SYS_mount, 1)           // Return EPERM (1) instead
    .allow(SYS_read)
    .build()?;

let sandbox = Sandbox::builder()
    .security(
        SecurityConfig::builder()
            .seccomp_profile(SeccompProfile::Custom(filter))
            .build()?
    )
    .build()?;
```

### SeccompFilterBuilder Methods

| Method                            | Returns                 | Description                                                 |
| --------------------------------- | ----------------------- | ----------------------------------------------------------- |
| `new(default_action)`             | `Self`                  | Create builder with a default action for unmatched syscalls |
| `strict()`                        | `Self`                  | Start with the Strict preset                                |
| `standard()`                      | `Self`                  | Start with the Standard preset                              |
| `permissive()`                    | `Self`                  | Start with the Permissive preset                            |
| `default_action(action)`          | `Self`                  | Change the default action for unmatched syscalls            |
| `allow(syscall)`                  | `Self`                  | Allow a syscall                                             |
| `deny(syscall)`                   | `Self`                  | Deny a syscall with KillProcess                             |
| `deny_with_errno(syscall, errno)` | `Self`                  | Deny a syscall, return the given errno                      |
| `log(syscall)`                    | `Self`                  | Allow a syscall but log it                                  |
| `allow_all(syscalls)`             | `Self`                  | Add Allow rules for each syscall in the slice               |
| `deny_all(syscalls)`              | `Self`                  | Add KillProcess rules for each syscall in the slice         |
| `remove(syscall)`                 | `Self`                  | Remove the rule for a syscall                               |
| `build()`                         | `Result<SeccompFilter>` | Compile into a `SeccompFilter`                              |

The `syscall`/`syscalls` arguments are `SyscallNumber` (= `libc::c_long`); pass the re-exported `SYS_*` constants.

### SeccompFilter

An opaque compiled BPF filter. Created by `SeccompFilterBuilder::build()`. Accessible via `libsandbox::seccomp::SeccompFilter`.

| Method           | Signature                                       | Description                               |
| ---------------- | ----------------------------------------------- | ----------------------------------------- |
| `program_len`    | `pub fn program_len(&self) -> usize`            | Number of BPF instructions                |
| `rule_count`     | `pub fn rule_count(&self) -> usize`             | Number of compiled rules                  |
| `default_action` | `pub fn default_action(&self) -> SeccompAction` | The default action for unmatched syscalls |

### SeccompAction

```rust
pub enum SeccompAction {
    KillProcess,    // Kill the entire process
    KillThread,     // Kill the calling thread
    Trap,           // Deliver SIGSYS
    Errno(u16),     // Return errno value
    Log,            // Allow but log
    Allow,          // Allow the syscall
}
```

**Note:** Seccomp BPF compilation supports x86_64 and aarch64.

---

## Result Types

### ExecutionResult

```rust
pub struct ExecutionResult {
    pub stdout: String,                  // Standard output (lossy UTF-8)
    pub stderr: String,                  // Standard error (lossy UTF-8)
    pub exit_code: i32,                  // Process exit code (0 = success)
    pub duration: Duration,              // Wall clock time
    pub killed_by_timeout: bool,         // True if killed by wall-time limit
    pub killed_by_oom: bool,             // True if killed by OOM
    pub signal: Option<i32>,             // Signal number if killed by signal
    pub peak_memory: Option<u64>,        // Peak memory in bytes
    pub cpu_time: Option<Duration>,      // CPU time (user + system)
}
```

#### Methods

```rust
pub fn success(&self) -> bool
```

Returns `true` if exit code is 0, not killed by timeout, not killed by OOM, and not killed by a signal.

```rust
pub fn failure_reason(&self) -> Option<String>
```

Returns a human-readable failure reason string, or `None` if the execution succeeded.

### ExecutionReport

```rust
pub struct ExecutionReport {
    pub result: ExecutionResult,
    pub diagnostics: ExecutionDiagnostics,
}
```

Returned by `run_detailed()` and `run_with_input_detailed()`.

### ExecutionDiagnostics

```rust
pub struct ExecutionDiagnostics {
    pub limits: LimitDiagnostics,
    pub metrics: MetricDiagnostics,
}
```

#### `degradation_summary`

```rust
pub fn degradation_summary(&self) -> Option<String>
```

Returns a human-readable summary of any limits that were not enforced or metrics that could not be collected. Returns `None` if everything is nominal.

### LimitDiagnostics

```rust
pub struct LimitDiagnostics {
    pub memory: LimitStatus,
    pub cpu: LimitStatus,
    pub pids: LimitStatus,
}
```

### LimitStatus

```rust
pub enum LimitStatus {
    NotRequested,                      // Limit was not configured
    Enforced,                          // Limit was successfully applied
    NotEnforced { reason: String },    // Limit could not be applied
    Unknown { reason: String },        // Status uncertain
}
```

### MetricDiagnostics

```rust
pub struct MetricDiagnostics {
    pub peak_memory: MetricStatus,
    pub cpu_time: MetricStatus,
}
```

### MetricStatus

```rust
pub enum MetricStatus {
    Collected,                         // Metric was successfully read
    Unavailable { reason: String },    // Metric could not be collected
    Unknown { reason: String },        // Collection status uncertain
}
```

---

## Error Types

### SandboxError

All errors returned by libsandbox operations. Grouped by domain:

**Platform errors:**

| Variant                      | Fields             | Description                          |
| ---------------------------- | ------------------ | ------------------------------------ |
| `PlatformNotSupported`       | `platform: String` | Running on an unsupported OS         |
| `PlatformFeatureUnavailable` | `feature: String`  | A required kernel feature is missing |

**Namespace errors:**

| Variant                 | Fields                            | Description                               |
| ----------------------- | --------------------------------- | ----------------------------------------- |
| `UserNamespaceDisabled` |                                   | Unprivileged user namespaces are disabled |
| `NamespaceCreation`     | `ns_type: String, reason: String` | Failed to create a namespace              |
| `NamespaceEnter`        | `String`                          | Failed to enter a namespace               |

**Mount errors:**

| Variant                  | Fields                                          | Description                       |
| ------------------------ | ----------------------------------------------- | --------------------------------- |
| `MountFailed`            | `src: PathBuf, target: PathBuf, reason: String` | Bind mount or tmpfs failed        |
| `PathNotFound`           | `PathBuf`                                       | Source path does not exist        |
| `InvalidMountPermission` | `path: PathBuf, reason: String`                 | Invalid permission for the target |
| `DynamicMountFailed`     | `reason: String`                                | Runtime mount operation failed    |
| `InvalidMountPath`       | `path: PathBuf, reason: String`                 | Path validation failed            |

**Cgroup errors:**

| Variant                       | Fields                                       | Description                           |
| ----------------------------- | -------------------------------------------- | ------------------------------------- |
| `CgroupV2Unavailable`         |                                              | cgroup v2 is not mounted              |
| `CgroupCreation`              | `String`                                     | Failed to create cgroup directory     |
| `CgroupSetting`               | `controller, setting, value, reason: String` | Failed to write a cgroup control file |
| `CgroupControllerUnavailable` | `controller: String, available: String`      | Required controller is not available  |
| `ResourceLimitUnavailable`    | `limit: String, reason: String`              | A requested limit cannot be enforced  |

**Seccomp errors:**

| Variant              | Fields            | Description                   |
| -------------------- | ----------------- | ----------------------------- |
| `SecurityFilterLoad` | `String`          | Failed to load seccomp filter |
| `SeccompFilterBuild` | `String`          | Failed to compile BPF program |
| `SyscallBlocked`     | `syscall: String` | A blocked syscall was invoked |

**Execution errors:**

| Variant                | Fields                   | Description                   |
| ---------------------- | ------------------------ | ----------------------------- |
| `Timeout`              | `duration: Duration`     | Execution exceeded time limit |
| `MemoryExceeded`       | `used: u64, limit: u64`  | Memory limit exceeded         |
| `ProcessLimitExceeded` | `count: u32, limit: u32` | PID limit exceeded            |
| `Killed`               | `signal: i32`            | Killed by signal              |
| `CommandNotFound`      | `String`                 | Command executable not found  |
| `ExecutionFailed`      | `String`                 | General execution failure     |

**Network errors:**

| Variant         | Fields           | Description             |
| --------------- | ---------------- | ----------------------- |
| `NetworkDenied` | `domain: String` | Domain blocked by proxy |

**Spawn errors:**

| Variant       | Fields   | Description                |
| ------------- | -------- | -------------------------- |
| `SetupFailed` | `String` | Child process setup failed |
| `ChildExited` |          | Child has already exited   |

**Configuration errors:**

| Variant  | Fields   | Description           |
| -------- | -------- | --------------------- |
| `Config` | `String` | Invalid configuration |

**I/O errors:**

| Variant    | Fields               | Description      |
| ---------- | -------------------- | ---------------- |
| `Io`       | `std::io::Error`     | I/O error        |
| `NulError` | `std::ffi::NulError` | Nul byte in path |

**Other:**

| Variant    | Fields   | Description    |
| ---------- | -------- | -------------- |
| `Internal` | `String` | Internal error |

### Result Type

```rust
pub type Result<T> = std::result::Result<T, SandboxError>;
```

---

## Free Functions and Constants

### `is_platform_supported`

```rust
pub fn is_platform_supported() -> bool
```

Check if the current platform supports sandboxing. Returns `true` when unprivileged user namespaces are enabled (reads `/proc/sys/kernel/unprivileged_userns_clone`).

### `platform_name`

```rust
pub fn platform_name() -> &'static str
```

Get the current platform name. Returns `"linux"`.

### Size Constants

```rust
pub const KB: u64 = 1024;
pub const MB: u64 = 1024 * 1024;
pub const GB: u64 = 1024 * 1024 * 1024;
```

---

## Thread Safety

- `Sandbox` implements `Send + Sync`.
- Each sandbox has independent resources (cgroup directory, namespace, proxy port).
- The global sandbox ID counter uses `AtomicU64`.
- Concurrent executions on the same `Sandbox` instance create independent child processes.
- `Child` is `Send` but not `Sync` (it requires `&mut self` for `try_wait()`).
