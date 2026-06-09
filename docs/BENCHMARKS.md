# libsandbox Benchmarks

Performance benchmarks and comparison with other sandbox solutions.

## Status

The benchmarks below were originally measured on macOS using the `sandbox-exec` backend, which has since been removed. They are preserved for historical reference only and **do not represent current Linux performance**. Benchmarks need to be re-run on Linux to produce representative numbers.

## Benchmark Suite

libsandbox ships five Criterion.rs benchmark groups:

| File                            | Criterion Groups              | What it measures                                          |
| ------------------------------- | ----------------------------- | --------------------------------------------------------- |
| `benches/sandbox_creation.rs`   | `benches`                     | Builder overhead (empty config, with limits, with mounts) |
| `benches/command_execution.rs`  | `benches`                     | End-to-end `run()` latency                                |
| `benches/io.rs`                 | `output_sizes`, `stdin_input` | I/O throughput scaling                                    |
| `benches/seccomp_profiles.rs`   | `benches`                     | Seccomp BPF compilation overhead per profile              |
| `benches/parallel_execution.rs` | `benches`                     | Concurrent sandbox scaling                                |

## How to Run

```bash
# Run all benchmarks
cargo bench

# Run a specific benchmark file
cargo bench --bench sandbox_creation
cargo bench --bench command_execution
cargo bench --bench io
cargo bench --bench seccomp_profiles
cargo bench --bench parallel_execution

# Run a specific criterion group within io
cargo bench -- output_sizes
cargo bench -- stdin_input

# Generate HTML report
cargo bench -- --verbose
# Results in: target/criterion/report/index.html
```

## Linux Results

> **To be filled in.** Run `cargo bench` on a Linux host with kernel 5.10+ and cgroup v2, then record the results here.

### Sandbox Creation

| Scenario    | Time | Description                          |
| ----------- | ---- | ------------------------------------ |
| Minimal     | --   | Default config, just struct creation |
| With limits | --   | Memory + CPU + PID limits            |
| With mounts | --   | One bind mount added                 |

**Note:** Sandbox creation only builds the config object. Actual isolation (clone, cgroup, namespace setup) happens during `run()` or `spawn()`.

### Command Execution

| Command        | Time | Notes           |
| -------------- | ---- | --------------- |
| `echo hello`   | --   | Minimal command |
| `true`         | --   | No output       |
| `sh -c "echo"` | --   | Shell wrapper   |

### I/O Scaling

| Output Lines | Time | Throughput |
| ------------ | ---- | ---------- |
| 10 lines     | --   | --         |
| 100 lines    | --   | --         |
| 1,000 lines  | --   | --         |
| 10,000 lines | --   | --         |

### Parallel Execution

| Sandboxes | Time | Scaling  |
| --------- | ---- | -------- |
| 1         | --   | baseline |
| 2         | --   | --       |
| 4         | --   | --       |
| 8         | --   | --       |

---

## Historical Data (macOS, Pre-Linux Port)

These numbers were measured on macOS 14.x (ARM64) with the `sandbox-exec` backend. They are included for reference only.

### macOS Performance

| Scenario                   | Time    |
| -------------------------- | ------- |
| Sandbox creation (minimal) | 2.5 us  |
| `echo hello` execution     | 13.0 ms |
| 4 parallel sandboxes       | 14.4 ms |
| 10K-line output            | 25.1 ms |

### macOS Breakdown (~13ms)

- `sandbox-exec` profile generation: ~0.5ms (macOS-specific)
- `fork()`: ~1ms
- `exec()`: ~2ms
- `sandbox-exec` policy enforcement: ~8ms (macOS-specific)
- `wait4()` + cleanup: ~1.5ms

**Linux is expected to be faster** because:

- No `sandbox-exec` overhead (direct `clone()` with namespace flags)
- cgroup v2 operations are simple filesystem writes (~0.5ms)
- Namespace creation costs ~1ms
- No intermediate policy layer

---

## Comparison with Other Solutions

### Startup Latency

| Solution       | Cold Start | Warm Start | Notes                   |
| -------------- | ---------- | ---------- | ----------------------- |
| **libsandbox** | ~10 ms\*   | ~10 ms\*   | No daemon, direct clone |
| Docker         | ~500 ms    | ~200 ms    | Requires dockerd        |
| gVisor (runsc) | ~150 ms    | ~80 ms     | Requires containerd     |
| Firecracker    | ~125 ms    | ~50 ms     | Requires KVM            |
| Wasmer         | ~5 ms      | ~1 ms      | WASM only               |
| Isolate        | ~10 ms     | ~10 ms     | Linux only              |

_\*Linux measurement pending._

### Memory Overhead

| Solution       | Per-Instance | Base Daemon | Total (10 instances) |
| -------------- | ------------ | ----------- | -------------------- |
| **libsandbox** | ~2 MB\*      | 0           | ~20 MB\*             |
| Docker         | ~30 MB       | ~100 MB     | ~400 MB              |
| gVisor         | ~50 MB       | ~200 MB     | ~700 MB              |
| Firecracker    | ~5 MB        | ~50 MB      | ~100 MB              |
| Wasmer         | ~10 MB       | 0           | ~100 MB              |

_\*Linux measurement pending._

### Feature Comparison

| Feature                  | libsandbox | Docker    | gVisor   | Firecracker | Wasmer  |
| ------------------------ | ---------- | --------- | -------- | ----------- | ------- |
| **Language**             | Rust       | Go        | Go       | Rust        | Rust    |
| **Isolation**            | Namespace  | Container | Kernel   | VM          | WASM    |
| **Platform**             | Linux      | Linux     | Linux    | Linux       | All     |
| **Embeddable**           | Library    | REST API  | REST API | REST API    | Library |
| **No Daemon**            | Yes        | No        | No       | No          | Yes     |
| **Filesystem Isolation** | Yes        | Yes       | Yes      | Yes         | Limited |
| **Network Isolation**    | Yes        | Yes       | Yes      | Yes         | N/A     |
| **Memory Limit**         | Yes        | Yes       | Yes      | Yes         | Yes     |
| **CPU Limit**            | Yes        | Yes       | Yes      | Yes         | No      |
| **Process Limit**        | Yes        | Yes       | Yes      | Yes         | N/A     |
| **Rootless**             | Yes        | Partial   | No       | No          | Yes     |
| **Dynamic Mounts**       | Yes        | No        | No       | No          | No      |
| **Custom Seccomp**       | Yes        | Yes       | Yes      | No          | N/A     |
| **GPU Passthrough**      | No         | Yes       | No       | No          | No      |

### Isolation Strength

| Solution       | Escape Difficulty       | Attack Surface |
| -------------- | ----------------------- | -------------- |
| Firecracker    | Very High (VM)          | Small (KVM)    |
| gVisor         | High (Kernel intercept) | Medium         |
| Docker         | Medium (namespaces)     | Large          |
| **libsandbox** | **Medium** (namespaces) | **Medium**     |
| Wasmer         | Medium (WASM sandbox)   | Small          |

---

## Use Case Recommendations

### AI Code Execution

libsandbox is well-suited for AI agent code execution due to sub-100ms startup, no daemon overhead, and embeddable library design.

### Online Judge / Code Competition

libsandbox provides strict resource limits, fast execution, and high concurrency. Comparable to Isolate.

### Production Microservices

Docker / Kubernetes is recommended for orchestration, service discovery, and ecosystem maturity.

### High-Security Isolation

Firecracker (VM-level) or gVisor (kernel intercept) provide stronger isolation than namespace-based solutions like libsandbox.

---

## Optimization Tips

### For Latency

1. **Reuse sandboxes** -- create once, run many commands.
2. **Minimize mounts** -- each mount adds overhead during spawn.
3. **Disable unused features** -- `NetworkConfig::none()` avoids proxy setup.

### For Throughput

1. **Parallel execution** -- use a thread pool; each sandbox is independent.
2. **Batch small commands** -- amortize spawn overhead.
3. **Use tmpfs** -- faster than disk I/O for temporary data.

### For Memory

1. **Set memory limits** -- prevent runaway processes via cgroup.
2. **Share read-only mounts** -- kernel copy-on-write shares pages.
3. **Drop sandbox when done** -- releases cgroup and namespace resources.
