# AGENTS.md

AI Agent working guide. This document provides code structure and decision rules for AI agents.

## Directory Structure

```
.
├── flake.nix              # Flake entry point
├── Cargo.toml             # Crate manifest (single crate, not a workspace)
├── deny.toml              # cargo-deny policy
├── src/                   # Library source (enumerate modules as needed)
├── examples/              # Runnable examples
├── benches/               # Criterion benchmarks
├── tests/                 # Integration and security tests
├── docs/                  # Architecture documentation
└── nix/
      ├── common.nix       # Core config
      └── checks.nix       # CI checks
```

## Dependency Management

libsandbox is a single crate (not a workspace). Add dependencies directly to
`[dependencies]` in `Cargo.toml`:

1. Look up the latest version: `cargo search <crate-name> --registry crates-io`
2. Add to `[dependencies]`; use `optional = true` plus an entry in `[features]`
   for opt-in dependencies (see the existing `tokio` and `landlock` features).

## Verification Checklist

After modifying Nix files:
- `nixfmt <nix file>` - Format single file
- `nixfmt $(find nix/ -name "*.nix") flake.nix` - Format all Nix files at once
- `statix check .` - Static analysis (run from project root)

After modifying TOML files:
- `taplo fmt <toml file>` - Format specific file (never use bare `taplo fmt` — it ignores .gitignore and formats everything)

After modifying Rust code:
- `cargo fmt` - Format check
- `cargo clippy --all-targets --all-features` - Lint check
- `cargo test --all-targets --all-features` - Run tests
- `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps` - Build docs and fail on rustdoc warnings
