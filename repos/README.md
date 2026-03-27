# Jig Protocol - Workspace

**WebAssembly-first messaging protocol with deterministic execution and capability security.**

---

## Architecture

Jig Protocol has adopted **WebAssembly (WASM) as the single unified runtime** for block execution.

### Active Components

- **jig-core** - Protocol primitives (manifests, bundles, receipts, CIDs)
- **jig-runtime** - Unified WASM runtime (deterministic execution, fuel metering, Receipt v0.2)
- **jig-server** - Reference server implementation
- **jig-cli** - Command-line client
- **jig-email-bridge** - Email gateway
- **jig-gui** - Dioxus-based UI (Riverdance)
- **jig-nameserver** - DNS/discovery service
- **jig-config** - Shared configuration
- **integration-tests** - Cross-component tests

### Archived Components (WASM-Only Migration)

The following repositories are **archived** and no longer maintained:

- **jig-wasmtime** - Trait-based Wasmtime wrapper (replaced by jig-runtime)
- **jig-docker** - Container-based runtime (replaced by WASM)
- **jig-podman** - Podman runtime (replaced by WASM)
- **jig-runtime-select** - Multi-engine dispatcher (no longer needed)

See individual repo READMEs for migration guides.

---

## Why WASM-Only?

1. **Determinism**: Reproducible execution across hosts
2. **Security**: Fine-grained capability sandboxing
3. **Performance**: Sub-millisecond cold starts
4. **Portability**: Same blocks run everywhere (server, CLI, browser)
5. **Simplicity**: One execution model, one receipt format

---

## Quick Start

### Build Workspace

```bash
cargo build --workspace --release
```

### Run Tests

```bash
cargo test --workspace
```

### Execute a Block (CLI)

```bash
jig-cli run block.wasm --runtime-config runtime.toml
```

### Start Server

```bash
jig-server --config server.toml
```

---

## Documentation

- **Runtime Architecture**: [jig-runtime/README.md](jig-runtime/README.md)
- **Protocol Spec**: [jig-core/README.md](jig-core/README.md)
- **CLI Integration**: [jig-cli/RUNTIME_INTEGRATION.md](jig-cli/RUNTIME_INTEGRATION.md)
- **Server Integration**: [jig-server/src/runtime/mod.rs](jig-server/src/runtime/mod.rs)

---

## Development

### Prerequisites

- Rust 1.75+ (edition 2024)
- WASM target: `rustup target add wasm32-wasi`
- For GUI: `dx` CLI tool

### Workspace Structure

```
repos/
├── jig-core/           # Protocol primitives
├── jig-runtime/        # WASM execution engine
├── jig-server/         # Server implementation
├── jig-cli/            # CLI client
├── jig-gui/            # Dioxus UI
├── jig-email-bridge/   # Email gateway
├── jig-nameserver/     # DNS/discovery
├── jig-config/         # Shared config
├── integration-tests/  # Cross-component tests
├── hello-wasm/         # Example WASM block
└── (archived repos)    # See individual READMEs
```

---

## License

- **jig-core**: MIT (portable protocol implementation)
- **jig-server**: AGPL-3.0 (server software)
- **jig-cli**: MIT (client tool)
- **jig-runtime**: MIT (execution engine)
- See individual component licenses for details

---

## Contributing

1. All block execution must target WASM
2. Follow existing patterns in jig-server/jig-cli integrations
3. Maintain Receipt v0.2 compatibility
4. Add tests for new features
5. Update documentation

For questions: Open an issue in the relevant component repo.

---

**Status:** Active development (M3 complete, M4 in progress)  
**Runtime API:** Stable (jig-runtime v0.2)  
**Protocol Version:** Receipt v0.2
