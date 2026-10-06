# jig-core

Core protocol implementation for Jig - a modern, open messaging protocol.

## Overview

`jig-core` provides the foundational data structures for the Jig executable internet. It intentionally keeps a small dependency surface so every other component (server, CLI, GUI, bridges) can embed the same primitives when building or verifying blocks.

It includes:

- Canonical block manifest definitions and builders
- Capability, resource, provenance, and privacy descriptors
- Merkle/CID helpers for packaging code + data into Jig Blocks
- Execution receipt structures
- Optional signing helpers (ed25519, Sigstore bundles)

## License

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Features

- **Near-Zero Dependencies**: Bare-minimum, pure-Rust dependency surface
- **Extensible**: Block-based message format
- **Secure**: E2E encryption by default
- **Fast**: 10k msgs/sec on single core

## Timing Semantics

Receipts include execution timings under `timings_ms`. `jig-core` enforces the invariant that `total == init + exec` and provides helpers to construct valid timings and annotate the clock source:

- `Timings::new(queue_wait, init, exec)` automatically sets `total = init + exec`.
- Hosts should measure with a monotonic clock. Optionally stamp the clock source in receipt metadata using:

  - constant key: `timing.clock_source`
  - builder helper: `.clock_source_monotonic()`

## Determinism & Wasm Validation

`jig-core` includes deterministic Wasm validation helpers used by hosts and build tools:

- `BlockBundle::validate_code(&constraints)` applies a strict determinism policy and enforces memory/table limits inferred from the module and provided constraints.
- `BlockBundle::validate_code_with_allowlist(&constraints, &HostImportAllowlist)` enables explicit host import allowlisting (e.g., allowing `jig_host::http_fetch` when policy permits).
- Set `constraints.deterministic = false` to allow floats (useful for CLI linting/test builds); strict mode remains the default.

Example:

```rust
use jig_core::bundle::BlockBundle;
use jig_core::manifest::{BlockManifest, Constraints};
use jig_core::wasm_validation::HostImportAllowlist;

let manifest = BlockManifest::builder().build()?;
let manifest_bytes = manifest.to_canonical_bytes()?;
let code_bytes: Vec<u8> = /* compiled Wasm */ vec![];
let bundle = BlockBundle { manifest_bytes: &manifest_bytes, code_bytes: &code_bytes, resources: vec![] };

let constraints = Constraints { fuel_max: 5_000_000, memory_max_mb: 32, execution_timeout_ms: 250, deterministic: true };

// Strict determinism (default)
bundle.validate_code(&constraints)?;

// With explicit allowlist
let allowlist = HostImportAllowlist::new().allow_module("jig_host", vec!["http_fetch".into()]);
bundle.validate_code_with_allowlist(&constraints, &allowlist)?;

// Lint manifest + Wasm together (capabilities + determinism)
use jig_core::{lint_block, CapabilityRegistry};
let registry = CapabilityRegistry::default();
let lint = lint_block(&manifest, &code_bytes, &constraints, &registry)?;
assert!(lint.is_clean());

// Author capabilities ergonomically
use jig_core::{capability, capabilities};
let caps = capabilities![
    capability!("core:compute"),
    capability!("net:http:fetch", scopes: ["https://api.example.com/*"]),
];
```

See also:

- `repos/jig-docs/core/RECEIPT_V0_2.md` for receipt structure, counters, timings, and validation rules.
- `repos/jig-spec/src/block-execution.md` for runtime semantics and on-wire examples.

## Quick Start

```rust
use jig_core::{Author, BlockBundle, BlockManifest};
use semver::Version;

let manifest = BlockManifest::builder()
    .version(Version::new(0, 1, 0))
    .author(Author {
        did: "did:jig:alice".into(),
        public_key: None,
        roles: vec!["author".into()],
    })
    .build()?;

let manifest_bytes = manifest.to_canonical_bytes()?;
let wasm_module_bytes = vec![]; // compiled WASM for the block payload
let bundle = BlockBundle {
    manifest_bytes: &manifest_bytes,
    code_bytes: &wasm_module_bytes,
    resources: vec![],
};

let block_cid = bundle.block_cid()?;
```

## Development

```bash
# Build
cargo build

# Test (unit + property)
cargo test --all-features

# Documentation
cargo doc --open
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.
