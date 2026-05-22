# jig-core Contributor Guide

## Scope

Core executable block types, hashing/signing helpers, and manifest/receipt tooling. No network/storage integrations; keep pure and dependency-light.

## Layout

- `src/` modules for block manifests, bundle/CID helpers, crypto, receipts, signing.
- Tests colocated with code using `#[cfg(test)]`.

## Build & Test

- Build: `cargo build -p jig-core`
- Preferred tests: `cargo nextest run -p jig-core`
- Docs: `cargo doc -p jig-core --open`

## Git Commands

- Don't.

## Coding Style

- Small files: target 200–250 LOC per file; split modules when behavior diverges.
- Favor SOC (separation of concerns) and LOB (locality of behavior) while balancing DRY.
- Naming: modules/functions `snake_case`, types/traits `CamelCase`.
- Format/lint: `cargo fmt --all` and `cargo clippy -p jig-core -D warnings`.

## Testing

- Write tests before code where practical; use precise names (e.g., `round_trips_message_cbor`).
- Use deterministic vectors for crypto; avoid randomness in unit tests unless seeded.

## PR Checklist

- Clear rationale and scope; no cross-crate side effects.
- Tests added/updated; docs for new types.
- No new non-portable deps; stays pure Rust.

## Live Objectives

- Execution plan tracked in `IMPLEMENTATION_PLAN.md` with KPI table covering TDD, SOC, LOB, DRY, curl-to-hello-world (<60s), and dead-simple defaults.
- Update plan statuses as work lands; reference KPI evidence in PR descriptions.
