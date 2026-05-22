# jig-server Contributor Guide

## Scope
Executable block ingestion server backed by SQLite, Wasmtime validation, and an HTTP API. Legacy transports will return later once the block pipeline is stable.

## Layout
- `src/` organized by transport (`irc/`, `server.rs`, `storage.rs`).
- Inline unit tests via `#[cfg(test)]`; integration via scripts in `repos/*.sh`.

## Build & Run
- Build: `cargo build -p jig-server`
- Generate config: `cargo run -p jig-server -- --init-config jig-config.toml`
- Run: `cargo run -p jig-server -- --config jig-config.toml`
- DB path override: `--db-path` or env `JIG_DB_PATH`.

## Testing
- Preferred: `cargo nextest run -p jig-server`
- HTTP integration tests will land after CLI migration; for now ensure unit tests cover storage/runtime.
- Default to writing tests before code; keep tests isolated and deterministic.

## Coding Style
- Keep files tight (200–250 LOC goal); split by concern (parsing, state, IO).
- Balance DRY with LOB: duplicate small adapters when it improves locality.
- Format/lint: `cargo fmt --all`, `cargo clippy -p jig-server -D warnings`.

## PR Checklist
- Describe API changes and include sample curl payloads + receipts.
- Call out storage schema migrations; provide upgrade notes.
- Tests added/updated (unit + nextest).
