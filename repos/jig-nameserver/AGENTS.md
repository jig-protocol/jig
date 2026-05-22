# jig-nameserver Contributor Guide

## Scope
Identity resolution and alias minting over HTTP. Verifies signed claims (Ed25519) and serves resolve/claim/alias endpoints.

## Layout
- `src/` modules for server, types, crypto, storage (in-memory now).
- Env: `JIG_NS_SECRET` (alias minting), `JIG_NS_DB_PATH` (future persistence).

## Build & Run
- Build: `cargo build -p jig-nameserver`
- Run: `cargo run -p jig-nameserver`

## Testing
- Preferred: `cargo nextest run -p jig-nameserver -q`
- Tests before code; deterministic vectors for signatures; avoid time flakiness (inject clocks where needed).

## Coding Style
- Small files (200–250 LOC target); separate HTTP handlers, crypto, and storage concerns.
- Format/lint: `cargo fmt --all`, `cargo clippy -p jig-nameserver -D warnings`.

## PR Checklist
- Document endpoint changes with request/response examples.
- Include tests for verify/resolve/alias flows.
- Note any config/env additions and defaults.

