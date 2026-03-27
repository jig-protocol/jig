# Repository Guidelines

This repo hosts the Jig Protocol Rust workspace. Use it as your source of truth for building the core protocol, server, CLI, and nameserver.

### Executable Internet Focus (2025-10-24)

- All roadmap work now orients around the executable internet master plan (`executable-internet-master-plan/PLAN_STRUCTURE.md`).
- Messages ship as Wasm-backed blocks with capability manifests; keep Rust + WASM as primary languages (Elixir only for supervision layers if explicitly justified).
- Maintain end-to-end encryption, adaptive proof-of-useful-work, and potato-friendly deployments as non-negotiable guardrails.
- Align code changes with the new repo-level implementation plans under `executable-internet-master-plan/implementation/`.

## Project Structure & Module Organization

- `repos/` (workspace root) — shared `Cargo.toml`, scripts, test helpers.
- `repos/jig-core/` — core types, crypto, storage traits.
- `repos/jig-server/` — reference server (IRC/SSH/WebSocket, SQLite, federation).
- `repos/jig-cli/` — command-line client.
- `repos/jig-nameserver/` — identity/alias HTTP service.
- `repos/jig-email-bridge/` — email bridge (MVP target component).
- `repos/jig-spec/` + `IMPLEMENTATION_PLAN.md` — architecture/spec docs and roadmap.
- Tests live inline in modules (`#[cfg(test)]`); integration tests and helpers via shell scripts in `repos/*.sh`.

MVP target components: stable `jig-core` v1, `jig-server` with IRC/SSH/WebSocket + federation discovery, `jig-cli` v1, `jig-nameserver` v1, `jig-email-bridge` v0, and Docker packaging under `repos/jig-docker/`.

## Build, Test, and Development Commands

- Build workspace: `cd repos && cargo build --workspace`
- Run server: `cargo run -p jig-server -- --irc` (add flags like `--ssh`)
- Run CLI: `cargo run -p jig-cli -- --anon`
- Run nameserver: `cargo run -p jig-nameserver`
- Install nextest: `cargo install cargo-nextest`
- Preferred tests: `cargo nextest run --workspace` (or `-p <crate>`)
- Integration scripts: `./repos/test_alice_bob.sh`, `./repos/test_irc_bridge.sh`

## Coding Style & Naming Conventions

- Language: Rust (edition 2024). Indent 4 spaces; keep lines concise.
- Names: crates/modules `snake_case`; types/traits `CamelCase`; functions/vars `snake_case`.
- Organization: prefer small files (<200–250 LOC) and tightly scoped modules/subcrates; optimize for SOC (separation of concerns) and LOB (locality of behavior) while balancing DRY.
- Formatting: `cargo fmt --all` before pushing.
- Linting: `cargo clippy --workspace -D warnings` for new/changed code.

## Testing Guidelines

- Default to writing tests before code (TDD where practical).
- Prefer `cargo nextest run --workspace` for speed and reliability; fall back to `cargo test` if needed.
- Keep unit tests near code with `#[cfg(test)]` and precise names (e.g., `parses_irc_tag_value`).
- Add integration coverage via `repos/*.sh` when behavior spans crates; keep tests deterministic and isolated (see `verify_test_isolation.sh`).

## Commit & Pull Request Guidelines

- Commits: short, imperative summaries (e.g., "fix irc registration update"). Group related changes; avoid mixed refactors + behavior changes.
- PRs: include a clear description, rationale, and component scope (`jig-server`, `jig-cli`, etc.). Link issues when relevant and include run/test instructions and sample commands. Screens/logs for protocol/IRC flows are helpful.

## Security & Configuration Tips

- Server DB: defaults to SQLite at `~/.jig/jig.db`. Override via `--db-path`, `JIG_DB_PATH` (preferred) or `JIG_DB`.
- Nameserver: `JIG_NS_SECRET` for alias minting; `JIG_NS_DB_PATH` for future persistent storage.
- Do not commit secrets or local DBs; add new ignores to `.gitignore` as needed.

# Denylist

- all `git` commands
- `rm`, `sed`, `sudo`, `chmod`
- proactively escalate if you think a command / crate / library / script is potentially unsafe or exposes unanticipated risk: we're working together to keep your machine + environment safe
