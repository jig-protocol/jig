# jig-cli Contributor Guide

## Scope
Block-aware command-line client that speaks to `jig-server` over HTTP. Focus on fast UX, stdin/stdout pipes, and anonymous/named DIDs.

## Layout
- `src/commands.rs` – user-facing operations.
- `src/http_client.rs` – thin wrapper around the `/blocks` API.
- `src/config.rs` – TOML load/save helpers (`~/.jig/config.toml`).
- `src/main.rs` – CLI parsing and orchestration.

## Build & Run
- Build: `cargo build -p jig-cli`
- Run: `cargo run -p jig-cli -- send "hello"`
- Use specific server: `jig --server http://localhost:7117 read`

## Testing
- `cargo check -p jig-cli`
- `cargo fmt -p jig-cli`
- Manual: start `jig-server` and run `cargo run -p jig-cli -- send "test"`

## Coding Style
- Keep modules small (≈200 LOC) with clear separation of CLI, HTTP, and config concerns.
- No direct SQLite access—storage lives in `jig-server`.
- Prefer async/await with `reqwest`; errors bubble via `anyhow::Result`.
- Format/lint: `cargo fmt`, `cargo clippy -p jig-cli -D warnings`.

## PR Checklist
- Describe UX changes and include sample commands.
- Update README + config defaults when altering flags.
- Add/update tests or scripts if behaviour changes (e.g. integration flows).
