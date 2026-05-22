# jig-bridge-email Contributor Guide

## Scope
Bidirectional email gateway (SMTP/IMAP ↔ Jig). Converts emails to Jig messages and vice versa, preserving threads and formatting.

## Layout
- `src/` modules for SMTP/IMAP clients, parsers, and Jig adapters.
- Config file: `email-bridge.toml` (runtime flags and credentials).

## Build & Run
- Build: `cargo build -p jig-bridge-email`
- Run: `cargo run -p jig-bridge-email -- --config email-bridge.toml`

## Testing
- Preferred: `cargo nextest run -p jig-bridge-email`
- Write tests before code; focus on robust parsing and idempotent conversions (MIME ↔ Jig blocks).
- Use fixtures for RFC822/MIME samples; avoid live network in unit tests.

## Coding Style
- Keep modules small (200–250 LOC); separate transport, parsing, and mapping layers.
- Format/lint: `cargo fmt --all`, `cargo clippy -p jig-bridge-email -D warnings`.

## PR Checklist
- Include sample messages and conversion cases; document config changes.
- Add tests for edge encodings (attachments, HTML/plain, quoting).

