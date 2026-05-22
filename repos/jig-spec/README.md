# Jig Protocol Specification

This repository contains the official specification for the Jig protocol.

- License: CC BY-SA 4.0 (see LICENSE)
- Status: Draft scaffolding
- Build: mdBook

## Goals

- Authoritative, implementation-agnostic protocol specification
- Clear versioning and change control via JEPs (Jig Enhancement Proposals)
- Small, focused chapters; RFC-style where appropriate

## Building the docs (mdBook)

You can build and serve the spec using cargo-make tasks (TOML-configured):

```bash
# One-time setup (pins tool versions in Makefile.toml)
cargo install cargo-make@0.37.24
cargo make setup

# Build static site
cargo make build

# Serve locally with hot reload
cargo make serve
```

The output will be generated in the `book/` directory.

## TOML-first configuration

We consolidate repository configuration in TOML wherever feasible:

- mdBook configuration: `book.toml`
- Task runner: `Makefile.toml` (cargo-make)
- Spellchecking: `typos.toml`

Notes:

- GitHub Actions requires YAML (see `.github/workflows/ci.yml`) but reads versions from `Makefile.toml` via `cargo make setup`.
- Example configurations in the spec should prefer TOML where possible; JSON/CBOR are still used for wire formats and canonical test vectors.

## Security and Zero-Trust

This specification is written under a strict zero-trust model. See `src/zero-trust.md` for the normative threat model and requirements that apply across all chapters. To report a security issue privately, read `SECURITY.md` or email security@jig.onl.

## Contributing

- Open issues and pull requests against this repository.
- Propose substantial changes via a JEP (see `jep/JEP-TEMPLATE.md`) before large edits.
- Keep chapters short (< ~250 lines) and focused; link out to appendices for extended material.

## Structure

- `book.toml` — mdBook configuration
- `src/` — specification sources
  - `SUMMARY.md` — table of contents
  - `introduction.md`
  - `protocol-overview.md`
  - `message-format.md`
  - `crypto.md`
  - `federation.md`
  - `transports.md`
  - `zero-trust.md`
  - `security.md`
  - `appendix.md`

## Versioning

The spec tracks the protocol version implemented by `jig-core` and `jig-server`. Each release will tag a corresponding spec version, with change notes in the appendix.
