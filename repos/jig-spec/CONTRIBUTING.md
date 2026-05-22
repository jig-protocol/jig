# Contributing to Jig Spec

Thanks for your interest in contributing to the Jig Protocol Specification!

This repository hosts the authoritative protocol specification. Substantial changes should go through the JEP (Jig Enhancement Proposal) process.

## Code of Conduct

Be respectful and constructive. Disagreements are expected; keep them technical and solution-oriented.

## Ways to Contribute

- Fix typos or clarify wording
- Improve examples and diagrams
- Propose a new feature or protocol change via a JEP
- Report security issues privately (see Security section)

## JEP (Jig Enhancement Proposal) Process

1. Fork this repository.
2. Create a new document under `jep/` using `JEP-TEMPLATE.md` as a starting point.
3. Use TOML frontmatter (between `+++` lines) to provide machine-readable metadata.
4. Open a GitHub issue using the "JEP Proposal" template to start discussion.
5. Submit a pull request referencing the issue. CI must pass (builds, linkcheck, typos).

Status lifecycle:
- Draft → Review → Accepted → Final → Deprecated → Superseded

JEPs should clearly state compatibility, migration, and security implications.

## Documentation Style

- Use RFC 2119 terminology (MUST, SHOULD, MAY) consistently
- Keep chapters small (< ~250 lines); move details to appendices if needed
- Use TOML in examples when representing configuration or structured data

## Building Locally

```bash
# Recommended: install via cargo-make (pins versions from Makefile.toml)
cargo install cargo-make@0.37.24
cargo make setup
cargo make ci

# Alternatively, install tools directly (keep in sync with Makefile.toml)
# cargo install mdbook@0.4.40 mdbook-linkcheck@0.7.7 typos-cli@1.23.6 cargo-make@0.37.24
```

Outputs appear under `book/`.

## Security

Please report security issues privately via email to security@jig.onl. Do not open public issues for security vulnerabilities until coordinated disclosure is arranged.
