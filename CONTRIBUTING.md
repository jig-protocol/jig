# Contributing to jig

jig is pre-alpha. Read the status section of the [README](README.md) before you run a server anywhere reachable. v0.x has no compatibility guarantee.

## Getting started

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) is a tour of the crates, the write path, identity, MLS, federation, the block runtime and the nameserver, and says where the specs and JEPs live.
- [`scripts/dev-setup.sh`](scripts/dev-setup.sh) checks for the toolchain and tools CI uses; `scripts/dev-setup.sh --install` installs what is missing, and `--spec` adds the spec book's tools.
- [`docs/OWNERSHIP.md`](docs/OWNERSHIP.md) says who reviews each area and what the review checks.
- [`docs/GOOD_FIRST_CONTRIBUTIONS.md`](docs/GOOD_FIRST_CONTRIBUTIONS.md) lists small changes to start with.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Report conduct issues to **dev@jig.onl**. Vulnerability reports go through [SECURITY.md](SECURITY.md), not that address.

## DAG rule

The dependency arrow points one way: **gigue may depend on jig; jig never depends on gigue.**

Do not add any of these:

- a crate, path, or git dependency whose name or URL is gigue
- the `gigue-internal` registry, or any other private registry
- a path dependency that leaves this repository and reaches into a gigue checkout

jig's graph is this workspace plus public crates. [`deny.toml`](deny.toml) rejects unknown git dependencies and unknown registries. The pull request template asks you to confirm the rule. A change that needs a gigue crate belongs in the gigue repository, depending on jig.

## Where a change goes

- Protocol behavior and the specification: open a [JEP proposal](https://github.com/jig-protocol/jig/issues/new?template=jep-proposal.yml). Normative text lives in [`repos/jig-spec/`](repos/jig-spec/) (CC-BY-4.0). [`repos/jig-spec/CONTRIBUTING.md`](repos/jig-spec/CONTRIBUTING.md) covers the book build.
- A bug, or a feature that is not a spec change: use the [bug report](https://github.com/jig-protocol/jig/issues/new?template=bug_report.yml) or [feature request](https://github.com/jig-protocol/jig/issues/new?template=feature_request.yml) form. Blank issues are off.
- A vulnerability: [SECURITY.md](SECURITY.md). Do not open a public issue, pull request, or discussion.
- A question about running jig: **dev@jig.onl**.

## Pull requests

Use the pull request template: what changed and why, a test plan, whether the spec or a JEP is affected, and the DAG-rule checkbox.

[`CODEOWNERS`](.github/CODEOWNERS) requests a review from [@the-jig-is-up](https://github.com/the-jig-is-up). `main` requires that review, a resolved conversation, and these checks: `workspace`, `wasm-build (text-block, wasm32-unknown-unknown)`, and `dependency-policy (cargo-deny)`. The branch must be up to date with `main`.

## Building and testing

The Cargo workspace is [`repos/`](repos/), not the repository root. `rust-toolchain.toml` at the root is the toolchain CI uses, with the `wasm32-unknown-unknown` target; rustup installs it on its own. You also need a C compiler (SQLite is built from source), and `cargo-nextest`; `scripts/dev-setup.sh` checks for both.

```bash
cd repos
CARGO_INCREMENTAL=0 cargo build --workspace
CARGO_INCREMENTAL=0 cargo nextest run --workspace
```

Each git worktree has its own `repos/target/`, which grows to tens of GB. `scripts/clean-build-artifacts.sh` lists the build output in every worktree of your clone, and deletes it with `--yes`. Agents working in this repository follow [AGENTS.md](AGENTS.md).

`cargo nextest run --workspace` needs no exported secrets. Stop any local `jig-server` on `127.0.0.1:7117` first: one CLI test expects that port to be closed.

CI is [`.github/workflows/ci.yml`](.github/workflows/ci.yml). `workspace` runs fmt, clippy, and nextest on the v0.0.2 crate surface. `wasm-build` checks the canonical `text-block` module. `dependency-policy` runs `cargo deny check` (advisories, bans, licenses, sources) from the repository root.

## License

Unless you say otherwise, a contribution you submit for inclusion is dual-licensed under Apache-2.0 or MIT, the same as the code. Contributions to `repos/jig-spec/` are CC-BY-4.0.
