# Good first contributions

Small, self-contained changes for a first pull request, each checked against `main` on
2026-10-25. They are not filed as issues. Before starting one, check open pull requests in case
someone has already picked it up, then follow [`CONTRIBUTING.md`](../CONTRIBUTING.md).
[`ARCHITECTURE.md`](ARCHITECTURE.md) explains where things live.

Each item says what is wrong today and what done looks like.

## Documentation that has drifted from the code

1. **Stale DID examples in the spec.**
   - `repos/jig-spec/src/transports.md` says DIDs are base58.
   - `protocol-overview.md` uses `did:jig:alice123`.
   - A `did:jig` is `did:jig:z` plus 52 characters of lowercase base32 ([Crypto
     Primitives](../repos/jig-spec/src/crypto.md)).
   - Done: the examples use that form.

## Comments that say something untrue

2. **`repos/jig-pipeline/src/lib.rs` says "Modules are stubbed in this initial commit".** They
   are not. Done: the crate doc describes what the crate does.
3. **`repos/Cargo.toml` says the MSRV floor is "set by wasmtime 48.x".** The workspace is on
   wasmtime 49. Done: the comment names the dependency that actually sets the floor.
4. **`repos/jig-runtime/src/config.rs` defaults `component_model: false`, "opt-in for now".**
   `ComponentRuntime` always enables the component model. Done: the field goes, or its comment
   says what it still controls. Check its callers first.

## Small build changes

5. **`publish = false` on crates not meant for crates.io** (roadmap phase 0, item 15). Only
   `integration-tests` sets it today. Per D6, `jig-core` and `jig-client` may be published once
   v0.2 stabilises the wire. Done: every other crate sets `publish = false`, with a comment
   pointing to D6.

## Before you start

- A change to protocol behaviour needs a JEP first. None of the items above do.
- Doc-only pull requests skip the build jobs in CI. Code changes run `fmt`, `clippy` and
  `nextest` exactly as [`CONTRIBUTING.md`](../CONTRIBUTING.md) lists them.
  [`scripts/dev-setup.sh`](../scripts/dev-setup.sh) checks you have the tools.
