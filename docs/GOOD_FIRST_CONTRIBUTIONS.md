# Good first contributions

Small, self-contained changes for a first pull request, each checked against `main` on
2026-10-25. They are not filed as issues. Before starting one, check open pull requests in case
someone has already picked it up, then follow [`CONTRIBUTING.md`](../CONTRIBUTING.md).
[`ARCHITECTURE.md`](ARCHITECTURE.md) explains where things live.

Each item says what is wrong today and what done looks like.

## Documentation that has drifted from the code

1. **`repos/README.md` describes an older workspace.**
   - Today it says:
     - Rust 1.75+ (`rust-toolchain.toml` pins 1.99.0, and the MSRV is 1.95);
     - "Receipt v0.2" (receipts are v0.3 COSE objects);
     - a `jig-cli run` command (the binary is `jig`, and the command is `jig block run`);
     - and it leaves out `jig-pipeline`, `jig-client`, `jig-mls`, `text-block` and the bridges.
   - Done: the crate list matches [`ARCHITECTURE.md`](ARCHITECTURE.md), or the file points to it.
2. **`repos/jig-runtime/WASI_SURFACES.md` documents WASI support that no longer exists.**
   - jig-runtime runs `jig:block` components with no WASI at all (see `src/lib.rs` and
     `src/grant_linker.rs`).
   - Done: delete the file, or replace it with a short note on what a component may import.
3. **The root README says `jig init` writes `~/.jig/keys/<did>.key`.** It writes
   `<did>.jigkey`, a sealed key file (`repos/jig-client/src/identity.rs`). Done: the quick-start
   comment names the right file.
4. **Stale DID examples in the spec.**
   - `repos/jig-spec/src/transports.md` says DIDs are base58.
   - `protocol-overview.md` uses `did:jig:alice123`.
   - A `did:jig` is `did:jig:z` plus 52 characters of lowercase base32 ([Crypto
     Primitives](../repos/jig-spec/src/crypto.md)).
   - Done: the examples use that form.
5. **Threat-register row AB-02 says the nameserver asks for no proof-of-work.** It does since
   #264: `/v1/register`, `/v1/rotate` and `/v1/renew` check it, priced by
   `jig-nameserver/src/v0_0_2_pow_policy.rs`. Done: the status cell says what `main` does,
   citing the PRs.

## Comments that say something untrue

6. **`repos/jig-core/src/did.rs` says the `z` is "the multibase prefix for base32upper".** In
   multibase, `z` means base58btc; jig uses a literal `z` followed by lowercase base32. Done: the
   comment says the `z` is a jig version sigil, and warns that a generic multibase decoder will
   misread it.
7. **`repos/jig-pipeline/src/lib.rs` says "Modules are stubbed in this initial commit".** They
   are not. Done: the crate doc describes what the crate does.
8. **`repos/Cargo.toml` says the MSRV floor is "set by wasmtime 48.x".** The workspace is on
   wasmtime 49. Done: the comment names the dependency that actually sets the floor.
9. **`repos/jig-runtime/src/config.rs` defaults `component_model: false`, "opt-in for now".**
   `ComponentRuntime` always enables the component model. Done: the field goes, or its comment
   says what it still controls. Check its callers first.

## Small code and build changes

10. **`publish = false` on crates not meant for crates.io** (roadmap phase 0, item 15). Only
    `integration-tests` sets it today. Per D6, `jig-core` and `jig-client` may be published once
    v0.2 stabilises the wire. Done: every other crate sets `publish = false`, with a comment
    pointing to D6.
11. **The jig-runtime fuzz crate does not build.**
    - `repos/jig-runtime/fuzz/Cargo.toml` names the package `jig-core-fuzz`, and its path
      dependency points at jig-runtime under the name `jig-core`.
    - The only registered target, `fuzz_target_1.rs`, is empty.
    - `fuzz_wasm_bytes.rs`, which feeds raw bytes to `ComponentRuntime::compile_renderer`, is not
      registered.
    - Done: `cargo +nightly fuzz build` succeeds with the real target, and the README says how to
      run it. Wiring fuzzing into CI is a separate change.

## Before you start

- A change to protocol behaviour needs a JEP first. None of the items above do.
- Doc-only pull requests skip the build jobs in CI. Code changes run `fmt`, `clippy` and
  `nextest` exactly as [`CONTRIBUTING.md`](../CONTRIBUTING.md) lists them.
  [`scripts/dev-setup.sh`](../scripts/dev-setup.sh) checks you have the tools.
