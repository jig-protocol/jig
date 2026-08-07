# jig

A block-based messaging protocol and reference implementation, in Rust.

A message in jig is a **block**: a signed manifest (plus optional WebAssembly code),
addressed by a blake3 CID over its own contents. Identity is a **self-certifying DID** —
`did:jig:z…` is literally your 32-byte ed25519 public key in base32
([`jig-core/src/did.rs`](repos/jig-core/src/did.rs)), generated locally, so there is no
account, no password, and nothing for a server to hand out. Servers **federate** peer to
peer over WebSocket and verify every block's signature themselves, so a relaying server
cannot forge or silently rewrite what it passes on.

Compared to its neighbours: IRC has no cryptographic identity and no durable history;
Matrix pins identity to an account on a homeserver and federates room state; Slack is a
single hosted service. jig's specific bet is that content-addressed signed blocks plus
locally-held keys plus a Wasm execution model for rendering can carry the same
conversations, and that channel-create and member-add should be the *same* signed-block
primitive as a chat message rather than a separate control plane. Whether that bet pays
off is not settled.

---

## Status: pre-alpha. Do not put this on a public IP.

Workspace version is `0.0.1`; the newest tag is `v0.0.2`. This has never been deployed
publicly — `jig.onl` is registered but serves nothing — and it has been exercised only on
loopback and private tailnets.

**Read this before running it anywhere reachable:**

- **No encryption of message content.** Blocks are *signed*, never encrypted. There is no
  E2EE and no per-message confidentiality. Anything on the wire without an outer TLS
  tunnel is plaintext, and the server stores plaintext.
- **No authentication and no authorization.** A WebSocket client may subscribe to any
  channel scope without proving anything
  ([`v0_0_2_ws.rs`](repos/jig-server/src/v0_0_2_ws.rs), the `Frame::Subscribe` arm).
  Channel `visibility = "restricted"` is *recorded* but not
  enforced on reads. The `/_admin_v0_0_2/*` endpoints that create channels and add members
  are unauthenticated, which is why the shipped config binds loopback only.
- **No graphical client.** `repos/jig-gui/` (Riverdance) is a Dioxus scaffold around a
  mocked chat UI. It depends on neither `jig-core` nor `jig-client` and never opens a
  connection — it is a design mock, not a client.
- Network-level access control — a tailnet, a firewall — is currently the *only* access
  control. That is a deliberate v0.0.x position, not an oversight, but it means the
  security model is entirely outside this repo.

### What works, what does not

| Capability | State |
| --- | --- |
| Local `jig-server` + `jig chat` / `jig tail` over WebSocket | Works |
| Signed, content-addressed blocks (ed25519 signature, CID) | Works |
| Channel create / join / list; membership records | Works, via unauthenticated admin endpoints |
| History backfill (last 100 blocks) on joining a channel | Works |
| `GET /api/v1/channels/:slug/blocks`, `/healthz`, `/metrics` | Works |
| Nameserver: alias register / resolve / rotate / renew | Works (`jig-nameserver`, `jig ns …`) |
| Server-to-server federation over WSS | Implemented and covered by [`h3_federation.rs`](repos/integration-tests/tests/h3_federation.rs); never run between two hosts on the public internet |
| Email bridge (Resend) | Implemented in-process; see [`bridges/email/README.md`](repos/bridges/email/README.md) |
| Wasm block execution **on the server** | **Not wired.** Every receipt is server-signed and synthetic ([`jig-pipeline/src/ingest.rs`](repos/jig-pipeline/src/ingest.rs), step 4). The server never calls `jig-runtime` |
| Wasm block execution in the CLI (`jig block run`) | Runs and emits a metered receipt for the runtime's own fixtures. It **rejects the workspace's own `text-block` build** with `MemoryMissingMaximum` from the determinism validator |
| `jig block lint` / `sign` / `verify` / `capabilities` | Stubs; they print "not yet implemented" and exit 1 |
| End-to-end encryption | None |
| Authentication / authorization | None |
| Graphical client | None |
| `jig read` | Broken by default — it calls the v0.0.1 `GET /blocks` route, which is gated off behind `dangerously_enable_v0_0_1_rest`. Use `jig chat`, `jig tail`, or the history endpoint |
| `jig --version` | Not implemented (`jig-server --version` is) |
| Prebuilt release binaries | None published. `install.sh`'s download path targets `releases.jig.onl`, which does not serve anything |

Design targets that have **not been measured** and should not be read as results: 10,000
messages/second on a $5 VPS, and a 60-second `curl … | sh` install. The benchmark
procedure for the second is written down in
[`docs/deployment/install-benchmark.md`](docs/deployment/install-benchmark.md) and has not
been run.

---

## Quickstart

Requires Rust **1.94+** (MSRV is set by wasmtime 47). Build the two binaries:

```bash
git clone https://github.com/jig-protocol/jig
cd jig/repos
cargo build --release -p jig-server -p jig-cli
export PATH="$PWD/target/release:$PATH"
```

Generate a config, then start the server. `--init-config` writes a commented template that
binds `127.0.0.1:7117` and enables the admin endpoints the channel commands need:

```bash
jig-server --init-config ~/.jig/config.toml
jig-server --config ~/.jig/config.toml
```

In another shell, make an identity, point the client at the server, create a channel, and
open the TUI:

```bash
jig init <nickname>                 # writes ~/.jig/cli.toml + ~/.jig/keys/<did>.key
jig server set http://127.0.0.1:7117
jig channel create '#hello'
jig chat '#hello'                   # Enter sends; Ctrl+Q or Esc quits
```

`jig send "text" --channel '#hello'` and `jig tail --channel '#hello'` are the
non-interactive equivalents. `jig server info` prints the server's advertised
`/.well-known/jig` capabilities, including any unsafe options it has enabled.

`jig chat` and `jig tail` exit non-zero when the connection drops but do not reconnect on
their own; [`scripts/jig-room.sh`](scripts/jig-room.sh) is the deliberate `until`-loop
stand-in.

### About `install.sh`

[`install.sh`](install.sh) at the repo root automates the above and hands off to
`jig chat`. Its **download path is dead** — no release tarballs have been published, and
`releases.jig.onl` does not serve — so only its source-checkout branch works. That branch
does work end to end, but it runs the same `cargo build --release` you can run yourself,
so it takes minutes rather than the 60 seconds the KPI comment at the top of the file
describes. Treat the manual quickstart above as the supported path.

---

## Workspace

Cargo workspace root is [`repos/`](repos/), not the repo root. `deny.toml` is the exception
and lives at the repo root.

| Crate | What it is |
| --- | --- |
| [`jig-core`](repos/jig-core/) | Protocol primitives: DIDs, manifests, bundles, CIDs, receipts, signing, capability DSL |
| [`jig-pipeline`](repos/jig-pipeline/) | Shared ingest → effect → persist → fanout pipeline used by both servers |
| [`jig-server`](repos/jig-server/) | Reference server: WebSocket + HTTP, SQLite storage, federation, bridge hosting |
| [`jig-client`](repos/jig-client/) | Client library: WSS connection, identity loading, bundle construction |
| [`jig-cli`](repos/jig-cli/) | The `jig` binary — init, send, tail, chat, channel, keys, ns, block |
| [`jig-config`](repos/jig-config/) | Shared TOML config types and loader |
| [`jig-nameserver`](repos/jig-nameserver/) | DID/alias registry: register, resolve, rotate, renew |
| [`jig-runtime`](repos/jig-runtime/) | Wasmtime-based Wasm runtime: deterministic execution, fuel metering, receipts |
| [`bridges/core`](repos/bridges/core/) | Common `Bridge` trait and context types |
| [`bridges/email`](repos/bridges/email/) | In-process email bridge (Resend provider) |
| [`text-block`](repos/text-block/) | The canonical `text-render` Wasm block (`wasm32-wasip1`) |
| [`hello-wasm`](repos/hello-wasm/) | Minimal WASI hello-world used for runtime measurements |
| [`integration-tests`](repos/integration-tests/) | Cross-component scenario tests: federation, TOFU mismatch, nameserver modes, persistence across restart, email bridge, TLS |
| [`jig-gui`](repos/jig-gui/) | Riverdance — a Dioxus scaffold with a mocked chat UI, wired to no jig crate. **Not a working client** |

Not Cargo members: [`repos/jig-spec/`](repos/jig-spec/) — an mdBook protocol spec, still
draft scaffolding, licensed CC BY-SA 4.0 — and [`repos/jig-docs/`](repos/jig-docs/), a
holding area of per-milestone working notes.

## Building and testing

```bash
cd repos
cargo build --workspace
cargo nextest run --workspace     # no environment variables required
```

`cargo nextest run --workspace` works from a clean checkout with nothing exported:
[`repos/.config/nextest.toml`](repos/.config/nextest.toml) injects a throwaway
`JIG_NS_SECRET` test fixture that `jig-nameserver`'s config defaults would otherwise panic
without. That value is a public, source-controlled fixture and must never appear in a
deployment.

One environment caveat: stop any local `jig-server` on `127.0.0.1:7117` first.
`jig-cli::global_flags missing_implicit_config_still_falls_back_to_defaults` asserts that
the default port is unreachable, so it fails against your own running server.

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs three jobs: `workspace`
(fmt, clippy, nextest — scoped to the v0.0.2 crate surface, not the legacy crates),
`wasm-build` (`text-block` for `wasm32-wasip1`), and `dependency-policy`
(`cargo deny check` — advisories, bans, licenses, sources). Toolchain is
`dtolnay/rust-toolchain@stable`.

## Where to go next

| You want to | Read |
| --- | --- |
| Run a server on a box you already have | [`deploy/README.md`](deploy/README.md) |
| Provision that box on GCP | [`docs/deployment/gcp-vps-runbook.md`](docs/deployment/gcp-vps-runbook.md) |
| Know exactly what shipped and what did not | the STATUS section of [`docs/deployment/internal-dogfood-3day.md`](docs/deployment/internal-dogfood-3day.md) |
| Find any doc in the repo, with a currency label | [`docs/README.md`](docs/README.md) |
| Understand why something is shaped the way it is | [`docs/superpowers/`](docs/superpowers/) |
| Work on the code with an agent | [`CLAUDE.md`](CLAUDE.md) / [`AGENTS.md`](AGENTS.md) |

Back up `server.key` before you do anything else — losing it changes the server's DID and
breaks TOFU pinning for every client that has ever connected. `deploy/README.md` opens with
this for a reason.

There is no `CONTRIBUTING.md` for the implementation yet;
[`repos/jig-spec/CONTRIBUTING.md`](repos/jig-spec/CONTRIBUTING.md) covers the spec only.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))

at your option. This is the customary Rust dual licence, chosen deliberately: a protocol
that cannot be embedded is not a protocol, so every crate you would need to speak jig —
`jig-core`, `jig-client`, `jig-server`, `jig-pipeline`, `jig-runtime`, `jig-nameserver`,
`jig-config`, `jig-cli`, the bridges, and the sample blocks — is permissively licensed for
any use, commercial included.

Two deliberate exceptions:

| Scope | Licence | Why |
| --- | --- | --- |
| [`repos/jig-gui/`](repos/jig-gui/NOTICE.md) (Riverdance) | **None granted yet** | A client application, not protocol surface. Copyleft or source-available may be the right answer; the call has not been made. Default copyright applies until it is. |
| [`repos/jig-spec/`](repos/jig-spec/) | CC BY-SA 4.0 | The written specification, not code. Under review — share-alike on a spec can impede the implementations the permissive code licence is meant to encourage. |

### Contribution

Unless you state otherwise, any contribution you intentionally submit for inclusion in the
work, as defined in the Apache-2.0 licence, shall be dual-licensed as above, without any
additional terms or conditions. Contributions to `repos/jig-gui/` are the exception — see
its [`NOTICE.md`](repos/jig-gui/NOTICE.md).

## Relationship to gigue

jig is sponsored by gigue, which builds a closed-source product of the same name. The
dependency direction is one-way and enforced as a rule: **gigue may depend on jig; jig
never depends on gigue.** No gigue code is in this repository.
