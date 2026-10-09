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

- **v0.x makes no compatibility guarantee.** Any v0.x release may change the wire format,
  manifests, receipts or configuration without a migration path. What v0.x does promise is
  that a mismatch is refused, not misread: the envelope version, manifest schema and
  encryption suite are checked, and anything unsupported is rejected
  ([`repos/jig-spec/src/versioning.md`](repos/jig-spec/src/versioning.md)).

- **No encryption of message content.** Blocks are *signed*, never encrypted. There is no
  E2EE and no per-message confidentiality. Anything on the wire without an outer TLS
  tunnel is plaintext, and the server stores plaintext.
- **Authentication and channel authorization, but no admission policy.** Every read
  carries a signed proof of possession of the caller's key, and `visibility = "restricted"`
  is enforced on history, the listing, live delivery and posting
  ([`jig-server/src/auth/`](repos/jig-server/src/auth/),
  [`jig-pipeline/src/authorize_write.rs`](repos/jig-pipeline/src/authorize_write.rs)).
  What is missing is any way to refuse a caller *before* those gates: any self-minted key
  is admitted, there is no rate limiting, and blocks relayed by a federated peer are
  trusted. Channel ops (`POST /api/v1/channels*`) run the same gates and need no
  `[debug]` flag.
- **No graphical client.** Riverdance, the unfinished GUI, is not in this repository.
  Its licence is undecided, and it is not a working client. The terminal client is
  `jig chat`.
- Network-level access control — a tailnet, a firewall — is still the recommended outer
  layer, because the gates above are new and nothing sits in front of them. It is no
  longer the *only* access control; see `deploy/README.md` for what the server enforces
  on its own.

### What works, what does not

| Capability | State |
| --- | --- |
| Local `jig-server` + `jig chat` / `jig tail` over WebSocket | Works |
| Signed, content-addressed blocks (ed25519 signature, CID) | Works |
| Channel create / join / list; membership records | Works. Blocks are signature-verified and owner/membership-gated at ingest; the routes still mount behind a `[debug]` flag |
| History backfill (last 100 blocks) on joining a channel | Works |
| `GET /api/v1/channels/:slug/blocks`, `/healthz`, `/metrics` | Works |
| Nameserver: alias register / resolve / rotate / renew | Works (`jig-nameserver`, `jig ns …`) |
| Server-to-server federation over WSS | Implemented and covered by [`h3_federation.rs`](repos/integration-tests/tests/h3_federation.rs); never run between two hosts on the public internet |
| Email bridge (Resend) | Implemented in-process; see [`bridges/email/README.md`](repos/bridges/email/README.md) |
| Wasm block execution **on the server** | `text-render` executes for real: the server runs its canonical module and signs the `render_hash` ([`jig-pipeline/src/ingest.rs`](repos/jig-pipeline/src/ingest.rs), step 4). Control-plane kinds still take a synthetic, server-signed receipt |
| Wasm block execution in the CLI (`jig block run`) | Runs and emits a metered receipt for the runtime's own fixtures. It **rejects the workspace's own `text-block` build** with `MemoryMissingMaximum` from the determinism validator |
| `jig block lint` / `sign` / `verify` / `capabilities` | Stubs; they print "not yet implemented" and exit 1 |
| End-to-end encryption | None. MLS is planned for v0.2. Every frame and manifest already names its encryption suite; `none` is the only one accepted ([spec](repos/jig-spec/src/encryption.md)) |
| Authentication / authorization | Signed proof of possession on every read; `restricted` channels membership-gated for reading, listing, live delivery and posting; membership changes owner-signed. **No admission policy or rate limiting** — any key is admitted |
| Graphical client | None |
| `jig read` | Broken by default — it calls the v0.0.1 `GET /blocks` route, which is gated off behind `dangerously_enable_v0_0_1_rest`. Use `jig chat`, `jig tail`, or the history endpoint |
| `jig --version` | Not implemented (`jig-server --version` is) |
| Prebuilt release binaries | `release.yml` builds static musl Linux (x86_64, aarch64) and Apple Silicon macOS tarballs with a signed `SHA256SUMS`, gated on the install smoke test. No real tag has been cut with it yet; the repo is private, so anonymous downloads don't work |

A design target that has **not been measured** and should not be read as a result: 10,000
messages/second on a $5 VPS.

The 60-second `curl … | bash` install **is** measured: on 2026-10-05, installing a published
test release took 3.5s on Linux x86_64 and 3.2s on Apple Silicon (GitHub-hosted runners),
from `curl` to "hello, world" accepted in `#hello`. CI fails above 60s; see
[`docs/deployment/install-benchmark.md`](docs/deployment/install-benchmark.md).

---

## Quickstart

Requires Rust **1.95+** (MSRV is set by wasmtime 48); `rust-toolchain.toml` pins the exact toolchain CI uses, and rustup picks it up automatically. Build the two binaries:

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

`jig send "text" --channel '#hello'` and `jig tail '#hello'` are the
non-interactive equivalents. `chat`, `tail`, and `read` each take the channel
either positionally or as `--channel`; `send` is flag-only, since its positional
slot is the message body. `jig server info` prints the server's advertised
`/.well-known/jig` capabilities, including any unsafe options it has enabled.

`jig chat` and `jig tail` exit non-zero when the connection drops but do not reconnect on
their own; [`scripts/jig-room.sh`](scripts/jig-room.sh) is the deliberate `until`-loop
stand-in.

### About `install.sh`

[`install.sh`](install.sh) at the repo root automates the above with no `[debug]` flag
and no prompts:

```bash
curl -fsSL https://raw.githubusercontent.com/jig-protocol/jig/main/install.sh | bash
# private repo: JIG_GITHUB_TOKEN=$(gh auth token) bash install.sh
```

It downloads `jig-<os>-<arch>.tar.gz` from the newest GitHub Release (`JIG_VERSION=<tag>` to
pin), verifies `SHA256SUMS.sig` with `ssh-keygen -Y` against the pinned release key and the
tarball against `SHA256SUMS`, and installs into `~/.jig/bin`. It then starts `jig-server` on
`127.0.0.1:7117`, creates `#hello`, posts "hello, world", and opens `jig chat` if a terminal
is attached. `JIG_INSTALL_FROM=source` builds from a checkout instead (minutes, not seconds).
The knobs are listed at the top of the script.

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

Not Cargo members: [`repos/jig-spec/`](repos/jig-spec/) — an mdBook protocol spec, still
draft scaffolding, licensed CC-BY-4.0 — and [`repos/jig-docs/`](repos/jig-docs/), a
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
| Report a vulnerability | [`SECURITY.md`](SECURITY.md) (security@jig.onl) |
| Know what a hostile server operator can and cannot do | the [threat register](repos/jig-spec/src/threat-register.md) and [`docs/security/`](docs/security/operator-threat-model.md) |

Back up `server.key` before you do anything else. Losing it changes the server's DID, so
the server comes back as a different identity: its receipts are signed by a new key, and
federation peers that list it by `expected_did` hold a stale value. Clients do not pin the
server's DID yet. Once they do (the handshake in JEP-0002 and threat-register OP-08), a
lost key will look like a man-in-the-middle to every client. `deploy/README.md` opens
with this for a reason.

[`CONTRIBUTING.md`](CONTRIBUTING.md) covers the implementation, the DAG rule, and how to send a change. [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) is the community standard. [`repos/jig-spec/CONTRIBUTING.md`](repos/jig-spec/CONTRIBUTING.md) is the spec-only guide.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))

at your option. This is the customary Rust dual licence, chosen deliberately: a protocol
that cannot be embedded is not a protocol, so every crate you would need to speak jig —
`jig-core`, `jig-client`, `jig-server`, `jig-pipeline`, `jig-runtime`, `jig-nameserver`,
`jig-config`, `jig-cli`, the bridges, and the sample blocks — is permissively licensed for
any use, commercial included.

One deliberate exception:

| Scope | Licence | Why |
| --- | --- | --- |
| [`repos/jig-spec/`](repos/jig-spec/) | CC-BY-4.0 | The written specification, not code. Attribution only, no share-alike, so implementation guides and second implementations can reuse the text freely. |

Riverdance, the unfinished GUI, is not part of this repository. Its licence is undecided.

### Contribution

Unless you state otherwise, any contribution you intentionally submit for inclusion in the
work, as defined in the Apache-2.0 licence, shall be dual-licensed as above, without any
additional terms or conditions.

## Relationship to gigue

jig is sponsored by gigue, which builds a closed-source product of the same name. The
dependency direction is one-way and enforced as a rule: **gigue may depend on jig; jig
never depends on gigue.** No gigue code is in this repository.
