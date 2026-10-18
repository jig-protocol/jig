# jig-server

Reference server implementation for the Jig protocol.

## Overview

`jig-server` stores signed blocks per channel and fans them out to subscribers over
WebSocket. It verifies every block's signature and runs the admission, write and suite
gates before storing it. For plaintext `text-render` blocks it executes its own canonical
Wasm module and signs a receipt. For encrypted (MLS) channels it validates commits and
stores ciphertext; it holds no group secret.

## Features

- **SQLite block store** for blocks, receipts, channels and memberships
- **Signed reads and writes**: per-request proofs of possession, channel membership gates,
  admission policy and per-DID / per-address rate limits
- **MLS delivery service** for encrypted channels and DMs
- **Wasmtime runtime** (fuel, memory and time limits) for the canonical `text-render` block
- **Federation** with configured, DID-pinned peers
- **TLS on by default**, with a self-signed certificate the server's DID vouches for
- **Config-as-code** via `jig-config.toml`

## Quick Start

```bash
# Write a config template
jig-server --init-config jig-config.toml

# Start with defaults (SQLite under ~/.jig/jig.db)
jig-server

# Start using a specific config file
jig-server --config jig-config.toml

# Override a few fields on the CLI. Bind loopback or a tailnet address —
# the server authenticates reads and gates channels, but nothing limits
# who may reach it (see deploy/README.md, "Security model").
jig-server --db-path /tmp/jig.db --bind 127.0.0.1 --port 7117
```

## HTTP API

The v0.0.2 surface, mounted by default:

| Endpoint | Method | Description |
| --- | --- | --- |
| `/.well-known/jig` | GET | Server DID, version, `unsafe_options_active` |
| `/healthz`, `/metrics` | GET | Liveness; Prometheus counters (restricted channels share one label) |
| `/api/v1/ws` | WSS | `Subscribe` (signed), `Submit`, `Block`, `Ack`, `Error` frames |
| `/api/v1/blocks` | POST | Submit a signed block bundle (`{bundle_b64, sig_b64}`) |
| `/api/v1/blocks/{cid}` | GET | One block and its receipts — signed read, channel-gated |
| `/api/v1/channels` | GET | Channels the caller may read — signed read |
| `/api/v1/channels/{slug}/blocks` | GET | Channel timeline — signed read, membership-gated |
| `/api/v1/channels/{slug}/members` | GET | Channel members and roles — signed read, same gate as the timeline |
| `/api/v1/channels[/{slug}/members\|archive]` | POST | Channel ops as signed blocks (create, add/join, archive). Other ops (`member-remove`, `channel-promote`) go through `POST /api/v1/blocks` |
| `/api/v1/mls/key-packages` | POST | Publish MLS key packages (`{key_packages_b64: [..]}`); each must be signed by, and name, its DID |
| `/api/v1/mls/key-packages/{did}` | GET | Take one of a DID's key packages (consumed unless last-resort) — signed read |
| `/api/v1/mls/key-packages/{did}/stock` | GET | How many a DID has left — signed read |
| `/api/v1/channels/{slug}/mls/group-info` | GET | Newest MLS group info of an encrypted channel, for joining by external commit — signed read, channel-gated |
| `/_admin_v0_0_2/channels[/{slug}/members\|archive]` | POST | Legacy aliases of the channel ops; mounted only with `[debug] admin_endpoints = true` |

Reads carry five `x-jig-*` headers with an ed25519 proof over the request
(`jig_client::ReadProof`); `jig channel list`, `jig chat`, `jig read` and `jig tail` sign
for you. A bare `curl` gets `401 AUTH_REQUIRED`.

The v0.0.1 REST routes (`/blocks`, `/blocks/{cid}`, `/receipts/{cid}`) and their
`dangerously_enable_v0_0_1_rest` flag were removed (D28); those paths answer `404`.

## License

Dual-licensed under MIT OR Apache-2.0, at your option. See [`LICENSE-MIT`](../../LICENSE-MIT) and [`LICENSE-APACHE`](../../LICENSE-APACHE).
