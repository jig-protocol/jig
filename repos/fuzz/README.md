# jig fuzz targets

cargo-fuzz targets over what jig decodes from the network. It is its own
workspace: cargo-fuzz builds it with nightly and sanitizer flags.

| Target | What it decodes |
| --- | --- |
| `dcbor` | deterministic CBOR; whatever decodes must re-encode to the same bytes |
| `cose` | COSE_Sign1 / COSE_Sign, and the JEP-0005 contract envelopes (offer, accept, refuse, end), raw and re-signed with a fixed key |
| `ingest_record` | `IngestRecord::decode`, then its payload, hash and signature check |
| `peer_frames` | the follower stream's `channel-records`, `records-from`, `records-later` (jig-server's `fuzzing` feature) |
| `envelope` | the WebSocket `Envelope`, and the handshake's reading of a welcome |
| `mls_delivery` | key packages, group infos, genesis and state snapshots, as the server's delivery service reads them |
| `mls_group` | commits and application messages against a live two-member group: the server's checks and a member's `decrypt` |
| `wasm_component` | a block's Wasm component, validated and compiled as a renderer |

## Running

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz
cd repos/fuzz
cp ../Cargo.lock Cargo.lock    # fuzz the versions jig ships
cargo +nightly fuzz run -O dcbor -- -max_total_time=60
```

CI (`.github/workflows/fuzz.yml`) runs every target for 30s on a pull request
touching one of the decoders, and as long as asked from `workflow_dispatch`.

## Reproducing a crash

A failing run uploads `artifacts/<target>/crash-*` as the `fuzz-crashes`
artifact. Then:

```bash
cargo +nightly fuzz run -O <target> path/to/crash-<hash>
```

## jig-server's `fuzzing` feature

`peer_frames` calls `jig_server::v0_0_2_stream::fuzz_decode_frame`, compiled
only with jig-server's `fuzzing` feature. Only this crate enables it; CI's
`workspace` job checks that no release binary does.
