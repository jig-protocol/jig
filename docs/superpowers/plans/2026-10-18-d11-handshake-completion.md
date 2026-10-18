# D11 handshake completion: build plan

Date: 2026-10-18. Design:
[`specs/2026-10-18-d11-handshake-completion-design.md`](../specs/2026-10-18-d11-handshake-completion-design.md)
(jig-protocol/jig#136). Lane L7.

Each slice is one PR off `main`, branch `type/<description>`, opened as a draft,
validated locally as CI does (`cargo fmt --check`, `cargo clippy --workspace
--all-targets -- -D warnings`, the changed packages' tests, and the integration tests a
slice touches), then marked ready. Build with `CARGO_INCREMENTAL=0`. Each slice that
changes behaviour updates JEP-0002's "v0.2 scope" status line, the threat-register rows
the design proposes for it, and the matching status evidence in
`docs/security/operator-threat-model.md` (once L1 has merged; until then the slice
lists the rows in its PR body).

v0.x has no compatibility guarantee. Every slice that changes the wire changes the
server and the client together, so `main` never holds one side without the other.

## Order and dependencies

| # | Slice | Depends on | Files (L7 unless noted) |
| --- | --- | --- | --- |
| 0 | TLS exporter hook | — | `jig-server/src/server.rs` (`serve_tls` only, agreed with L3), `jig-pipeline/src/handshake.rs` |
| 1 | Close classes, signed refusal, one `hello`, frame and receipt checks | — | `jig-pipeline/src/handshake.rs`, `jig-pipeline/src/envelope.rs` (new frames), `jig-server/src/v0_0_2_ws.rs` (handshake code), `jig-client/src/connection.rs`, `jig-server/src/v0_0_2_federation.rs` (`complete_client_handshake`) |
| 2 | Restricted ⇒ MLS; plaintext REST refused | L3's #124 (https default) | `jig-client/src/pins.rs`, `jig-cli/src/cmd/trust.rs`, the jig-cli smoke tests L3 listed |
| 3 | Skew bound | 1 | `jig-pipeline/src/ingest.rs` (step 3), `jig-pipeline/src/handshake.rs`, `jig-config/src/v0_0_2_server.rs` (the flag and the new key; coordinate with L3's config collapse), `integration-tests/tests/h7_unsafe_advertised.rs` |
| 4 | `ingest` records | 1 | `jig-pipeline` (new `ingest_record` module, `persist.rs` table, `fanout.rs`), `jig-pipeline/src/envelope.rs` (`ingest` on `block`, new `record` frame), REST history, `jig-client` (chain state, checks) |
| 5 | `seen`, head gossip, fork check; `ends` on removes | 4 | `jig-core` manifest fields, `jig-client/src/blocks.rs`, `jig-pipeline/src/authorize_write.rs` (`ends`), `jig-server/src/v0_0_2_ws.rs` (`head`), federation forwarding |
| 6 | Evidence and sticky refusals | 1, 4 | new `jig-client/src/evidence.rs`, `jig-client/src/pins.rs`, `jig-cli/src/cmd/trust.rs` (`jig trust evidence`, `jig trust accept`) |
| 7 | Manifest log | 4 | server bootstrap of the reserved channel, `server-manifest` kind, welcome `manifest`, client check, `jig trust show` |
| 8 | Mutual server-to-server handshake with channel binding | 0, 1 | `jig-pipeline/src/handshake.rs` (`peer_proof`, transcript hash), `jig-client/src/connection.rs` (exporter from `MaybeTlsStream`), `jig-server/src/v0_0_2_ws.rs`, `jig-server/src/v0_0_2_federation.rs` |
| 9 | Name pinning | — | `jig-client/src/pins.rs` (`names`), `jig-cli/src/cmd/trust.rs` (`accept-name`, expiry warning); resolution call sites belong to F/L6 |
| 10 | `sequencer-set` and handover | 4, 7, F's contract | `jig-pipeline` (kind, expected-sequencer rule), `jig-client` chain checks |

Slices 2 and 9 do not touch the wire and can run alongside 1. Slice 3 is small and can
follow 1 at once. 4 is the largest and gates 5, 6, 7 and 10.

## Slice details

### 0. TLS exporter hook

- `serve_tls` exports 32 bytes under `TLS_EXPORTER_LABEL` from each TLS session and
  puts `TlsExporter` in every request's extensions.
- Test: each TLS session's requests carry a 32-byte value, and two sessions differ.
- Nothing reads it until slice 8; the hook lands first because L3 has open PRs in
  `server.rs`.

### 1. Close classes and later-frame checks

- `refusal` frame, sealed under `jig-handshake-refusal-v1`; `HandshakeResult` gains
  `Incompatible(VerifiedRefusal)` and loses `LeaveOpen`.
- Server: answers `UNSUPPORTED_VERSION`/`UNSUPPORTED_SUITE` with a signed refusal and
  closes 4002; a frame before `hello`, a second `hello`, or a client frame outside its
  offer gets an error and close 4004.
- Client: closes 4001 on handshake failure and 4003 on a contradiction; the reader
  classifies unparseable frames instead of dropping them; receipts are checked against
  `welcome.server_did`; a `KIND_NOT_ALLOWED` for an advertised kind is a contradiction;
  a refusal that omits a pinned suite is a contradiction.
- Federation dialer: the same result handling in `complete_client_handshake`.
- Tests: one per class and code, in `handshake.rs` unit tests and the `v0_0_2_ws.rs`
  socket tests (the existing `frame_before_hello_is_refused_and_the_socket_stays_open`
  and `version_and_suite_refusals_leave_the_connection_open` tests change to assert the
  close).

### 2. Restricted ⇒ MLS; plaintext REST refused

- `prove_channel` refuses a restricted `channel-create` whose suite is `none`.
- `trust::server_tls`/`trust::http` refuse `http://` unless the host is loopback, with
  a message naming `jig server set https://…`.
- Tests: `pins.rs` unit test; CLI smoke tests that expected a plaintext connection
  failure still pass on loopback; a non-loopback `http://` is refused.

### 3. Skew bound

- Config key `max_future_skew_ms` (default 300 000, 30 000–900 000, refused at boot
  outside the range); advertised in `capabilities`; covered by the welcome signature.
- Ingest refuses a block more than the bound ahead with `CLOCK_SKEW` and the server's
  time; `update_on_receive` only within the bound.
- `naively_unbounded_clock_skew` removed from `unsafe_options_active`; h7 updated.
- Client: class 1 on a bound outside the range.

### 4. `ingest` records

- `IngestRecord { channel_id, seq, ingest_hlc, block_cid, prev, sequencer, sig }`,
  canonical bytes under `jig-ingest-v1`; signed in `ingest` after the write gate, in
  the same transaction that stores the block; `seq` 0 is the `channel-create`.
- Storage: one row per block (`ingest_records`), indexed by channel and `seq`.
- Delivery: `block` frames and REST history carry the record; a `record` frame for a
  block the reader may not read.
- History reads order by `seq`.
- Client: per-channel chain state in the pin store; the checks of design item 5; a
  failure is class 3.
- Migration: existing channels get records at first boot, in `hlc_ts` order, signed by
  the server (pre-release data; the PR says so).
- Federation: relayed blocks keep the owner's record; a carrier never re-signs.

### 5. `seen`, gossip, forks; `ends`

- Manifest `seen` (full record) on every authored block except `channel-create`;
  `member-remove` gains `ends`, checked by the write gate.
- `head` frame: client → carrier; carrier verifies, keeps the latest per channel,
  forwards on federation links.
- Client fork and reorder checks of design item 6.
- Tests: a two-chain server in the test harness is caught through `seen` and through
  `head`; a replayed self-leave is refused on a second server.

### 6. Evidence and sticky refusals

- `jig-evidence-v1` writer; the pin store records a sticky refusal per server with the
  bundle path.
- `jig trust evidence list|show|export|import`, `jig trust accept <server>`.
- Tests: each class 3 path writes a bundle that verifies offline; timeouts and
  malformed frames never make a refusal sticky; an imported bundle never does.

### 7. Manifest log

- The server creates its manifest-log channel at first boot and publishes a
  `server-manifest` (with F's peer-policy fields, empty until F's build) whenever its
  advertised facts change; the write gate refuses other kinds and other writers.
- `welcome.manifest`; the client fetches and compares it, and pins the chain.
- `jig trust show <server>`.

### 8. Mutual handshake

- `hello.peer_did`, `welcome.server_nonce` and `welcome.tls_exporter` (signed),
  `peer_proof` under `jig-handshake-peer-v1` over the transcript hash.
- The dialed server requires `peer_proof` when `peer_did` is set, closing 4001
  otherwise; the connection is then symmetric, with authorization left to F's rules.
- Client: exporter from the rustls connection inside `MaybeTlsStream`; an empty
  exporter on a TLS connection is class 1.
- Tests: a relayed handshake between two TLS sessions fails; a dialer without a proof
  is closed.

### 9. Name pinning

- `names` map in the pin store; a change moves only with a rotation signed by the old
  key; otherwise refused with the reason and both fingerprints.
- `jig trust accept-name <name>`; a warning before an attestation expires.
- Resolution itself is F's and L6's; this slice provides the check they call.

### 10. `sequencer-set`

- The kind (owner-only), its record signed by the new sequencer at cited head + 1, and
  the expected-sequencer rule in client checks; carriers refuse the old sequencer's
  later records.
- Lands with or after F's contract build.

## Done

Exit criterion 3 is met when slices 1, 3, 4, 6 and 7 are merged and the threat-register
rows for OP-01, OP-02 and TM-01 read as the design proposes. Slices 5, 8, 9 and 10 close
OP-06, OP-09 and OP-08 and are part of v0.2 under B′.
