# L3 legacy inventory: v0.0.1 vs v0.0.2 in the server, config and CLI

Date: 2026-10-18. Lane L3 of `docs/superpowers/plans/2026-10-18-v0.2-close-and-m3-start.md`.

This lists every v0.0.1/v0.0.2 pair in the files L3 owns: what still uses each item, what to do
with it, and how its use was checked. Evidence is file:line on `main` at `d16f26a`, plus
jig-protocol/jig#107 (slice 1, D28), which removes the v0.0.1 REST routes.

**Actions**
- **delete**: no production path calls the item. Searched callers and green tests show it.
- **fix**: the item stays but is wrong.
- **ask**: DJ decides. Nothing is deleted until then.

Removals go one PR per area (slice 3). None of them changes behaviour. Each PR names what it
removed and how it showed that nothing used it.

## Summary

| # | Area | Old | Keep | Action |
|---|---|---|---|---|
| 1 | Server ingest | v0.0.1 REST (`POST`/`GET /blocks`, `/blocks/{cid}`, `/receipts/{cid}`) | v0.0.2 `/api/v1/blocks*` | Done in #107 |
| 2 | Server storage | `jig.db` (`storage.rs`, `SqliteBlockStore`) | `jig_v002.db` (`jig-pipeline::persist`) | delete, after Q1 |
| 3 | Server runtime | `BlockRuntime` and `[execution]` pricing keys | `v0_0_2::runtime_config_from` | delete (L2 owns `runtime/`); ask Q2 |
| 4 | Server config, file discovery | `try_load_jig_config_from_well_known` (reads jig-config `[storage.truth]`) | `--config` file | ask Q3 |
| 5 | Channel ops | `/_admin_v0_0_2/*` aliases, CLI 404 fallback | `/api/v1/channels*` | delete CLI fallback; ask Q4 about server aliases |
| 6 | jig-config | 12 legacy modules, 3 orphan files | `v0_0_2_server`, `default_config_path` | delete |
| 7 | CLI HTTP | `JigHttpClient` | `cmd::trust::http` | delete; ask Q5 about `receipt --block` |
| 8 | CLI `block` | `init` templates, `lint`/`sign`/`verify`/`capabilities` stubs, `run` ABI | — | ask Q6, Q7 |
| 9 | CLI docs and Cargo | stale plan docs, `daemon` feature, unused `jig-config` dependency | README | delete / fix |

## 1. Server ingest: v0.0.1 REST (done, #107)

- **Removed:** `POST /blocks`, `GET /blocks`, `GET /blocks/{cid}`, `GET /receipts/{cid}` and the
  `dangerously_enable_v0_0_1_rest` flag.
- **Clients that used them:** none in production.
  - `jig read` and the no-subcommand send already use the v0.0.2 routes
    (`repos/jig-cli/src/main.rs:637-640`, `:775-778`).
  - `JigHttpClient::get_block` (the old `GET /blocks/{cid}` client) is dead code (see §7).
- **Docs follow-ups for L1:** listed in the #107 PR body.

## 2. Server storage: `jig.db` vs `jig_v002.db`

**What still reads `jig.db`:** after #107, nothing reads it.
- `SqliteBlockStore` is opened only by `server.rs::boot_checks`, which opens the file and runs
  its health check.
- Its types (`StoredBlock`, `StoredReceipt`, `StoredResource`, `StoredBlockSummary`,
  `encode_resource_data`) are re-exported from `lib.rs:26-29`, but no other crate uses them.
  - `integration-tests` and the v0.0.2 modules use the `jig_pipeline::persist` types of the
    same names.

**What `database_path` still does:** the key stays, even though the file it names is dead.
- It anchors the v0.0.2 database: `main.rs:143-150` derives `<stem>_v002.db`.
- It anchors the v0.0.2 key and the TLS directory (`server.rs` `start`, `tls/` next to the
  database).

**Side effects that removing the store would lose:**
- `SqliteBlockStore::new` runs `create_dir_all` on the parent directory.
  - The v0.0.2 store does this itself (`jig-pipeline/src/persist.rs:330`,
    `jig-server/src/v0_0_2.rs:341`), and it is created before `JigServer`. So nothing is lost.
- A boot fails if `jig.db` can't be opened.
  - The v0.0.2 store makes the same check on the same directory. It only warns, though: the
    v0.0.2 module degrades to "running without it" (`main.rs:166-170`). That warn-and-continue
    is a separate problem (Q1).

**Action:** delete `storage.rs`, its re-exports, and the `jig.db` half of `boot_checks`.
- An operator's existing `jig.db` stays on disk, unread. The release note should say it can be
  deleted.

**Q1:** should a v0.0.2 init failure be fatal? Today the server boots with only
`/.well-known/jig`, `/healthz` and `/metrics` and logs a warning. That is a behaviour change, so
it goes in a separate PR.

## 3. Server runtime: `BlockRuntime` and `[execution]` pricing

- **`BlockRuntime`** (`repos/jig-server/src/runtime/mod.rs:75`, owned by L2): after #107 it is
  only constructed (in `boot_checks`, to validate `[execution]`) and never executes anything.
  - The v0.0.2 path builds its own runtime config in `v0_0_2.rs:86`
    (`runtime_config_from`).
- **`[execution] pricing_enabled` and `cost_per_fuel`** (`config.rs:121`, mapped at `:283`):
  only `BlockRuntime::new` reads them (`runtime/mod.rs:108-113`), and `runtime_config_from` does
  not map pricing. So these keys have done nothing on any live path since #107.
- **`ExecutionConfig.host_id`**: same situation. It is separate from `ServerConfig.host_id`,
  which `/.well-known/jig` still serves.

**Action:**
- L3 removes the pricing keys from `ServerConfig`. Slice 4 gives them a "removed key" error.
- L3 replaces the `BlockRuntime` half of `boot_checks` with a direct
  `jig_runtime::RuntimeConfig::validate()` on `runtime_config_from` output.
- L2 decides whether `BlockRuntime` and `runtime/mod.rs`'s v0.0.1 receipt mapping go. This goes
  to L2 through the orchestrator.

**Q2:** were the pricing keys meant to come back with the M3 pricing work? If so, they come back
in the design that uses them. They don't stay as dead keys.
- On hold: L2's hazard-2 PR, which signs the pricing schedule version actually in force, will
  show which keys are live. No pricing key is dropped before that PR lands.

## 4. Server config: hybrid file discovery

`ServerConfig` and `JigServerConfig` are two types read from one file, and neither uses
`deny_unknown_fields` (`main.rs:105-109`, `jig-config/src/v0_0_2_server.rs:439-442`). Slice 4
merges them into one struct with `deny_unknown_fields` (roadmap item 17).

**The path that doesn't fit:**
- With no `--config`, `ServerConfig` loads `./jig-config.toml`, then `~/.jig/config.toml`
  (`config.rs:184-200`).
  - It reads only `storage.truth.connection_string` (sqlite) into `database_path`, through
    `jig_config::storage::MultiTierStorageConfig` (`config.rs:155-180`).
  - `JigServerConfig` falls back to defaults in the same case (`main.rs:44-49`).
- So a server started without `--config` takes its database path from the v0.0.1 jig-config
  file, and takes everything else from defaults. That file is not the CLI's: the CLI moved to
  `~/.jig/cli.toml` (`repos/jig-cli/src/config.rs:106-115`).
- This is jig-server's only production use of `jig_config::storage`.

**Q3:** drop this discovery in slice 4, so that only `--config` (or `JIG_DB_PATH` /
`--db-path`) sets the database path? I recommend dropping it.
- Dropping it changes behaviour only for a deployment that runs without `--config` and relies on
  a `[storage.truth]` table. The shipped systemd unit and `install.sh` both pass `--config`.

## 5. Channel ops: `/_admin_v0_0_2/*` aliases vs `/api/v1/channels*`

**Server:**
- `/api/v1/channels`, `/{slug}/members` and `/{slug}/archive` are always mounted
  (`v0_0_2_admin.rs:286-294`).
- The `/_admin_v0_0_2/*` aliases run the same handlers. They mount only under
  `debug.admin_endpoints` (`v0_0_2_admin.rs:296-308`, `v0_0_2_ws.rs:258-262`), which is
  advertised in `unsafe_options_active`.

**CLI:** `post_channel_op` retries on the alias after a 404 or 405
(`repos/jig-cli/src/cmd/channel.rs:126`, `:141-151`; help text at `main.rs:142-145`).
- That retry only helps a server older than the `/api/v1/channels` routes.
- `post_channel_op` is shared by create (L4), join and delete.

**Tests that call the aliases directly:**
- `integration-tests/src/harness.rs:296-334`, which turns the flag on by default at `:89-116`.
- `jig-server/tests/support/mod.rs:200-248`.
- `boot_config.rs:62` and `h5_tofu_mismatch.rs:213` set the flag.
- `h7_unsafe_advertised.rs:59,135` asserts the flag is advertised.
- `scripts/` has no hits.

**Action:**
- Delete the CLI fallback once L4's channel-creation change lands, so the two edits to
  `channel.rs` don't collide.
- Moving the test harnesses to `/api/v1/channels*` is a test-only change.

**Q4:** do the server aliases and `debug.admin_endpoints` go too?
- `admin_endpoints` gates only these aliases (`v0_0_2_ws.rs:259`). Removing the aliases would
  make the key dead, so slice 4 would turn it into a removed-key error.
- The routes themselves are in `v0_0_2_admin.rs`, outside the files L3 owns. That needs a small
  separate PR or the owner's agreement.

## 6. jig-config: legacy modules vs `v0_0_2_server`

**Production users outside the crate:**
- `v0_0_2_server`: jig-server and jig-nameserver.
- `default_config_path`: jig-server `config.rs:194`, jig-nameserver `config.rs:110`.
- Three `storage` types: jig-server `config.rs:159,172` (see §4).

No other module has a production caller.

| Module | Lines | Users | Action |
|---|---|---|---|
| analytics | 717 | `tests/analytics.rs` only | delete |
| audit | 524 | `tests/audit.rs` only | delete |
| bridges | 1406 | `tests/bridges.rs` only. jig-server's `[bridges]` is `v0_0_2_server::BridgesSection` | delete |
| execution | 802 | own unit tests only | delete |
| interop | 816 | `bridges`, `tests/interop.rs` | delete |
| nameserver | 1261 | `tests/nameserver.rs`, `examples/validate_nameserver_configs.rs`. jig-nameserver has its own config | delete |
| pricing | 599 | `tests/pricing.rs` only | delete |
| profiles | 266 | the modules above, `storage` helpers, tests, `examples/config_generator.rs` | delete |
| receipt | 562 | `tests/receipt.rs` only | delete |
| storage | 594 | jig-server `config.rs:155-180` (§4) | delete after Q3, or inline the 3 types into jig-server |
| templates | 549 | `examples/config_generator.rs` only. Its `path = "~/.jig/jig.db"` output is stale | delete |
| validation | 609 | own unit tests only | delete |
| lib.rs runtime types (`EngineKind`, `RuntimeConfig`, …) | — | `tests/podman_toml.rs:20` only | delete |
| `deployment.rs`, `features.rs`, `network.rs` | 273 | not declared in `lib.rs`, never compiled (`deployment.rs:41-68` would not compile) | delete |

**Also goes with them:**
- The matching `tests/*.rs` files.
- `examples/config_generator.rs` and `examples/validate_nameserver_configs.rs`.
- The example TOMLs: `hyperscale`, `potato` and `nameserver-*`.
- The crate's planning docs: `README.md` (rewritten to cover `v0_0_2_server`), `MIGRATION.md`,
  `PHASES.md`, `IMPLEMENTATION_PLAN.md`, `IMPLEMENTATION_SUMMARY.md`, `PROGRESS_UPDATE.md`,
  `NAMESERVER_INTEGRATION.md`, `BRIDGE_INTEROP_STRATEGY.md`. `SECURITY.md` stays.

**Unused dependencies on jig-config:**
- jig-cli (`Cargo.toml:76`, optional, enabled by no feature): L3 removes it.
- jig-pipeline (`Cargo.toml:11`) and jig-client (`Cargo.toml:12`): no `jig_config` use in any
  `.rs` file, but they are outside L3's files. They go to their owners (L2 and L7).

**Ordering:** the jig-config deletion goes in after slice 4, or slice 4 lands first. Slice 4 moves
the server struct, and with it the server's last `storage` use.

## 7. CLI HTTP: `JigHttpClient` vs `cmd::trust::http`

**`JigHttpClient`** (`repos/jig-cli/src/http_client.rs`, 56 lines):
- A plain `reqwest::Client` with no pinning and no signing.
- Its only method, `get_block`, is `#[allow(dead_code)]` and targets the removed
  `GET /blocks/{cid}`.
- `main.rs:598` constructs it for every command not dispatched earlier.

**Its only consumers:** `jig receipt view --block` and `jig receipt compare --block`
(`main.rs:687,711`).
- Both reach `fetch_receipt_from_server` (`cmd/receipt.rs:170-179`). That function ignores its
  arguments and always returns "not yet implemented … Server needs /receipts/{cid} endpoint".
- So `--block` has never worked on any server, TLS or not. The card's "breaks against TLS
  servers" understates it.

**Action:** delete `http_client.rs`, the construction at `main.rs:598`, and the `JigHttpClient`
parameters.

**Q5:** for `--block`, which option?
- (a) Remove the flag.
- (b) Reimplement it on `GET /api/v1/blocks/{cid}` with `trust::http` and a signed read proof,
  as `cmd/history.rs:74-82` does. It would decode `receipts[*].receipt_bytes_b64`.

(b) is a feature, not a deletion, so it would be its own PR. I recommend (a) now and (b) with
the Dv developer loop.

## 8. CLI `block` surface

The `local-runtime` feature is on by default.

**Stubs:** `lint`, `sign`, `verify` and `capabilities` each print
"not yet implemented in v0.0.1 (waiting for jig-core …)" and exit 1 (`main.rs:740-768`).
- **Action:** remove them until Dv rebuilds the developer loop. This is the plan's proposal; it
  needs a yes from DJ (Q6).

**`init` templates** (`cmd/block_init.rs`, `templates/`):
- **Target:** `.cargo/config.toml` sets `target = "wasm32-wasi"` (`block_init.rs:187-191`). The
  pinned toolchain ships `wasm32-wasip1` and `wasm32-unknown-unknown` (`rust-toolchain.toml`).
- **Entry point:**
  - The rust template exports `execute() -> i32` and `metadata()`.
  - `jig block run` looks for `run`, `_start` or `main` (`jig-runtime/src/api.rs:173-182`,
    `:492-500`), so a scaffolded rust block can't run.
  - Neither convention is the payload ABI (`jig_alloc`/`execute_payload`) that `text-block` and
    the server's render path use.
- **Validator rejects:** the templates call the clock (`chrono::Utc::now()`, Go `time.Now()`)
  and pull in f64 code through serde_json / `encoding/json`.
- **Next-step text:** it tells users to run `jig block lint .` (a stub) and `jig send --block .`
  (no such flag).
- **Action:** ask (Q6). I recommend removing `init` together with the stubs. Fixing it means
  picking the ABI, which is design track A's decision.

**`jig block run`** (`cmd/block_run.rs`, `runtime.rs:56-88`):
- It calls `Runtime::execute`, which takes an argument-less `run`/`_start`.
- `--seed` fills only 8 of the 32 seed bytes (`runtime.rs:77-82`).
- `--pricing` uses an f64 cost (`block_run.rs:68-73`).
- It works only for modules that export `_start`/`run`, such as TinyGo output. It doesn't work
  for `text-block`.
- **Q7:** keep `run` until track A settles the ABI, or remove it now? The card says to ask before
  removing it. I recommend keeping it: the plan's ABI row says both stay until A decides.

## 9. CLI docs, Cargo items and small fixes

| Item | Evidence | Action |
|---|---|---|
| `ALIGNMENT_SUMMARY.md`, `JIG_CLI_IMPLEMENTATION_PLAN.md`, `IMPLEMENTATION_ROADMAP.md`, `PHASE_E_PROGRESS.md` | 2025-11 plans, "awaiting approval" or "pending". They describe `http_client.rs` and `wasm32-wasi` | delete |
| `RUNTIME_INTEGRATION.md` | M3.2 notes, partly current. Doesn't mention the payload ABI | fold anything still true into the README, then delete |
| `README.md:14-15` | says `jig read` still calls `/blocks`; it doesn't | fix |
| `Cargo.toml` `daemon = []` | never used in `src` | delete |
| `Cargo.toml:27-30` comment | "legacy until Phase F" | fix |
| `main.rs:416` help | nameserver "e.g. http://127.0.0.1:7118"; the default is 7070 (`jig-nameserver/src/config.rs:1791`) | fix (slice 6) |

**Kept on purpose:**
- Plain-HTTP nameserver clients (`cmd/ns.rs:149-154`, `cmd/init.rs:168`, `cmd/keys.rs:102,211`).
  The nameserver is not DID-pinned; that is L6's area.
- The deliberate plaintext probe in `cmd/trust.rs:80`.

## 10. What still uses plaintext `http://` to a jig-server

DJ decided the client refuses plaintext REST for now; L7 builds the refusal in `cmd/trust.rs`
after #107. These are the things that refusal would break, and what to do about each one.

| Dependent | Evidence | What breaks | Proposed handling |
|---|---|---|---|
| `JigHttpClient` | `repos/jig-cli/src/http_client.rs:16`, built at `main.rs:598` | Nothing at runtime: its only method is dead code (§7) | L3 deletes it before L7's refusal lands (no open question blocks this) |
| CLI default server URL | `repos/jig-cli/src/config.rs:46`: `base_url = "http://127.0.0.1:7117"` | With no `--server` and no `cli.toml`, every REST command is refused. The server's default is TLS on (`[tls] enabled = true`), so this default already disagrees with a default server | Change the default to `https://127.0.0.1:7117` in the same PR as the refusal, or just before it (L3 owns the file; L7 sequences it) |
| `scripts/demo-e2ee.sh` | `:43` uses `https://` | Nothing | none |
| `integration-tests` harness | `src/harness.rs:221-222`, `:456-457` (`http://`), `:217-218` (`ws://`) | The tests call it with raw `reqwest` and `jig_client::Client` over `ws://`, not through `cmd::trust`, so a refusal in `trust.rs` doesn't reach them. A refusal added in `jig-client` itself would | none if the refusal stays in `cmd/trust.rs`; otherwise the harness needs TLS (L7) |
| `jig-cli/tests` | `global_flags.rs:23,143,158`; `send_tail_smoke.rs:68,110,151`; `channel_smoke.rs:139`; `server_smoke.rs:21,152`; `keys_smoke.rs:84`; `ns_smoke.rs:16,23` | Most of these point at a closed port (`http://127.0.0.1:1`) and expect a connection failure. A refusal fails them earlier, with a different message. `global_flags.rs:143-158` sets an `http://` server and checks that it is used. `server_smoke.rs:21` only writes config | L7 updates these in the refusal PR: switch them to `https://` or assert the refusal message |
| Nameserver clients | `cmd/ns.rs:149-154`, `cmd/init.rs:168`, `cmd/keys.rs:102,211` | Nothing, if the refusal applies only to jig-server REST. The nameserver is not DID-pinned | none; L6's area |

## Questions for DJ

1. **Q1.** Should a failed v0.0.2 module init stop the boot instead of warning?
2. **Q2.** Do `[execution] pricing_enabled` and `cost_per_fuel` go? They have no live reader.
3. **Q3.** Drop the `jig-config.toml` / `~/.jig/config.toml` discovery for the server's
   `database_path`? (Recommended.)
4. **Q4.** Do the server's `/_admin_v0_0_2/*` aliases go with the CLI fallback?
5. **Q5.** For `jig receipt --block`: (a) remove it now (recommended), or (b) reimplement it on
   `/api/v1/blocks/{cid}`?
6. **Q6.** Remove `jig block init`, `lint`, `sign`, `verify` and `capabilities` until Dv?
   (Recommended.)
7. **Q7.** Keep `jig block run` until track A settles the ABI? (Recommended.)
