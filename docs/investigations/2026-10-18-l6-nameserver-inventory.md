# jig-nameserver module inventory (lane L6)

**Status:** inventory complete. Deletions wait for DJ's checkpoint on lane F's design, as the [plan](../superpowers/plans/2026-10-18-v0.2-close-and-m3-start.md) requires. The exception is code that no design could claim; see "Delete now" below.
**Scope:** `repos/jig-nameserver/**` at `d16f26a`. Line counts are from `wc -l` and include inline tests. The crate has no `tests/` directory.
**Lane F's proposed claim** (draft #106, not yet reviewed by DJ): only the `v0_0_2_*` alias flow (register, resolve, renew, rotate), which F1 would change in place. It claims none of the legacy modules. The `/v1/handles` debug route stays with L6.

## Production paths

- **Binary** (`src/main.rs`):
  - `serve` (also the default) runs `server::run_http_server`, which calls `build_app_parts`.
  - `analyze` and `export` open `SqliteStorage` and run `AnalyticsEngine` against it.
- **`build_app_parts`** (`server.rs`):
  - mounts the legacy `app_router` (about 45 routes) plus four v0.0.2 routers;
  - opens `SqliteStorage`, and falls back to `MemoryStorage` if that fails;
  - always installs `DefaultFederationResolver`;
  - builds `FederationCoordinator` and its gossip loop only when `[federation].enabled`.
- **v0.0.2 routes:** `GET /v1/challenge`, `POST /v1/register`, `GET /v1/resolve/{alias}`, `POST /v1/rotate`, `POST /v1/renew`, and `GET /v1/handles` (only when `debug.list_handles`).
  - These files import no legacy module. They store data in `jig_pipeline::persist::SqliteStore` in a separate `_v002.db`, and sign with a separate `_v002.key`.
- **Callers outside the crate:**
  - `integration-tests` uses `build_app` and `build_app_parts`. The h10 test exercises the legacy surface only through `GET /v1/health` and `POST /v1/challenge`.
  - `jig-cli` and `jig-pipeline` call only v0.0.2 routes.
  - No client in the workspace calls a legacy route under `/v1/reputation`, `/tribunal`, `/work`, `/transparency`, `/receipts`, `/attestations`, `/anomalies`, `/hosts`, `/federation`, `/claim`, `/alias`, `/admin` or `/policy`.
- **CI** builds the crate with default features only. No `tier2-*`, `tier3-*` or `profiling` feature is built anywhere.

## Modules

Verdicts:
- **keep**: production needs it.
- **delete**: no caller, superseded, and no design claim.
- **F/R decides**: dead or a prototype that lane F (naming, lookups) or lane R (reputation, PoW, tribunals) might reuse; it waits for the checkpoint.

### Modules in `lib.rs` and the binaries

| Module | Lines | Production caller | What it does | Superseded by | Verdict |
|---|---|---|---|---|---|
| `discovery.rs` | 183 | **None. It is not in `lib.rs` and is never compiled.** It would not compile: it uses `trust_dns_resolver`, which is not a dependency. | Sketch of DNS endpoint discovery | `federation.rs` has the working SRV lookup | **delete** |
| `runtime.rs` | 348 | **None.** `NameserverRuntime` is constructed only in its own tests. `cfg.runtime` is read only here. | Runs blocks through jig-runtime with fuel limits and receipt signing | Nothing. v0.0.2 sets `executor: None` on purpose. | **F/R decides** (receipt verification is lane R / D23). Deleting it drops the `jig-runtime` dependency and its `wasi-preview2` and `receipt-signing` features. |
| `anomaly.rs` | 681 | Compiled in, but used only by tests. `escalate_anomaly` is the only writer of the anomaly and PoW-penalty tables, so the routes that read them always return empty results. | Receipt fuel and failure heuristics, cross-checks against peers, automatic escalation to tribunal and penalty | Nothing | **F/R decides** (R) |
| `transparency.rs` | 244 | `GET /v1/transparency/verify` calls `verify_chain`. Nothing in production appends to the log, so it is always empty. | Merkle roots and chained hourly hashes | Nothing | **F/R decides** (R / D23) |
| `federation.rs` | 418 | **Yes.** Legacy `GET /v1/resolve?name=` falls back to remote lookup. The gossip routes and loop run when enabled. | SRV discovery, then a plain-HTTP remote resolve whose result is cached. Gossip is a placeholder: it never contacts the peer and stores a fixed `blake3("placeholder-policy")`. | v0.0.2 does no recursion; it trusts on first use only. | **F/R decides** (F: lookups). Only this module uses `hickory-resolver` and `urlencoding`. |
| `pow.rs` | 62 | **Yes.** `POST /v1/claim` and `POST /v1/alias` | Hashcash with leading zero bits, keyed by the server secret (see lane R notes) | `GET /v1/challenge` + `POST /v1/register` (no PoW) | **F/R decides** (R / D26). D26 already rules out this design. |
| `hot/**` | 1198 | **None.** `create_hot_backend` is called only from tests, and `[hot]` config is never read. | KV trait with memory, Redis and Scylla backends | Nothing. Production keeps rate state in `NamesStorage`. | **delete**, pending DJ's call on the backends (see below). Drops `redis` and `scylla`. |
| `analytics/**` | 1546 | **CLI only** (`analyze`, `export`) through `SqliteAnalytics`. `BackendRegistry` is test-only, and `analytics.backend` is never read. | Aggregates over receipts, anomalies, penalties and useful work. Anomaly and penalty figures are always zero because nothing writes them. | Nothing | SQLite path and CLI: **F/R decides** (R). DuckDB and Parquet: DJ's call on the backends (see below). |
| `storage/sqlite.rs` | 2958 | **Yes**, behind every legacy route and the CLI | The legacy store: about 15 tables | Naming has moved to `jig_pipeline::persist::SqliteStore` | **keep** while legacy routes exist. Each table falls with the route group it serves. |
| `storage/mod.rs` | 1255 | **Yes.** It defines `NamesStorage` (64 methods). `MemoryStorage` is the production fallback and is also used by `perf`. | Trait plus in-memory backend | — | **keep**. The silent memory fallback should become a startup error (follow-up). |
| `storage/backends/**` | 802 | **None.** `create_storage_backend` has no caller, and `storage.backend`/`JIG_NS_STORAGE_BACKEND` are parsed but never used. | Postgres implements 8 of 64 methods; the other 56 return "not yet implemented", `rate_check_and_increment` among them. CockroachDB and TiDB are placeholders that return errors. | — | **delete**, pending DJ's call on the backends. Drops `sqlx`. |
| `crypto.rs` | 70 | **Yes.** `POST /v1/claim` | ed25519 check of a claim signature | `v0_0_2_register::verify_proof_of_control` | Goes with the claim/alias group (**F/R decides**) |
| `identity.rs` | 62 | **Yes.** It supplies the key `/.well-known/jig-ns` publishes. Its secret key is never used to sign. | Legacy nameserver ed25519 identity | `v0_0_2::load_or_generate_server_key` (`_v002.key`), which does sign attestations | **F decides**. The nameserver currently has **two identities**, and the well-known document advertises the one that signs nothing. |
| `types.rs` | 618 | **Yes**, across all legacy code | 38 legacy request/record types | v0.0.2 request and attestation types, for naming | Shrinks with the route groups |
| `config.rs` | 2351 | **Yes** | TOML, profile and environment loading. `validate()` **requires `JIG_NS_SECRET`** even though v0.0.2 uses no PoW. | — | **keep**. Never-read sections (`transparency`, `anomaly_detection`, `analytics`, `hot`, `storage.backend*`) go with their modules. |
| `error.rs` | 52 | Yes | Legacy error type | v0.0.2 has its own `ErrorBody` | keep |
| `bin/dns-txt.rs` | 34 | **None.** It is auto-built as `dns-txt`, not shipped by `release.yml`, and nothing refers to it. | Prints DNS TXT records from `[capabilities]` | — | **delete** (low stakes; DJ may keep it as an operator tool) |
| `bin/perf.rs` | 211 | **None.** It requires the `profiling` feature, which is never built. | Load driver for legacy challenge and resolve | — | **delete** with the legacy challenge flow. Drops `hdrhistogram` and `pprof`. |
| `v0_0_2*.rs` | — | **Yes** | The current alias flow | — | **keep**. F1 changes it in place. L6 makes bug fixes only until then. |

### Legacy route groups in `server.rs` (3115 lines, of which about 1125 are tests)

All of these are compiled into the binary and reachable through `serve`.

| Group | Writes reach production? | Superseded by | Verdict |
|---|---|---|---|
| Core: well-known, capabilities, policy, health, `GET /v1/resolve?name=` | n/a | `GET /v1/resolve/{alias}`. h10 checks `/v1/health`. | Health: keep. Well-known: F decides what it should advertise. Legacy resolve: F decides. |
| Admin: `/v1/admin/penalties`, `/v1/admin/rate` | yes | — | Goes with the legacy rate limiter |
| `POST /v1/challenge`, `/v1/claim`, `/v1/alias` | yes; legacy alias rows are never read back or reaped | v0.0.2 challenge, register, rotate and renew | **F/R decides**. F supersedes naming; R owns the PoW and difficulty logic. |
| Reputation (observe, summary, observations) | yes | — | **R decides** (D21, D23) |
| Tribunal (cases, decision, blocks) | yes; `/blocks/{cid}` has no production writer | — | **R decides** (D22, D23) |
| Useful work (enqueue, assign, result) | yes | — | **R decides** |
| Transparency (entries, hashes, verify) | no writer | — | **R decides** (D23) |
| Federation (peers, gossip, policy, runtime) | gossip is stored only | — | **F decides** |
| Receipts (submit, get, list) | yes | — | **R decides** (receipt format is lane A) |
| Attestations (submit, list) | yes | Unrelated to the v0.0.2 alias `Attestation` | **R decides** |
| Anomalies and host penalties | no writer | — | **R decides** |

## Optional backends: a question for DJ

None of the following has ever been built in CI. The plan's rule is: build them in CI, or delete them.

| Backend | Feature | Complete? | Can config select it? |
|---|---|---|---|
| Postgres | `tier2-storage` (`sqlx`) | No: 8 of 64 methods | No (`create_storage_backend` has no caller) |
| Redis/Valkey/Dragonfly | `tier2-hot` | Looks complete against the KV trait, but has never been compiled | No (`[hot]` is never read) |
| Scylla | `tier3-hot` | Same as Redis; `incr` is not atomic | No |
| DuckDB/Parquet | `tier2-analytics` (`duckdb`, `arrow`, `parquet`, `csv`) | DuckDB never ingests data. Every Parquet query returns an error, and `export_parquet` is a stub. | No (`analytics.backend` is never read) |
| ClickHouse | `tier3-analytics` (no dependencies) | Stub that returns an error | No |

L6's recommendation is to **delete all five.** None can be selected at runtime, Postgres is mostly stubs, and putting them in CI means maintaining four heavy dependency trees (`sqlx`, `redis`, `scylla`, `duckdb`+`arrow`+`parquet`) for code nothing runs. The `hot` trait and `storage/backends` registry go with them.

## Notes for lane R (record only; not fixed here, per D26)

- **The legacy PoW is keyed with the server secret.** `pow.rs` computes `blake3::keyed_hash(blake3(server_secret), "{challenge_id}|{action}|{subject}|{scope}|{nonce}")`. Without `JIG_NS_SECRET`, nobody can solve or verify a challenge, so the PoW gates who holds the secret, not how much work a client did. The spec's status note says the same (`identity-and-reputation.md`). D26 rules out this design.
- **`POST /v1/register` (v0.0.2) has no PoW and no rate limit,** and neither do `rotate` and `renew`. `GET /v1/challenge` (v0.0.2) is not rate-limited either. Its nonce map is bounded by a 60 s TTL, not by a count.
- **The legacy SQLite rate limiter** let every request through once a key reached its limit (fixed in #104). It still runs a deferred-transaction read-modify-write on a fresh connection, so concurrent requests can lose updates or get `SQLITE_BUSY`.
- I've sent other problems in the legacy surface to DJ separately.

## Unused dependencies (needs a `cargo udeps` or build check before removal)

`jig-client`, `hyper`, `hyper-util` and `tower-http` are never `use`d in `src/`.

## Docs that change with any deletion

- `repos/jig-spec/.../identity-and-reputation.md` lists the legacy routes as the reference surface. Its claim that "the anomaly detector opens cases automatically" is not true of the running service.
- `docs/operations/nameserver-abuse-runbook.md`
- The crate's own docs: `README.md`, `OPERATOR_GUIDE.md`, `PROGRESS.md`, `BACKEND_ARCHITECTURE.md`, the `PHASE_*` files and `examples/`.

## Delete now (no design could claim it)

1. `src/discovery.rs`: never compiled and does not compile.
2. Optional backends (`hot/**`, `storage/backends/**`, DuckDB/Parquet/ClickHouse analytics backends, and their features and dependencies), **if DJ chooses deletion**.
3. `bin/dns-txt.rs`, unless DJ wants it kept.
4. Unused dependencies, after a build confirms they are unused.

Everything else marked F/R decides waits for the checkpoint.
