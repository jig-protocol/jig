# Internal dogfooding: 3-day plan (solo + parallel agents)

**Shape:** DJ solo, traveling. Coding agents run in parallel lanes; DJ reviews and owns
every commit. Tailnet is the security boundary *(as of 2026-08-04; since 2026-09 the
server authenticates reads and gates channels itself and the tailnet is defence in
depth — see `deploy/README.md`)*. macOS-only clients. Nameserver in scope, GUI out.

**Original status:** proposed, not executed. All forensics verified against the **main
checkout** (`b04df60`) on 2026-08-04 by running real binaries. Most of the code below has
since landed — see the status section immediately following.

---

## STATUS (as of the internal-MVP batch)

The plan below was written against a pre-implementation tree. Read this section first; the
rest is preserved for its reasoning, not as a to-do list.

### Shipped

| Area | What landed | Where to check |
| --- | --- | --- |
| History read path | `GET /api/v1/channels/:slug/blocks?limit=N`, oldest-first, limit clamped to 200 | `jig-server/src/v0_0_2_blocks.rs`, `jig-pipeline/src/persist.rs::list_blocks_by_channel` |
| Stream termination | `BlockStream` ends when the reader task exits — the silent zombie connection is gone | `jig-client/src/connection.rs` (`ReaderCleanup`) |
| Fatal config load | An explicit `--config` that fails to parse logs `FATAL` and exits 1; no silent fall back to a fresh server DID | `jig-server/src/main.rs::load_v0_0_2_config` |
| Bootable templates | `install.sh` and `--init-config` both emit a hybrid config with `admin_endpoints = true` | `install.sh`, `jig-server/src/config.rs::write_template` |
| CLI global flags | `--server`, `--config`, `--did` are lifted before dispatch, so `init`/`keys`/`server`/`channel` honour them | `jig-cli/src/main.rs` |
| Observability | `/healthz` + `/metrics`, mounted outside the v0.0.1 gate; `TraceLayer` at INFO on both routers; `jig-server` defaults `RUST_LOG` to `info` | `jig-server/src/handler.rs` |
| Nameserver alias API | Binary serves `GET /v1/challenge`, `POST /v1/register`, `GET /v1/resolve/:alias`, `/v1/rotate`, `/v1/renew`; `/v1/handles` gated behind `[debug] list_handles` | `jig-nameserver/src/server.rs` (merge at ~L1509) |
| v0.0.1 REST gated off | `GET`/`POST /blocks`, `/blocks/:cid`, `/receipts/:cid` mount only under `dangerously_enable_v0_0_1_rest` (default false) | `jig-server/src/handler.rs::build_router` |
| wasmtime | 47.0.3. The aarch64 sandbox-escape advisory is closed **by upgrade, not by suppression**. `pricing.schedule_version` is `0.2.0` because bulk memory ops are now billed per byte | `repos/Cargo.toml`, `jig-runtime/src/config.rs` |
| MSRV | **1.95**, set by wasmtime 48 and inherited by `jig-runtime` + `jig-server` | `repos/Cargo.toml` |
| Deploy assets | systemd units, hybrid config template, `VACUUM INTO` backup timer | `deploy/`, `deploy/README.md` |
| History prefetch | `jig chat` and `jig tail` backfill the last 100 blocks before streaming; a failed fetch warns and opens empty rather than aborting | `jig-cli/src/cmd/history.rs`, `chat.rs` |
| Readable output | `HH:MM` timestamps, a local `[contacts]` DID→name map in `cli.toml`, shortened DIDs when unknown, inbound bell | `jig-cli/src/cmd/display.rs`, `config.rs` |
| Disconnect UX | `jig tail`/`jig chat` exit non-zero with `connection lost`; `scripts/jig-room.sh` loops on that | `jig-cli/src/cmd/display.rs`, `scripts/jig-room.sh` |
| Nameserver CLI | `jig ns resolve <alias>` / `jig ns list`, with errors that distinguish an unregistered alias from a gated route | `jig-cli/src/cmd/ns.rs` |

### Not done — know these before the first group session

- ~~**No authz beyond the tailnet.**~~ *Superseded 2026-09-09 by the authn/authz work:
  reads are signed and restricted channels are membership-gated; see
  `deploy/README.md`. Left as written below for the record of what this dogfood ran.*
  No authn, no authz, no per-channel ACL enforcement on
  reads or sends. Membership is derived state for bridge dispatch only. Tailnet membership
  *is* the access control; removing someone from the tailnet is how you revoke them.
- **No reconnect with backoff.** `jig tail` and `jig chat` now *detect* a dropped connection
  and exit non-zero with `connection lost`, but neither reconnects on its own.
  `scripts/jig-room.sh` (`until jig chat "$1"; do sleep 2; done`) is the deliberate
  stand-in — it works only because of that non-zero exit, so anything that reverts chat to
  exiting 0 silently breaks reconnect.
- **`jig read` 404s by default** — it still calls the now-gated `GET /blocks`
  (`jig-cli/src/http_client.rs` → `commands::read_messages`). Do not enable
  `dangerously_enable_v0_0_1_rest` to fix it; use `jig chat` or curl the history endpoint.
- **No GUI.** Still cut.
- **No E2EE.** Blocks are signed, not encrypted. The tailnet (and optionally
  `tailscale cert` TLS) is the only confidentiality layer.
- **No public exposure, deliberately.** Nothing is reachable off the tailnet, and nothing in
  this plan makes it so.
- **`jig --version` is not implemented.**

### Corrections to statements below

- "Rule zero" is spent — PR #21 is merged; `main.rs` loads the real `JigServerConfig`.
- Day 2's exit criterion "`jig tail` exits non-zero on disconnect" **is** met — `pump`
  returns an error carrying `connection lost`, so `until`-style loops retry correctly.
- Day 3's "`/v1/challenge` returns a 64-char hex string (was 405)" is now true for **GET**.
  The legacy **POST** handler still coexists on the same path; the merge is method-disjoint
  and is covered by `both_challenge_methods_survive_the_merge`.
- `jig-nameserver serve --bind/--port` are now honoured and win over the env vars. The
  comment inside `deploy/jig-nameserver.service` still says they are ignored — stale.

**Line numbers throughout this document are approximate.** Every agent brief must carry:

> Line numbers are approximate. If a cited line doesn't match, **grep for the quoted code
> and report the drift** — do not guess, and do not edit a different symbol that looks close.

---

## The honest dogfood moment

Two different events, and conflating them is how this slips:

1. **DJ's own first real message through the VPS — Day 1, hour ~5–6.** Achievable. Hold
   the plan to it.
2. **First message between DJ and a second human — end of Day 1 at best, realistically
   Day 2 morning.** The blocker is *not code*. It is Tailscale invite acceptance and
   per-device approval clicks across timezones while you're traveling.

**→ Send the Tailscale invites in hour 0, before you write or review a single line.** This
is the highest-leverage action in the entire plan and it costs five minutes.

What's still rough at first contact: **no history at all** (joiners see an empty box and
will report it as broken), senders render as raw 61-char DIDs next to raw epoch-millis, and
a dropped connection is silent.

> **Now:** all three are fixed. `jig chat` and `jig tail` backfill the last 100 blocks on
> open, senders render as `14:32  dj:` via the local `[contacts]` map (shortened DID when
> unknown), and a dropped connection exits non-zero with `connection lost`. What remains
> rough: no auto-reconnect without `scripts/jig-room.sh`, and `jig read` still 404s.

### On the nameserver, plainly

You promoted it over the GUI, and that ranking is right — a working naming layer is
load-bearing for the protocol in a way a GUI client isn't. But **it lands end of Day 3 and it
does not move the dogfood needle.** Readable names in `jig chat` do *not* require it (see
Lane F). Treat the nameserver as protocol debt you're paying down while the team is already
chatting, not as a prerequisite. If Day 3 slips, this is what slips.

---

## Tailscale gives you real HTTPS for free

Tailscale issues genuine TLS certs for `*.ts.net` MagicDNS names. Point the shipped `[tls]`
config at a `tailscale cert` pair and you get `https://jig-vps.<tailnet>.ts.net` with **no
certbot, no DNS records, no public exposure** — and clients need no `-k`. This is strictly
better than plaintext `ws://` for the same effort. Do it on Day 1.

---

## Structural correction: filename-disjoint ≠ independent

The first draft of this plan claimed six independent lanes. A review found that **Lane B
reads a config field that Lane A declares in a file Lane B is forbidden to open.** Lane B
simply does not compile until Lane A merges.

That failure mode is worse than a stall: an agent staring at a red build while holding an
instruction that says *"never open config.rs"* is exactly the agent that opens config.rs and
declares the field itself — recreating the collision the lane structure existed to prevent.

**The fix: every cross-lane symbol is declared in F0, not in a lane.** F0 lands the *field*
`dangerously_enable_v0_0_1_rest` (defaulting false, unread); Lane B later reads it. Same for
`DeliveredBlock`'s serde derives, the `build_text_render_with_nickname` additive overload,
and the `NameserverSection` type.

Four hidden edges the review found — all resolved by moving the declaration into F0:

| Consumer | Needs from | Symbol |
|---|---|---|
| Lane B | Lane A | `dangerously_enable_v0_0_1_rest` |
| Lane F | Lane E | stream-end semantics |
| Lane F | Lane C | history endpoint JSON shape |
| Lane I | Lane C | WAL sidecar assertion |

**Also add to every brief:** *"You may not add, remove, or upgrade any dependency. If you
believe you need one, stop and report."* Eight agents with `cargo add` and one shared
`Cargo.lock` is a merge battlefield, and it routes around `cargo deny`.

---

## F0 — the foundation batch (~11 agent-hours, ~2–3h wall clock)

Ten tasks, mutually file-disjoint, dispatched **concurrently**. Review as one sitting
(~75 min). Merging F0 unblocks every downstream lane plus the deploy.

| # | Tier | Hrs | Task | File(s) |
|---|---|---|---|---|
| F0-1 | A | 0.25 | `repos/.config/nextest.toml` with a default `JIG_NS_SECRET` so the bare test command stops failing | new file |
| F0-2 | A | 0.25 | Delete `jig-server/src/federation/` + `src/email.rs` — verified dead (no `mod` decl anywhere) | deletes |
| F0-3 | **B** | 2 | `#[serde(default)]` on the four `jig-config` sections | `jig-config/src/v0_0_2_server.rs` |
| F0-3b | **B** | 1 | **Split out:** new `NameserverSection` + `alias_suffix` validation | same file, second commit |
| F0-4 | A | 0.25 | Add `Serialize`/`Deserialize` to `DeliveredBlock` | `jig-client/src/connection.rs` |
| F0-5 | **B** | 0.5 | `rustls-tls-native-roots` on jig-client's tokio-tungstenite | `jig-client/Cargo.toml` |
| F0-6 | B | 1 | **Additive** `build_text_render_with_nickname`; old fn delegates | `jig-client/src/blocks.rs` |
| F0-7 | B | 1.5 | Trim release CI matrix to the two darwin targets | `.github/workflows/release.yml` |
| F0-8 | **B** | 1.5 | Fix the duplicate `penalties` table | `jig-nameserver/src/storage/sqlite.rs` |
| F0-9 | B | 3 | systemd units + backup script (new files only) | `deploy/*` |
| F0-10 | A | 0.5 | **Unconditionally delete** `repos/jig-core/install.sh` | delete |
| F0-11 | A | 0.25 | Declare `dangerously_enable_v0_0_1_rest: bool` (default false, unread) | `jig-server/src/config.rs` |

### Tier corrections you must apply

The review caught four tasks that looked mechanical and aren't. **Do not hand these to a
cheap model:**

- **F0-3 → tier B, and split.** `IdentitySection` holds `pub mode: IdentityMode`, an enum
  with no `Default` derive and no `#[default]` variant; the section gets defaults from a
  hand-written `impl Default`. **Container-level** `#[serde(default)]` works; **per-field**
  `#[serde(default)]` does not compile — and the fix a cheap model reaches for is adding
  `#[derive(Default)]` to `IdentityMode`, which silently changes semantics. The new
  `NameserverSection` with its `validate()` is design work; split it into F0-3b.
- **F0-8 → tier B.** This is rename-by-comprehension in a 2,784-line file containing two
  identically-named tables. The agent must tell legacy sites (903-904, 919, 932, 952) from
  Phase-D sites (2466, 2494, 2515) *by reading which schema each query assumes*. A
  grep-driven rename silently breaks the legacy penalty API. **And the obvious test —
  `SqliteStorage::new` is_ok twice — does not detect a wrong rename**, it only proves the
  batch ran. The test must assert both tables exist with their distinct columns.
- **F0-5 → tier B.** The one-line diff is trivial; the *verification* isn't.
  `cargo build -p jig-client` passes either way inside the workspace because jig-server
  unifies the feature in. The real gate is
  `cargo tree -p jig-cli -e features -i tokio-tungstenite`.
- **F0-10:** make the deletion unconditional. The earlier brief offered a fallback of
  `${JIG_TELEMETRY:-false}`; a cheap agent will take the escape hatch and leave a
  default-off-but-present phone-home in a privacy-first project.

---

## Lanes

Two of these are **serial spines**, not parallel lanes. Naming them honestly:

### Serial spine 1 — `jig-cli` (16h, one owner, strictly sequential)

Lane G (thread `--server`/`--config`) then Lane F (all CLI UX) own the **same ten files**.
`jig-cli` is the most contended crate in the repo. Do not pretend these run concurrently.

- **Lane G · tier C · 4h** — `main.rs` applies `cli.server` only *after* four early-return
  subcommand blocks have already dispatched, and `cmd/channel.rs` carries a **duplicate
  private** `load_active_identity()`. Real scope: 9 source files + 1 test. Must land alone,
  first, before any other CLI edit.
- **Lane F · tier B · 12h** — default-channel on create → terminal bell → HH:MM → surface
  submit errors → connection-lost exit → contacts directory → history prefetch → `jig ns`.
  Work in ascending blast-radius order.

**Readable names without the nameserver:** add a `[contacts]` map in `cli.toml` keyed on
DID. **Do not** implement this by stamping `metadata["nickname"]` into block builders — that
key is the trigger for the server's dormant identity check (`ingest.rs:109`), so adding it
silently activates TOFU enforcement and produces hard `IDENTITY_ERROR`s the first time one
person uses two machines.

### Serial spine 2 — `jig-nameserver` (Lane N · tier C · 11h)

Boot fix → config flags → mount the v0.0.2 routers → roundtrip test → deploy.

**The brief in the first draft self-contradicts** and must be fixed before dispatch: step 2
says `build_app` *takes* `v0_0_2::AppState` as a parameter; step 3 says `build_app`
*constructs* it. Pick one. Also unspecified: who builds the **legacy** `AppState`, whose
`federation_coordinator` spawns a background gossip loop — if `build_app` constructs it,
four tests spawn four gossip loops.

Suffix: **`gigue.jig`**. Alias resolution never touches DNS (`NameserverResolver` does
`GET {url}/v1/resolve/{alias}`), so any suffix works on a tailnet, and `.jig` is not an IANA
TLD so it cannot leak publicly.

Run it as a **separate process on port 7070**, same VPS. Co-hosting would drag
hickory-resolver + jig-runtime/wasi into the server build and put the attestation signing
key in the chat server's process.

### Genuinely parallel lanes (dispatch after F0)

| Lane | Tier | Hrs | Owns | Does |
|---|---|---|---|---|
| **A** server-boot | B | 5.25 | `jig-server/src/{config,main}.rs`, `install.sh` | serde defaults, bootable hybrid config, fatal load |
| **B** server-HTTP | C | 4 | `jig-server/src/handler.rs` | gate v0.0.1 REST, `/healthz` + `/metrics` |
| **C** storage→history | B | 3.75 | `jig-pipeline/src/persist.rs`, `jig-server/src/v0_0_2_blocks.rs` | WAL pragmas, `list_blocks_by_channel`, history endpoint |
| **E** client transport | B | 1.5 | `jig-client/src/connection.rs` | drop subs on reader exit — kills the silent zombie |
| **H** freebies | **B** | 0.75 | `v0_0_2_ws.rs`, `h2_single_server.rs` | fix stale channel-scope comments, flip h2 to channel scope |
| **I** integration | C | 6 | `integration-tests/*` | restart-persistence test, real CLI-path test |

**Lane B must hand-roll Prometheus text from `AtomicU64`** so it never opens `Cargo.toml`.

**Lane H → tier B, not A.** Its brief contains *"if the test fails, stop and report"* —
judgement under uncertainty, which is what cheap models are worst at, and the failure mode
is an agent quietly weakening an assertion. Not worth 0.75h of savings.

**Lanes H and I are coupled through `harness.rs`** in a way `git diff --name-only` cannot
see: Lane I reshapes `TestJigServer::start_with_config`, and h2 consumes that harness.
Sequence I after H, or give both to one owner.

---

## Day plan

### Day 1 — deploy first, polish later

**Hour 0 (before anything):** send Tailscale invites. Merge `origin/main`.

- **DJ ops track (serialized):** provision VPS → `tailscale up` → install rustup/cc/pkg-config
  (~15 min, a fresh box has none; `ring` needs a C compiler) → 2GB swap → build (45–90 min on
  1 vCPU) → `tailscale cert` → systemd unit with **`After=tailscaled.service`** → `jig channel
  create '#hello'`.
- **Concurrently:** the F0 batch of ~11 agents.
- **Build teammate binaries locally** — your Mac is arm64, so `aarch64-apple-darwin` is
  native. The `jig` release binary is **3.0 MB** (lto + strip already configured), trivially
  AirDrop-able. Teammates need `xattr -d com.apple.quarantine ./jig`.

**Exit:** `curl https://jig-vps.<tailnet>.ts.net/.well-known/jig` returns the server DID
from your Mac with no `-k`; `#hello` exists; you've sent and received a real message between
two identities.

### Day 2 — polish while people are already typing

- **Morning, alone:** land Lane G. Budget a real review — it's the day's one tier-C CLI diff.
- **Then concurrently:** Lanes A, B, C, E, H + Lane N spine. Lane F starts once G merges.
- Small frequent reviews, not one merge.

**Exit:** 5+ teammates have posted. `jig tail` exits non-zero on disconnect (so
`jig-room.sh` actually retries). Chat shows `14:23  dj: hi`. `POST /blocks` returns 404.

> **Outcome:** `POST /blocks` 404s as intended. The other two did not land — `jig tail`
> exits **0**, `jig-room.sh` does not exist, and chat still shows raw DIDs and epoch-millis.
> Use `while true; do jig tail …; sleep 2; done`, not `until`.

### Day 3 — nameserver, history, keys

- Review the Lane N mount diff **carefully**. `Router::merge` on the shared `/v1/challenge`
  path (legacy POST vs v0.0.2 GET) is a runtime panic if the analysis is wrong — do not merge
  without seeing the mount test's actual output.
- Deploy the nameserver bound to the **tailscale interface**, not `0.0.0.0` — `/v1/register`
  has no authentication beyond proof-of-control over a self-minted key.
- History prefetch closes the empty-room complaint.
- **Run the restore drill against real data.** Losing `server.key` changes the server DID.

**Exit:** `curl <tailscale-ip>:7070/v1/challenge` returns a 64-char hex string (was 405); an
alias registers and resolves across a restart; `jig chat '#hello'` opens with history.

> **Outcome:** the `Router::merge` analysis held — legacy POST and v0.0.2 GET coexist on
> `/v1/challenge`, no startup panic, covered by `both_challenge_methods_survive_the_merge`.
> `GET /v1/challenge` returns `{"challenge":"<64 hex>"}`; register/resolve/rotate/renew are
> mounted, `/v1/handles` only under `[debug] list_handles`.

---

## Cut list

Unchanged from the 24h plan, plus: **the GUI entirely**, **`Frame::CatchUp` cursor replay**
(REST "last 100" gets 95% of the value), **real in-client reconnect** (stream-close plus
`scripts/jig-room.sh`'s `until` loop is indistinguishable at this scale, now that the
clients exit non-zero), and **flipping `[identity] mode` to nameserver** (a
literal no-op today, and a live enforcement path the moment builders stamp nicknames — 12–20h).

## Risks

1. **The first teammate message is gated on Tailscale invites, not code.** Send them hour 0.
2. **The nameserver is quietly a 4–5 day item if anything goes wrong**, and it does not move
   the dogfood needle. It is the designated slip.
3. **`jig-cli` is a 16h serial spine.** No amount of agent parallelism compresses it.
4. **DJ review is the throughput ceiling** — ~11 F0 diffs plus 8 lanes, while traveling.
5. **Tier-A agents on mis-tiered tasks** will produce plausible-looking wrong diffs. The four
   corrections above are the ones that matter.
6. ~~**Zero observability until Lane B lands.**~~ **Closed.** A verified run of 8 messages
   and 4 WS connections produced *zero* log lines at `RUST_LOG=info`; the fix was pinning
   the tower-http span *and* event levels to INFO (tower-http defaults both to DEBUG, and a
   DEBUG span under an INFO filter logs "started processing request" with no method or URI).
   `/healthz` and `/metrics` now exist and sit outside the v0.0.1 gate — a scrape target
   that vanishes when the operator locks the server down is not a scrape target.
7. **The tailnet is doing 100% of your security** *(no longer: reads are signed and
   channels gated since 2026-09, but with no admission policy the tailnet is still what
   keeps strangers off the port)*. The danger is six weeks of "it's been fine" becoming
   the argument for port 443.
