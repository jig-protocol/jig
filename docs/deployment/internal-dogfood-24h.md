# Internal dogfooding: 24-hour plan

> **⚠️ SUPERSEDED** by [`internal-dogfood-3day.md`](./internal-dogfood-3day.md).
> That plan reflects DJ's decisions of 2026-08-04: 3-day solo budget with parallel agents,
> nameserver promoted over the GUI, macOS-only clients. This document is retained for its
> verified state-of-the-union findings **as of 2026-08-04**. Finding #2 ("zero authz") is
> no longer true: since the authn/authz work of 2026-09, reads are signed and restricted
> channels are membership-gated for reading, listing, delivery and posting — the attack
> described there is refused at three gates. See `deploy/README.md`, "Security model".

**Status:** proposed, not executed. Verified against `main` @ `b04df60` on 2026-08-04 by
running the real binaries, not by reading code.

**Goal:** 5–10 gigue teammates messaging each other daily in one shared channel on one
jig-server, terminal-only, on a tailnet.

**Non-goal:** anything public-facing. See "Cut list".

---

## Verified state of the union

Everything below was proven by execution.

| Capability | State |
|---|---|
| Live WS fan-out A→B in a shared channel | ✅ works |
| 3 concurrent `jig tail` clients each receive every message | ✅ works |
| ed25519 signature verification on `POST /api/v1/blocks` | ✅ works |
| DIDs self-certifying (`did:jig:z` + base32 pubkey); no nameserver needed | ✅ works |
| Blocks/channels/memberships survive server restart | ✅ works |
| `jig chat` ratatui TUI (2-pane, WS-backed, Enter sends) | ✅ works |
| TLS/WSS edge (`[tls]`, rustls 0.22 + hyper-util upgrades) | ✅ works |
| Workspace tests | ✅ 1002 passed — **only with `JIG_NS_SECRET` set** |
| Message history / scrollback | ❌ none |
| Authn / authz | ❌ none |
| Reconnect | ❌ silent zombie |
| Graphical client | ❌ mock only |

### The five findings that shape this plan

1. **No history.** `Frame::CatchUp` is a no-op stub (`v0_0_2_ws.rs:303`), `persist.rs` has
   no list-by-channel query despite the `blocks_channel_hlc` index existing at
   `persist.rs:152`, and `jig read` queries the *wrong database* (`jig.db` vs
   `jig_v002.db`) *and* reads `metadata.content` while the client writes `metadata.body`.
   The data is durable; nothing can read it back. **This is a read-path gap, not a
   storage build.**

2. **Zero authz, and one unsigned-ingest hole.** Verified by attack: a brand-new DID that
   never joined anything read a `visibility = restricted` channel and wrote a persisted
   block into it. Separately, the legacy v0.0.1 `POST /blocks` route accepts a block
   claiming an **arbitrary DID with no signature field in the API at all**, executes
   attacker-supplied Wasm, and signs a receipt for it (`handler.rs:150`,
   `runtime/mod.rs:107`).

3. **Neither committed config boots a working server.** `install.sh` omits root-level
   `database_path`/`bind_address`/`port`, which have no serde defaults → server refuses to
   start. `--init-config` omits `[debug]` → `jig channel create` 404s. And **`[server]
   listen` is decorative** — it only builds the `ws://` origin string; the socket binds
   root-level `bind_address`.

4. **Silent zombie on disconnect.** On server restart or a wifi blip, `jig tail` and
   `jig chat` stay alive, print nothing, accept typed input, and never receive another
   message. The user believes they are still in the room.

5. **No graphical client exists.** `riverdance` has zero network code and zero dependency
   on any jig crate. `jig-client` cannot compile to wasm32. Terminal-only is the only
   option, so **binary distribution is a real task**.

---

## Recommended path

**One jig-server bound to a Tailscale interface IP, plaintext `ws://`, one shared open
channel, terminal-only** — plus four small shipped fixes.

Why this beats the alternatives:

- **vs. public `wss://jig.onl`:** the TLS edge genuinely works, and that is the trap.
  Exposing it means exposing a WebSocket with zero auth. Reaching "safe on a public IP" is
  ~1.5–2 weeks. Tailscale delivers the same reachability for a team of 10 at ~0h of jig
  code, and deletes all DNS/certbot work from the critical path.
- **vs. email-bridge dogfooding:** `dm_channel_slug()` hashes a *sorted DID pair*. The
  bridge is structurally 1:1 and cannot carry a team channel.
- **vs. shipping a web UI:** `jig-client` doesn't compile to wasm32. 3–5 days minimum,
  including key-custody design.

---

## Honest scheduling

**This fits in 24 hours only with DJ + 2 engineers in parallel, and DJ available to review
at H4 and H10.** Total engineering is **~20–28h across three workstreams**. Solo, this is a
3-day plan — say so now rather than discovering it at H14.

DJ is the critical path, not the code: three PRs, one reviewer, and DJ owns the commit
stream end-to-end.

---

## Hour blocks

### H0–H1 · DJ · serialized, blocks everything

- `git merge origin/main` into this worktree. This is a **fast-forward** (worktree is
  strictly behind main) — 7 files, no conflict potential. PR #21 is what makes
  `main.rs` load `JigServerConfig` from `--config`; without it your config file is ignored.
- `cd repos && cargo build --workspace --bins` → exit 0.
- `cd repos && JIG_NS_SECRET=<any> cargo nextest run --workspace` → green. **The bare
  command fails**: 11 jig-nameserver tests panic on the missing secret, which only the CI
  YAML knows about. Do not pin an exact test count as your exit criterion.
- Cut three branches: `fix/config-fatal-load`, `feat/channel-history`,
  `fix/client-stream-close`.
- Post the branch names + the `JIG_NS_SECRET` gotcha in Slack — jig can't carry this yet.

**Exit:** build exits 0; suite green with the secret set; three branches pushed.

### H1–H4 · DJ (ops hat) · parallel, no code dependency

- **Install build deps first** — a fresh VPS has no `rustup`, no `cc`, no `pkg-config`;
  `ring` needs a C compiler. ~15 min, and it is not optional.
- `tailscale up`, record the `100.x` address.
- **Add 2GB swap before building.** 1 vCPU / 1GB will OOM on wasmtime + rustls + axum.
  Budget **45–90 min** for the build, not 20–40.
- `cargo build --release -p jig-server -p jig-cli` — **both in one invocation**. A
  standalone jig-cli build has no TLS (it only gets rustls by cargo feature unification).
- `/etc/jig/config.toml` in the hybrid shape below. `bind_address` = the tailscale IP,
  **not `0.0.0.0`** — do not rely on the VPS firewall alone.
- systemd unit (none ships in the repo). **`After=tailscaled.service`** or the unit fails
  on reboot and you find out the morning after. Keep `jig-server.prev` for rollback.
- **Grep the boot log for `v0.0.2 config load ... failed` before declaring victory.**

```toml
# Root keys drive ServerConfig (these are what actually bind).
database_path = "/var/lib/jig/jig.db"     # v0.0.2 store becomes jig_v002.db
bind_address  = "100.x.y.z"               # tailscale IP. NOT 0.0.0.0.
port          = 7117

[server]                                   # these drive JigServerConfig
listen              = "100.x.y.z:7117"     # cosmetic only — does NOT bind
server_did_keyfile  = "/var/lib/jig/server.key"
allowed_block_kinds = ["text-render", "channel-create", "member-add", "channel-archive"]

[identity]
mode = "tofu"

[debug]
admin_endpoints = true    # REQUIRED or `jig channel create` 404s
list_handles    = false
```

**Exit:** from a *second* tailnet device, `curl http://100.x.y.z:7117/.well-known/jig`
returns JSON containing `server_did`.

### H1–H4 · eng-1 · branch `fix/config-fatal-load`

TDD first, per ROE.

- `#[serde(default)]` on `database_path`/`bind_address`/`port` (`jig-server/src/config.rs:11-13`;
  a `Default` impl already exists at :61-73 — wire it).
- `#[serde(default)]` on every field of `DebugSection`/`IdentitySection`/`FederationSection`/
  `ServerSection` in `jig-config/src/v0_0_2_server.rs`, so a *partial* `[debug]` table
  doesn't silently zero the rest.
- **Make `JigServerConfig::load` failure fatal when `--config` was explicitly passed.**
  Today it's a `warn!` + `::default()` — a server that quietly ignores your config file.
- Fix `install.sh:155-183` and `write_template` (`config.rs:164-167`) to emit the hybrid
  shape. Add a test that loads install.sh's literal heredoc.
- WARN loudly when `[server] listen` disagrees with root `bind_address`/`port`.
- **Delete or `dangerously_`-gate the v0.0.1 `/blocks` + `/receipts` routes** (2–4h). This
  is the unsigned-arbitrary-DID + anonymous-Wasm hole. Do it even on a tailnet.

**Exit:** `jig-server --config <install.sh's exact heredoc>` binds and serves.

### H1–H7 · eng-2 · branch `feat/channel-history`

- `pub fn list_blocks_by_channel(&self, slug, limit, since_hlc)` in `persist.rs`. The
  `blocks_channel_hlc` index at :152 already supports it.
- `GET /api/v1/channels/:slug/blocks?limit=` in `v0_0_2_blocks.rs`, mounted next to
  `/api/v1/channels` at :287. Percent-decode `#`-prefixed slugs.
- **Interface contract — the plan's coupling point, and easy to get wrong.** `Frame::Block`
  has *four* fields (`bundle_b64`, `sig_b64`, `receipts`, `delivery_cid`). The three-field
  struct is `jig_client::DeliveredBlock`, and it derives only `Debug, Clone` — **there is no
  `Deserialize`**. Add serde derives to `jig-client` (agree this with eng-1 up front; it
  crosses branch boundaries). Note `receipts: []` is harmless — `decode()` only uses them
  for a parity warning.
- Set `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout` in `persist.rs:114-123`. The
  v0.0.1 store already does this; the v0.0.2 store does not.
- Integration test: boot a real server, submit 3 blocks, GET the timeline.

**Exit:** the endpoint returns the text-render blocks for `#gigue`. Filter by
`block_kind='text-render'` when you compare against sqlite — the channel also has
`channel-create` and `member-add` rows.

### H4–H9 · eng-1 · branch `fix/client-stream-close` — budget 5–7h, not 3

- **Zombie fix (~1h):** in `jig-client/src/connection.rs`, when the reader task (:131-183)
  exits, clear `pending_subscriptions` so every `BlockStream` sender drops and the stream
  ends.
- `jig tail`/`jig chat` print `connection lost` to stderr and exit non-zero.
- Stop swallowing submit errors at `chat.rs:280` (`let _ = client.submit(...)`).
- **Wrapper (~0.5h):** `scripts/jig-room.sh` = `until jig chat "$1"; do sleep 2; done`.
  With the stream-close fix + history backfill this *is* reconnect, at 1/6th the cost.
- **`--server` override (~1–1.5h, bigger than it looks):** `load_active_identity()` and
  `load_server_url()` take **no arguments** and both call `config::load_config(None)`.
  Threading an override means changing both signatures and every caller in
  `send.rs`/`tail.rs`/`chat.rs`/`channel.rs`/`keys.rs` plus dispatch in `main.rs`. Also
  `load_config` silently returns `Config::default()` on a missing path, so `--config /typo`
  stays quiet even after the fix.
- **Decide `jig read`:** repoint it at eng-2's endpoint, or make it exit non-zero. Do not
  leave a command that silently succeeds and prints nothing.

**Exit:** kill the server under a live `jig tail` → process exits within 2s with a visible
message and non-zero status.

### H9–H12 · eng-1 + eng-2 converge

⚠️ These two workstreams **touch the same files** (`chat.rs`, `tail.rs`,
`jig-client/src/blocks.rs`). Branch eng-1's UX work off eng-2's branch and pair on the
merge; do not pretend they are independent.

- Prefetch the last 100 blocks in `chat.rs::run()` *before* `TerminalGuard::enter()`, decode
  via `cmd/blocks_decode.rs`, prefill `ChatState.messages`.
- **Nicknames:** stamp `nickname` from cli.toml `display_name` into the manifest in
  `jig-client/src/blocks.rs::build_text_render`. This also revives the TOFU lock, which is
  dead today because no client ever sets that key.
- Format `HlcTimestamp::wall_ms` as `HH:MM` instead of `1785860921282`.
- Terminal bell on inbound message (zero `notify`/`bell` matches in jig-cli today).
- Set `default_channel` in cli.toml when `jig channel create` succeeds.

**Exit:** `jig chat '#gigue'` on a never-connected machine opens showing
`14:32  dj  hello team`, not `1785860921282  did:jig:zdw6fioj...  hello team`.

### H12–H15 · DJ · serialized

- Review + merge in dependency order. Conventional commits, scoped.
- `cargo fmt --all && cargo clippy --workspace -- -D warnings && JIG_NS_SECRET=... cargo nextest run --workspace`
  before each merge.
- Rebuild on the box, `install -m755`, keep `jig-server.prev`, `systemctl restart`.
- Verify state survived the restart.
- **Distribute the CLI.** Intel and Apple Silicon are **two binaries**. Unsigned macOS
  binaries get quarantined — everyone needs `xattr -d com.apple.quarantine ./jig`.

### H15–H18 · DJ leads, team participates

- **First step is Tailscale**, not `jig init` — install + device approval. This is where the
  session stalls for 5–10 people.
- Then: `jig init <unique-nickname>` → `jig server set http://100.x.y.z:7117` →
  `scripts/jig-room.sh '#gigue'`. **Skip `jig channel join`** — membership isn't enforced.
- **Have everyone back up `~/.jig/keys/*.key` now.** It is the only copy of their identity.
- Watch the first three people screen-shared. You will find paper cuts.
- Seed the room with real content first so nobody's first impression is an empty pane.
- **Move one real recurring thing in on day one** — standup, or the deploy log. A tool with
  no job gets closed by Thursday.
- **Say the security boundary out loud:** the tailnet *is* the authentication.

**Exit:** ≥5 people have each sent a message and each independently confirms they can see
messages sent *before* they joined.

### H18–H24 · soak

Sleep is in this block. Check `journalctl -u jig-server` in the morning. Write down paper
cuts; do not fix them at 2am. Set up `VACUUM INTO` backups on a timer + an offsite copy of
`server.key` — **losing `server.key` changes the server DID and breaks TOFU for everyone.**

**Exit:** server up overnight with no manual restarts; block count grew; a written day-2
list exists.

---

## Cut list

| Cut | Why it's safe |
|---|---|
| Public exposure, DNS, certbot, port 443, jig.onl | Tailnet gives the same reachability for 10 people |
| All authn/authz (16–30h+) | WireGuard device identity does the job for a closed team. **Loan against the future** |
| Any GUI (1–2 weeks) | riverdance has zero network code; jig-client can't reach wasm32 |
| Email bridge as team channel | `dm_channel_slug()` hashes a DID *pair* — structurally 1:1 |
| Nameserver aliases (`dj@dj.jig`) | Alias routers are never mounted by `run_http_server()`; its SQLite migration fails on a fresh DB and silently degrades to in-memory |
| `Frame::CatchUp` cursor replay | "last 100 over REST" delivers 95% of the value |
| Real reconnect w/ backoff (6–10h) | stream-close fix + `until` loop is indistinguishable at this scale |
| Federation between per-person servers | One server, one DB, one channel |
| E2EE | **Only with an explicit written caveat.** There is no `jig-crypto` crate. Bodies are cleartext at rest |
| `curl \| sh` 60s KPI | We're installing on 1 server + ~10 laptops by hand |
| Multi-channel per connection | Genuinely broken (`v0_0_2_ws.rs:89/198` keeps only the last `sub_id`), but jig-cli opens one channel per process, which masks it |

---

## Decisions needed from DJ

1. **Host: $5 VPS or an existing always-on box?** → *Recommend:* whatever you can
   `tailscale up` in 15 minutes. The potato-install KPI is a product goal, not this week's
   test.
2. **Leave `[debug] admin_endpoints = true` on all week?** → *Recommend:* yes, documented as
   a known hole. Off means nobody can create `#random` on Thursday without a config edit and
   restart. Note there is no owner check — anyone on the tailnet can add anyone to anything.
3. **Minimal stream-close + shell wrapper, or proper reconnect in jig-client?** →
   *Recommend:* minimal. Biggest schedule saver in the plan.
4. **Three PRs reviewed as they land, or one at H12?** → *Recommend:* three, reviewed at H4
   the moment the first is ready. Batching means one 3-hour unavailability slips everything.
5. **Windows?** → *Undecided and it matters:* `jig-client/src/identity.rs` guards its 0600
   checks with `#[cfg(unix)]` (:111,128,182,241), so a Windows build writes private keys
   **with no permission enforcement at all**. Either declare macOS/Linux-only for the week,
   or budget the fix.

---

## Biggest risks

1. **Solo, this is 3 days.** The 24h version needs DJ + 2 engineers.
2. **DJ's review queue is the critical path**, not the code.
3. **The tailnet is doing 100% of your security.** The verified attack is not hypothetical.
   The danger is that six weeks of "it's been fine" becomes the argument for putting this
   exact server on port 443.
4. **TOFU collision, the realistic one:** not two people picking `dj` — *one* person on two
   machines. Laptop and desktop mint different DIDs under one nickname; the second gets a
   hard `IDENTITY_ERROR` with no documented recovery.
5. **Zero operator observability.** A verified run of 8 messages and 4 WS connections
   produced **zero log lines** at `RUST_LOG=info`. `TraceLayer` is a dependency and is never
   applied. No `/healthz`, no `/metrics` — a crash-loop is invisible overnight.
6. **Adoption is the real risk and it isn't technical.** Terminal-only, no notifications, no
   mobile, one channel per window. The counter is moving one real workflow in on day one.

---

## Loose end worth a look

`repos/jig-core/install.sh` POSTs `{os, arch, email}` to `https://metrics.jig.onl/install`
by default whenever `JIG_TELEMETRY` is unset. That domain doesn't resolve today. Decide
whether that's intended before anyone runs it.
