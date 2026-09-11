# Deploying jig on a tailnet VPS

Systemd units, a hybrid config template, and a backup job for running
`jig-server` + `jig-nameserver` on a single small VPS reachable **only over
Tailscale**.

| File | Purpose |
| --- | --- |
| `jig-server.service` | Block server, port **7117** |
| `jig-nameserver.service` | DID/alias registry, port **7070** |
| `config.example.toml` | The hybrid `/etc/jig/config.toml` |
| `jig-backup.sh` | `VACUUM INTO` snapshots + `server.key` |
| `jig-backup.service` / `.timer` | Daily 03:17 UTC backup |

Each unit file carries its own rationale in comments. This document covers the
sequence and the things that are not visible from inside a single file.

---

## 🔴 BACK UP `/var/lib/jig/server.key` OFFSITE. TODAY.

**LOSING `/var/lib/jig/server.key` CHANGES THE SERVER DID AND BREAKS TOFU
PINNING FOR EVERY CLIENT.**

The server DID is derived from that 32-byte ed25519 seed. Every client that has
talked to this server has pinned the resulting DID on first contact (TOFU). If
the key is gone, the server comes back up with a **different identity**, and
every client sees what is indistinguishable from a man-in-the-middle. Restoring
a database without the key restores nothing useful.

```bash
sudo base64 /var/lib/jig/server.key   # paste into 1Password, then forget it exists
```

Two related traps:

- The server **generates** the key `0600` on first boot and **refuses to start**
  later if the file is group- or other-readable (it hard-fails on `mode & 0o077`).
  If you restore it from backup, `chmod 600` and `chown jig:jig` it.
- Restoring the key onto a *different* host is what you want. Restoring the
  databases without it is not.

Teammates have the same problem one level down: see
[Teammate onboarding](#teammate-onboarding) — `~/.jig/keys/*.key` is the only
copy of a person's identity.

---

## Security model: identity in the server, the tailnet as defence in depth

The server authenticates and authorizes on its own. Network placement is a
second layer, not the only one — but it is still a layer you want, because the
gates below are new and not everything is behind one yet.

What the server enforces (with `[auth] require_authenticated_reads = true`,
the default):

- **Every read carries proof of possession.** REST reads and WSS subscribes
  are signed by the caller's ed25519 key over a canonical hash of the request;
  the server verifies the signature against the DID and refuses replays. A DID
  without its key reads nothing.
- **Restricted channels are membership-gated.** History, the channel listing,
  live WSS delivery and posting are all decided by the same rule: `open`
  channels reach any authenticated caller; `restricted` ones reach the owner
  and members only. The listing does not name restricted channels — or their
  owner — to non-members. Live delivery is re-checked on every block, so
  removing a membership stops an already-open subscription. (There is no
  `member-remove` block or CLI verb yet: today a removal is the operator
  deleting the `memberships` row, or archiving the channel.)
- **Membership is the owner's to grant.** `member-add` onto a restricted
  channel, or of anyone but yourself onto any channel, must be signed by the
  channel owner; `channel-promote` likewise. Self-join (`jig channel join`)
  works on open channels only. Unknown `visibility` values fail closed.
- **The server can refuse a caller before asking what they want.**
  `[auth.admission]` runs after a key is proven and before anything is
  authorized, on every read and every write: `banned_dids`, ruleset-scoped
  reputation `floors`, and an explicit `unknown_dids = "admit" | "refuse"`.
  A refused caller gets `403 NOT_ADMITTED` and learns nothing about channels.
  A members-only server is `unknown_dids = "refuse"` plus a `records` entry
  per member:

  ```toml
  [auth.admission]
  unknown_dids = "refuse"
  [[auth.admission.records]]
  did = "did:jig:z..."          # each member's DID
  ruleset_key = "club"
  score = 1
  ```

  Reputation is ruleset-scoped, so a floor never refuses a DID that has no
  score under its ruleset — that case is the `unknown_dids` choice, by
  design, so a fresh key is not punished for being fresh.

What it does not enforce yet — the reasons to keep `bind_address` on the
tailnet:

- **No rate limiting or proof-of-work, and no reputation scoring.** Admission
  consumes scores the operator wrote down; nothing computes or exchanges them
  yet. With the default `unknown_dids = "admit"`, anyone who can reach the
  port can create channels and post to open ones, unthrottled.
- **Federated peers are trusted.** Blocks relayed from a peer are persisted
  and delivered to local subscribers without running the write gate. Only
  federate with servers you would let post on your behalf.
- **Admin endpoints still live behind `[debug]`.** `admin_endpoints = true`
  (required, below) mounts the channel-ops routes. They run the same gates as
  everything else now, so the risk is the label, not the behaviour — but do
  not read "debug" as "harmless".
- **No end-to-end encryption.** The operator reads every message. See
  `docs/RELEASE_READINESS.md` §1.3.
- The nameserver's `/v1/register` has no auth beyond proof-of-control of a
  self-minted key. Its config default `bind` is `127.0.0.1`, but the unit
  overrides it with `JIG_NS_BIND` — set that to the tailnet IP, not `0.0.0.0`.

Removing someone from the tailnet still removes their access, and until a
`member-remove` block exists it is still the operator's only lever short of
editing the database.

---

## Install

```bash
# 1. dedicated non-root user, no shell, no home of its own
sudo useradd --system --home-dir /var/lib/jig --shell /usr/sbin/nologin jig
sudo install -d -o jig -g jig -m 0750 /var/lib/jig /var/backups/jig
sudo install -d -m 0755 /etc/jig /opt/jig/bin

# 2. binaries + backup script
sudo install -m 0755 target/release/jig-server     /opt/jig/bin/
sudo install -m 0755 target/release/jig-nameserver /opt/jig/bin/
sudo install -m 0755 deploy/jig-backup.sh          /opt/jig/bin/

# 3. config — EDIT IT, the 100.x.y.z placeholders are not real
sudo install -m 0644 deploy/config.example.toml /etc/jig/config.toml
tailscale ip -4                     # <- put this address in the config
sudoedit /etc/jig/config.toml

# 4. nameserver secret (MANDATORY — it exits non-zero at startup without one)
printf 'JIG_NS_SECRET=%s\n' "$(openssl rand -hex 32)" \
  | sudo tee /etc/jig/jig-nameserver.env >/dev/null
sudo chown root:jig /etc/jig/jig-nameserver.env
sudo chmod 600 /etc/jig/jig-nameserver.env      # <- 600. it is a secret.

# 5. optional server secrets (bridge tokens etc.), same treatment
#    sudo chmod 600 /etc/jig/jig-server.env

# 6. units
sudo install -m 0644 deploy/jig-server.service deploy/jig-nameserver.service \
                     deploy/jig-backup.service deploy/jig-backup.timer \
                     /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now jig-server jig-nameserver jig-backup.timer
```

Edit `Environment=JIG_NS_BIND=100.x.y.z` in `jig-nameserver.service` before
enabling it.

`jig-server --init-config <path>` writes a template equivalent to
`config.example.toml` if you would rather generate it than copy it. It emits
**both halves** of the hybrid file, including `[debug] admin_endpoints = true`.

### Verify the deploy

| Check | Command | Expect |
| --- | --- | --- |
| Server liveness | `curl http://100.x.y.z:7117/healthz` | `200`, body `ok` |
| Server identity | `curl http://100.x.y.z:7117/.well-known/jig` | `server_did` + `unsafe_options_active` |
| Server counters | `curl http://100.x.y.z:7117/metrics` | Prometheus text |
| Channel list | `curl http://100.x.y.z:7117/api/v1/channels` | `401` `AUTH_REQUIRED` — reads are signed; use `jig channel list` instead |
| Nameserver liveness | `curl http://100.x.y.z:7070/v1/health` | `{"status":"ok"}` |
| Nameserver alias API | `curl http://100.x.y.z:7070/v1/challenge` | `{"challenge":"<64 hex>"}` |
| Units | `systemctl status jig-server jig-nameserver` | both `active (running)` |

> ⚠️ **Once you enable `[tls]`, every one of the `:7117` rows above becomes
> `https://`, not just the ones you were thinking about.** TLS wraps the *whole*
> router on the single configured port — `/healthz`, `/metrics`,
> `/.well-known/jig`, `/api/v1/*` and the WebSocket alike. An `http://` request
> to a TLS port produces no usable response, and **`curl -s` hides the error**,
> so a working server looks like a silently dead one. Drop the `-s`, or use
> `https://<host>.<tailnet>.ts.net:7117/healthz`. Clients must move to
> `https://` / `wss://` too (`jig server set https://…`).
>
> The nameserver on `:7070` is **not** covered by `[tls]` — that section belongs
> to `jig-server` only — so its rows stay `http://` unless you terminate TLS in
> front of it yourself.

`/healthz` and `/metrics` are deliberately mounted **outside** the v0.0.1 gate,
so they answer on a default, locked-down deployment. Use `/healthz` — not
`/.well-known/jig` — as the uptime check: it touches no storage.

`RUST_LOG=info` now produces a line per HTTP request (a `TraceLayer` is applied
to both the legacy and the v0.0.2 routers). `jig-server` defaults to `info` when
`RUST_LOG` is unset, so `journalctl -u jig-server -f` shows traffic without
extra configuration.

---

## ⚠️ The units MUST order after tailscaled

Both units carry `After=`/`Wants=` on `tailscaled.service`, plus
`Restart=on-failure` / `RestartSec=5s`. Binding a `100.x` address requires the
Tailscale interface to already exist; without the ordering the service starts
first, `bind(2)` returns `EADDRNOTAVAIL`, and the unit dies — on **reboot**, so
nobody notices until the whole team tries to use it the next morning.

`After=` only orders unit *start*; tailscaled being "active" does not guarantee
the address is assigned yet. The restart settings cover that residual race. Do
not strip them thinking the ordering is enough.

If your box loses the race repeatedly, add a gate (left out by default so a
missing `tailscale` binary can't permanently wedge the unit):

```ini
ExecStartPre=/usr/bin/tailscale ip -4
```

---

## The hybrid config, in one paragraph

`main.rs` loads the same `--config` file into **two unrelated structs**.
Root-level keys (`database_path`, `bind_address`, `port`, `[tls]`, `[execution]`)
become `ServerConfig` and are **what actually binds**. `[server]`, `[identity]`,
`[federation]`, `[debug]`, `[bridges]` become `JigServerConfig`. Neither type
uses `deny_unknown_fields`, so each ignores the other's sections in silence —
which is exactly why editing the wrong half produces no error and no effect.

**An explicitly-passed `--config` that fails to parse is now FATAL.** The server
logs `[jig-server] FATAL: v0.0.2 config load from … failed` to both tracing and
stderr and exits `1`. It no longer falls back to defaults, which used to mint a
fresh server DID and break TOFU for everyone. A missing `--config` still means
"use defaults" — that path is legitimate and unchanged.

Three landmines, all called out in `config.example.toml`:

- **`[server] listen` is DECORATIVE.** It only builds the `ws://…` origin-tag
  string. It does **not** control the bind address. The server now logs a
  startup `WARN` when `listen` disagrees with the effective `bind_address:port`.
- **`[debug] admin_endpoints = true` is REQUIRED.** With it false, the
  `/_admin_v0_0_2/*` router is never mounted and `jig channel create` returns a
  bare **404** that looks like a wrong URL, wrong port, or a bad build.
- **`dangerously_enable_v0_0_1_rest` defaults to `false`, and should stay false.**
  It gates the unsigned v0.0.1 REST surface (`GET`/`POST /blocks`,
  `/blocks/:cid`, `/receipts/:cid`), which takes an attacker-chosen author DID
  with no signature and signs a receipt attesting to it. The visible cost of
  leaving it off is that **`jig read` 404s** — it still calls `GET /blocks`. Use
  `jig chat` or `GET /api/v1/channels/<slug>/blocks` instead; do **not** turn the
  flag on to make `jig read` work.

### Reading history

Reads are signed, so a bare `curl` gets `401 AUTH_REQUIRED`. Let the CLI
sign for you:

```bash
jig tail --channel '#hello'    # backfills the last 100 blocks, then follows
```

Under the hood that is `GET /api/v1/channels/%23hello/blocks?limit=100` with
five `x-jig-*` headers carrying an ed25519 proof over the request (see
`jig_client::ReadProof`). Blocks come back oldest-first as a JSON array
(`bundle_b64`, `receipts`, `delivery_cid`). A restricted channel you are not
a member of is `403 NOT_A_MEMBER`; a channel with no local row (federated, or
mistyped) is `200` with `[]`. `limit` defaults to and is clamped at **200**.

---

## Real TLS with `tailscale cert` (no certbot, no public DNS)

Tailscale issues genuine Let's Encrypt certificates for your MagicDNS name, so
you get real HTTPS/WSS with **no public DNS record, no port 80 challenge, and no
public exposure whatsoever**. This is strictly better than certbot here.

Enable HTTPS + MagicDNS in the tailnet admin console, then:

```bash
sudo install -d -o jig -g jig -m 0750 /var/lib/jig/tls
sudo tailscale cert \
  --cert-file /var/lib/jig/tls/<host>.<tailnet>.ts.net.crt \
  --key-file  /var/lib/jig/tls/<host>.<tailnet>.ts.net.key \
  <host>.<tailnet>.ts.net
# `-R` and the wrapped shell are both deliberate. `sudo chown jig:jig
# /var/lib/jig/tls/*` FAILS: your shell expands the glob before sudo runs, and
# the directory is 0750 jig:jig, so an unprivileged shell cannot list it. chown
# then reports "cannot access '/var/lib/jig/tls/*'" even though tailscale just
# wrote the files. sudo elevates the command, not the globbing.
sudo chown -R jig:jig /var/lib/jig/tls
sudo sh -c 'chmod 600 /var/lib/jig/tls/*.key'
```

Point the server's existing `[tls]` block at them:

```toml
[tls]
enabled = true
cert_path = "/var/lib/jig/tls/<host>.<tailnet>.ts.net.crt"
key_path  = "/var/lib/jig/tls/<host>.<tailnet>.ts.net.key"
```

`systemctl restart jig-server`, and
`curl https://<host>.<tailnet>.ts.net:7117/healthz` works from any tailnet
device **without `-k`**. Clients use `wss://` for the same host.

**Renewal is not automatic here.** The server reads the cert once at startup (no
hot reload). Certs are ~90 days, so re-run `tailscale cert` and restart the
service on a monthly timer, or leave TLS off for a short-lived dogfood — the
tailnet is already an encrypted transport.

---

## Teammate onboarding

Do these **in order**. Steps 1–2 are where a group session actually stalls: the
invite email and the per-device approval click are asynchronous and often cross
a timezone. Send the invites before anyone builds anything.

| # | Who | Step | Command / action |
| --- | --- | --- | --- |
| 1 | You | Send the Tailscale invite | tailnet admin console → Invite external user |
| 2 | Them | Install Tailscale, sign in, **wait for your approval** | `tailscale up`, then you approve the device |
| 3 | Them | Confirm they can see the box | `tailscale ping <host>` |
| 4 | You | Get them the `jig` binary | AirDrop or `tailscale file cp` |
| 5 | Them | Clear the macOS quarantine flag | `xattr -d com.apple.quarantine ./jig` |
| 6 | Them | Confirm the server is reachable | `curl http://100.x.y.z:7117/healthz` |
| 7 | Them | Create an identity | `./jig init <nickname>` |
| 8 | Them | Point at the server | `./jig server set http://100.x.y.z:7117` |
| 9 | Them | **Back up `~/.jig/keys/*.key`** | copy into a password manager |
| 10 | Them | Chat | `./jig chat '#gigue'` |

You create `#gigue` once, from any machine: `jig channel create '#gigue'`.
Teammates do **not** need `jig channel join` for an `open` channel — v0.0.2
stores membership as derived state for bridge dispatch and does not gate reads
or sends on it. Run `jig channel join` only for a `restricted` channel.

### Step 5 — macOS Gatekeeper

The `jig` binary is unsigned and unnotarised. Anything that arrives by download
or AirDrop is tagged `com.apple.quarantine`, and Gatekeeper refuses to run it —
the failure is a modal dialog, or a bare `zsh: killed`, neither of which says
"quarantine".

```bash
xattr -d com.apple.quarantine ./jig
xattr -l ./jig                       # no com.apple.quarantine line
```

Build one binary per architecture if anyone is on Intel: `aarch64-apple-darwin`
for Apple Silicon, `x86_64-apple-darwin` for Intel. A binary of the wrong arch
fails with `Bad CPU type in executable`, which looks nothing like an arch
mismatch either. Ship the right one, or ship both under distinct names.

### Step 9 — their key is the only copy

`jig init` writes `~/.jig/keys/<did>.key` (0600) and `~/.jig/cli.toml`. **There
is no recovery and no key escrow.** Losing that file means losing the identity:
a new `jig init` produces a new DID, and their message history is attributed to
a DID nobody controls any more.

```bash
base64 ~/.jig/keys/*.key    # into 1Password, once, on day one
```

Restoring means putting the file back at that path with mode 0600 and keeping
`cli.toml`'s `did` pointed at it.

### Step 10 — staying connected

`jig chat` and `jig tail` do **not** reconnect on their own, but they now *detect*
a dropped connection: both exit non-zero with `connection lost` instead of hanging
or returning success. That makes a supervising loop work:

```bash
scripts/jig-room.sh '#gigue'
```

which is just `until jig chat "$1"; do sleep 2; done`. Use the same shape for
`jig tail`. This is the deliberate stand-in for real reconnect-with-backoff, and
it is load-bearing on the non-zero exit — if a future change makes either command
exit 0 on disconnect, the loop silently stops retrying.

Three smaller sharp edges:

- `jig tail` prints the raw 61-char DID and raw epoch-millis per line. Nicer rendering
  (`HH:MM`, a `[contacts]` name map, an inbound bell) is **in flight in this same batch**
  — check whether `jig-cli/src/cmd/display.rs` is wired up before promising it.
- `jig --version` is not implemented. Identify a build by its file hash.
- `--server`, `--config`, and `--did` are honoured by every subcommand,
  including `init`, `keys`, `server`, and `channel` (they were silently ignored
  for those four until recently). `--config <path>` requires the file to exist.

---

## Backups

`jig-backup.timer` runs `jig-backup.sh` daily at 03:17 UTC (`Persistent=true`,
so a rebooted box catches up). It snapshots:

| What | Why |
| --- | --- |
| `/var/lib/jig/jig.db` | v0.0.1 store |
| `/var/lib/jig/jig_v002.db` | **the v0.0.2 block store — where the actual messages are** |
| `/var/lib/jig/nameserver.db` | alias registry |
| `/var/lib/jig/server.key` | server identity |

**The `_v002` suffix is not a typo.** `jig-server` derives the v0.0.2 store path
from `database_path` by appending `_v002` to the file stem, so a configured
`/var/lib/jig/jig.db` means blocks live in `/var/lib/jig/jig_v002.db`. **Both
files exist and both matter** — a backup of only `jig.db` backs up essentially
nothing anyone typed.

Databases are copied with `sqlite3 … 'VACUUM INTO …'`, which takes a read lock
and writes one consistent file, so snapshots are safe while the server is
serving. `cp` of a live WAL database is not. The script aborts if `sqlite3` is
missing rather than producing a key-only "backup".

Output is `/var/backups/jig/<UTC timestamp>/` plus a `MANIFEST.txt` of sha256
sums. Snapshots older than `JIG_BACKUP_RETENTION_DAYS` (default 14) are pruned;
pruning only ever touches timestamp-shaped directories directly under
`JIG_BACKUP_DIR`. `DRY_RUN=1` shows what would go.

```bash
sudo -u jig JIG_BACKUP_RETENTION_DAYS=14 /opt/jig/bin/jig-backup.sh   # manual run
systemctl list-timers jig-backup.timer
journalctl -u jig-backup.service -n 50
```

`/var/backups/jig` is **on the same disk as the thing it is backing up**. Ship
it elsewhere — `tailscale file cp`, `rsync` to another tailnet node, or restic
to object storage. At minimum, get `server.key` off the box (top of this file).

### Restore

```bash
sudo systemctl stop jig-server jig-nameserver
sudo cp /path/to/snapshot/{jig.db,jig_v002.db,nameserver.db} /var/lib/jig/
sudo cp /path/to/snapshot/server.key /var/lib/jig/server.key
sudo chown -R jig:jig /var/lib/jig          # -R, not /var/lib/jig/* — see the
                                            # glob note in the TLS section above
sudo chmod 600 /var/lib/jig/server.key      # or the server refuses to start
sudo systemctl start jig-server jig-nameserver
curl http://100.x.y.z:7117/.well-known/jig  # server_did MUST match the old one
```

That last check is the whole point: if `server_did` changed, you restored the
databases without the key.

---

## The nameserver

The binary now serves the v0.0.2 alias API alongside the legacy routes:

| Route | Method | Notes |
| --- | --- | --- |
| `/v1/health` | GET | liveness |
| `/v1/challenge` | GET | v0.0.2 — issues a 64-hex nonce |
| `/v1/challenge` | POST | legacy PoW challenge; method-disjoint from the GET |
| `/v1/register` | POST | consumes a GET-issued challenge, returns an attestation |
| `/v1/resolve/:alias` | GET | v0.0.2 alias → DID |
| `/v1/resolve?name=` | GET | legacy |
| `/v1/rotate`, `/v1/renew` | POST | key rotation / renewal |
| `/v1/handles` | GET | **debug-gated** behind `[debug] list_handles` |

`/v1/handles` enumerates every registered alias, so it stays off unless you
explicitly set `list_handles = true`. Alias resolution never touches DNS, so the
default `alias_suffix` (`gigue.jig`) works on a tailnet and cannot leak
publicly — `.jig` is not an IANA TLD.

---

## Gotchas worth knowing before they cost you an evening

- **`jig-nameserver serve --bind/--port` ARE honoured**, and they win over both
  the config file and `JIG_NS_BIND`/`JIG_NS_PORT`. The shipped unit sets the env
  vars instead, which is still correct and still applied after any TOML load.
  *(The comment inside `jig-nameserver.service` still says the flags are parsed
  and ignored; that comment is stale.)*
- **`JIG_NS_SECRET` is mandatory** — the nameserver refuses to start without it,
  logging through tracing *and* stderr before exiting non-zero. It is in a
  required (no leading `-`) `EnvironmentFile` so a missing secret fails loudly
  instead of booting with a default PoW secret.
- **Secrets never go inline in a unit file.** `systemctl cat` is readable by any
  local user. `EnvironmentFile`, `chmod 600 root:jig`, always.
- **`MemoryDenyWriteExecute` is deliberately absent** from every unit. Blocks
  execute through wasmtime's cranelift JIT, which maps pages W then X; enabling
  W^X denial turns every block execution into a segfault.
- **`UMask=0077` is deliberate.** The server writes `server.key` on first boot
  and refuses to start later if the mode is loose.
- **`StateDirectory=jig`** makes systemd create and chown `/var/lib/jig`;
  `ReadWritePaths=/var/lib/jig` is still needed because `ProtectSystem=strict`
  makes everything else read-only, and SQLite must write `-wal`/`-shm` siblings
  in that directory.
- **Ports 7117 and 7070 are unprivileged**, so no `CAP_NET_BIND_SERVICE`. If you
  ever move the edge to `:443`, add `AmbientCapabilities=CAP_NET_BIND_SERVICE`
  rather than running as root.
- **Two processes, one host, on purpose.** Separate ports, separate databases,
  separate blast radius.
- **Building on the VPS needs a toolchain first.** A fresh box has no rustup, no
  C compiler, and no pkg-config; `ring` needs a C compiler. The workspace MSRV
  is **1.94** (`jig-runtime` and `jig-server` inherit it), set by wasmtime 47.
  A 1 vCPU box wants ~2 GB of swap and 45–90 minutes. Cross-building on your Mac
  and copying the binary over is usually the better trade.
