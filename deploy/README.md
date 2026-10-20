# Deploying jig on a tailnet VPS

Systemd units, a config template, and a backup job for running
`jig-server` + `jig-nameserver` on a single small VPS reachable **only over
Tailscale**.

| File | Purpose |
| --- | --- |
| `jig-server.service` | Block server, port **7117** |
| `jig-nameserver.service` | DID/alias registry, port **7070** |
| `config.example.toml` | The `/etc/jig/config.toml` template |
| `jig-backup.sh` | `VACUUM INTO` snapshots + `server.key` |
| `jig-backup.service` / `.timer` | Daily 03:17 UTC backup |

Each unit file carries its own rationale in comments. This document covers the
sequence and the things that are not visible from inside a single file.

---

## 🔴 BACK UP `/var/lib/jig/server.key` OFFSITE. TODAY.

**LOSING `/var/lib/jig/server.key` CHANGES THE SERVER DID.**

The server DID is derived from that 32-byte ed25519 seed. If the key is gone, the
server comes back up with a **different identity**:

- every receipt it signs from then on is under a new key, unlinkable to its
  earlier receipts;
- federation peers that list this server by `expected_did` now hold a stale value;
- once clients pin the server DID on first contact (the mandatory handshake,
  JEP-0002), every client will see what is indistinguishable from a
  man-in-the-middle. Clients do not pin it yet, so today this is the next
  release's problem, not an excuse to skip the backup.

Restoring a database without the key restores nothing useful.

User nickname pins (the server-side TOFU lock that binds a nickname to a user's
DID) live in the database, not in the key, and survive a key loss.

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
  did = "did:jig:z..."          # each member's DID — including the operator's own
  ruleset_key = "club"
  score = 1
  ```

  Reputation is ruleset-scoped, so a floor never refuses a DID that has no
  score under its ruleset — that case is the `unknown_dids` choice, by
  design, so a fresh key is not punished for being fresh. Three things to
  know before switching a server to `refuse`:

  - **Your own key needs a record.** `jig channel create`, `member-add` and
    `archive` are signed writes, and admission runs on writes too. Without a
    record for the operator's DID, the operator is a stranger.
  - **Bridges cannot run on a members-only server.** The email bridge signs
    inbound mail with a shadow DID minted per sender at runtime; those can
    never be in `records`, so every inbound message is refused.
  - **The policy is read at boot.** Editing `banned_dids` or `records` takes
    effect on the next restart, not before — and an already-open WSS
    subscription belongs to a DID that was admitted when it subscribed; it
    keeps its channel-level checks per delivery, but is not re-admitted until
    it reconnects.

  Every configured DID is parsed and canonicalized at boot; one that could
  never match a key (a typo, a legacy label) is a startup error, because a
  ban that cannot match is worse than none. The read escape hatch
  (`require_authenticated_reads = false`) skips admission for reads — there
  is no proof to admit — but never for writes.

What it does not enforce yet — the reasons to keep `bind_address` on the
tailnet:

- **No reputation scoring.** Admission consumes scores the operator wrote
  down; nothing computes or exchanges them yet. With the default
  `unknown_dids = "admit"`, anyone who can reach the port can create channels
  and post to open ones, within `[auth.rate_limit]`. `unknown_dids =
  "proof-of-work"` makes each new key do some hashing first, which slows an
  identity flood but does not stop one.
- **Federated peers vouch for their authors.** Blocks relayed from a peer run
  the same admission, write and suite gates as local ones, except that their
  authors are not asked for proof-of-work: they never spoke to this server.
  Only federate with servers you would let post on your behalf.
- **Channel ops are on by default.** `POST /api/v1/channels*` is always
  mounted and runs the same gates as every other write: anyone who can reach
  the port can create an open channel.
- **End-to-end encryption is per channel.** Restricted channels and DMs are
  always MLS, and open channels are MLS only when created `--encrypted`. The
  operator reads every other open channel and sees who posts where and when in
  all of them. See `docs/RELEASE_READINESS.md` §1.3.
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

# 3b. nameserver config — EDIT IT, it must name the suffixes you serve
sudo install -m 0644 deploy/jig-nameserver.example.toml /etc/jig/jig-nameserver.toml
sudoedit /etc/jig/jig-nameserver.toml

# 4. optional env files (bridge tokens etc.): chmod 600 root:jig
#    sudo chmod 600 /etc/jig/jig-server.env
#    /etc/jig/jig-nameserver.env is optional too; the nameserver needs no secret

# 5. units
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
the root keys and every section in one file.

### Verify the deploy

| Check | Command | Expect |
| --- | --- | --- |
| Server liveness | `curl -k https://100.x.y.z:7117/healthz` | `200`, body `ok` |
| Server identity | `curl -k https://100.x.y.z:7117/.well-known/jig` | `server_did`, `tls_binding` and `unsafe_options_active` |
| Server counters | `curl -k https://100.x.y.z:7117/metrics` | Prometheus text |
| Channel list | `curl -k https://100.x.y.z:7117/api/v1/channels` | `401` `AUTH_REQUIRED` — reads are signed; use `jig channel list` instead |
| Nameserver liveness | `curl -k https://100.x.y.z:7070/v1/health` | `{"status":"ok"}` |
| Nameserver identity | `curl -k https://100.x.y.z:7070/.well-known/jig-ns` | `server_did`, `tls_binding` and `unsafe_options_active` |
| Nameserver alias API | `curl -k https://100.x.y.z:7070/v1/challenge` | `{"challenge":"<64 hex>"}` |
| Units | `systemctl status jig-server jig-nameserver` | both `active (running)` |

> ⚠️ **`jig-server` serves TLS by default**, on every route of its one port:
> `/healthz`, `/metrics`, `/.well-known/jig`, `/api/v1/*` and the WebSocket.
> With no `[tls] cert_path`/`key_path` it makes a self-signed certificate on
> first start (`tls/` next to the database) and its DID vouches for it at
> `/.well-known/jig`. `jig` trusts it through the DID it pinned, so `curl`
> needs `-k`, and `jig` needs nothing. An `http://` request to the port gets no
> usable response, and **`curl -s` hides the error**. A client still set to
> `http://` is told to run `jig server set https://…`.
>
> **Upgrading a server that ran without `[tls]`:** it comes back on TLS. Every
> client re-runs `jig server set https://…`; their pins and encrypted-channel
> state carry over, because neither is keyed by the scheme. To keep plaintext
> (behind a proxy that terminates TLS, say), set `[tls] enabled = false`. The
> server then lists `tls.enabled=false` in `/.well-known/jig`'s
> `unsafe_options_active` and logs a startup warning (#120). A `jig` CLI refuses a
> plaintext `http://` server that is not on its own machine (#142).
>
> **The nameserver on `:7070` serves TLS by default too**, from its own `[tls]`
> section in `/etc/jig/jig-nameserver.toml` (same keys). Its self-signed
> certificate lives in `/var/lib/jig/nameserver/tls/`, apart from jig-server's,
> and the nameserver's DID vouches for it at `/.well-known/jig-ns`.
>
> **Upgrading a nameserver that served plaintext:** it comes back on TLS, and
> `http://…:7070` stops answering. Point every client and server at
> `https://…:7070` instead (`jig --nameserver`, `[server] nameserver_url`, and
> the nameserver URLs in delegations). Clients accept the certificate on the
> word of the DID the suffix's delegation lists, not on a CA's alone, so a
> reverse proxy in front of the nameserver must pass TLS through, not
> terminate it.
> An `http://` nameserver is refused unless the client opts in, for loopback
> or local testing only: `[identity] dangerously_allow_plaintext_nameservers`
> on jig-server (listed in `unsafe_options_active`), `[naming]
> dangerously_allow_plaintext_nameservers` in the CLI's `cli.toml`.

`/healthz` and `/metrics` are always mounted and need no signed read,
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

## The config file, in one paragraph

`main.rs` loads `--config` once, into one `ServerConfig`. Root-level keys
(`database_path`, `bind_address`, `port`, `[tls]`, `[execution]`) are **what
actually binds**. `[server]`, `[identity]`, `[auth]`, `[federation]`, `[debug]`
and `[bridges]` configure the pipeline. Every table denies unknown fields, so a
typo or a key in the wrong section stops the boot with serde's error, which names
the key and lists the valid ones. A key jig-server used to accept and has since
removed fails with `` `<key>` is no longer a jig-server config key: <why>. Delete
it. `` (#199).

**An explicitly-passed `--config` that fails to parse is now FATAL.** The server
logs `[jig-server] FATAL: config load from <path> failed: …` to both tracing and
stderr and exits `1`. It no longer falls back to defaults, which used to mint a
fresh server DID (see the top of this file). A missing `--config` still means
"use defaults" — that path is legitimate and unchanged.

Three landmines:

- **`[server] listen` is DECORATIVE.** It only builds the `ws://…` origin-tag
  string. It does **not** control the bind address. The server now logs a
  startup `WARN` when `listen` disagrees with the effective `bind_address:port`.
- **The `/_admin_v0_0_2/*` aliases are gone**, and `[debug] admin_endpoints`
  with them. Current CLIs use `/api/v1/channels*`, which is always mounted. A
  config that still sets the key **refuses to boot**: delete the line. Configs
  written by v0.1.0-alpha.1's installer carry `admin_endpoints = false` and need
  that one deletion.
- **The unsigned v0.0.1 REST surface is gone** (D28): `GET`/`POST /blocks`,
  `/blocks/:cid` and `/receipts/:cid` answer `404`, and the
  `dangerously_enable_v0_0_1_rest` flag is a removed key: a config that sets it
  refuses to boot. `jig read` uses the
  signed history endpoint, `GET /api/v1/channels/<slug>/blocks`.

### Reading history

Reads are signed, so a bare `curl` gets `401 AUTH_REQUIRED`. Let the CLI
sign for you:

```bash
jig tail --channel '#hello'    # backfills the last 100 blocks, then follows
```

Under the hood that is `GET /api/v1/channels/%23hello/blocks?limit=100` with
five `x-jig-*` headers carrying an ed25519 proof over the request (see
`jig_client::ReadProof`). Blocks come back oldest-first as a JSON array
(`bundle_b64`, `receipts`, `delivery_cid`); add `&before=<block cid>` for the page
just older than that block. A restricted channel you are not
a member of is `403 NOT_A_MEMBER`; a channel with no local row (federated, or
mistyped) is `200` with `[]`. `limit` defaults to and is clamped at **200**.

---

## A CA-issued certificate with `tailscale cert` (no certbot, no public DNS)

The server's own self-signed certificate is enough for `jig`, which trusts it
through the server DID. For a certificate browsers and `curl` trust too,
Tailscale issues genuine Let's Encrypt certificates for your MagicDNS name,
with **no public DNS record, no port 80 challenge, and no public exposure
whatsoever**. This is strictly better than certbot here.

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

Point the server's `[tls]` block at them:

```toml
[tls]
cert_path = "/var/lib/jig/tls/<host>.<tailnet>.ts.net.crt"
key_path  = "/var/lib/jig/tls/<host>.<tailnet>.ts.net.key"
```

`systemctl restart jig-server`, and
`curl https://<host>.<tailnet>.ts.net:7117/healthz` works from any tailnet
device **without `-k`**. Clients use `wss://` for the same host.

**Renewal is not automatic here.** The server reads the cert once at startup (no
hot reload). Certs are ~90 days, so re-run `tailscale cert` and restart the
service on a monthly timer. Each restart, the server DID vouches for whatever
certificate it serves, so `jig` clients follow a renewal without re-pinning.
Or remove `cert_path`/`key_path` to go back to the self-signed certificate.

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
| 6 | Them | Confirm the server is reachable | `curl -k https://100.x.y.z:7117/healthz` |
| 7 | Them | Create an identity | `./jig init <nickname>` |
| 8 | Them | Point at the server | `./jig server set https://100.x.y.z:7117` |
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
| `/var/lib/jig/jig_v002.db` | **the v0.0.2 block store — where the actual messages are** |
| `/var/lib/jig/nameserver.db` | the nameserver's legacy registry |
| `/var/lib/jig/nameserver_v002.db` | **the nameserver's alias bindings** |
| `/var/lib/jig/server.key` | server identity |
| `/var/lib/jig/nameserver_v002.key` | **the nameserver's signing key** (set `JIG_NAMESERVER_KEYFILE` if `[v0_0_2.server] server_did_keyfile` puts it elsewhere) |

The nameserver files are skipped on a box that doesn't run the nameserver, but
a snapshot is refused if `nameserver_v002.db` exists without its key. **A
restore without `nameserver_v002.key` loses the nameserver's DID**: the
nameserver mints a new key, and every attestation the old one signed stops
verifying for servers and clients whose delegation names the old DID.

**The `_v002` suffix is not a typo.** `jig-server` derives its store path from
`database_path` by appending `_v002` to the file stem, so a configured
`/var/lib/jig/jig.db` means blocks live in `/var/lib/jig/jig_v002.db`.
`jig.db` itself is no longer opened: the v0.0.1 store it held was removed
(#196). On a box upgraded from an older release the file is still there and
unused; delete it yourself once no backup you keep needs it. Nothing deletes
it for you.

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
to object storage. At minimum, get `server.key` and `nameserver_v002.key` off the box (top of this
file).

### Restore

```bash
sudo systemctl stop jig-server jig-nameserver
sudo cp /path/to/snapshot/{jig_v002.db,nameserver.db,nameserver_v002.db} /var/lib/jig/
sudo cp /path/to/snapshot/server.key /var/lib/jig/server.key
sudo cp /path/to/snapshot/nameserver_v002.key /var/lib/jig/nameserver_v002.key
sudo chown -R jig:jig /var/lib/jig          # -R, not /var/lib/jig/* — see the
                                            # glob note in the TLS section above
sudo chmod 600 /var/lib/jig/server.key      # or the server refuses to start
sudo chmod 600 /var/lib/jig/nameserver_v002.key
sudo systemctl start jig-server jig-nameserver
curl -k https://100.x.y.z:7117/.well-known/jig  # server_did MUST match the old one
```

That last check is the whole point: if `server_did` changed, you restored the
databases without the key.

---

## The nameserver

The binary serves the alias API and its discovery documents. The legacy routes
(proof-of-work challenges, `/v1/claim`, `/v1/alias`, `/v1/policy`, admin,
reputation, tribunal, transparency and federation) were removed:

| Route | Method | Notes |
| --- | --- | --- |
| `/.well-known/jig-ns`, `/.well-known/jig-ns/capabilities` | GET | discovery documents |
| `/v1/health` | GET | liveness |
| `/v1/challenge` | GET | issues a 64-hex nonce |
| `/v1/register` | POST | consumes a GET-issued challenge, returns an attestation |
| `/v1/resolve/:alias` | GET | the signed alias attestation, plus transitional unsigned hints (`did`, `alias`, `valid_until`) |
| `/v1/suffixes` | GET | suffixes served, their registration mode, and this nameserver's DID |
| `/.well-known/jig-ns-delegation` | GET | signed delegation for a DNS-rooted suffix (`?suffix=`, else the `Host`) |
| `/v1/rotate`, `/v1/renew` | POST | key rotation / renewal |
| `/v1/handles` | GET | **debug-gated** behind `[debug] list_handles` |

> **Rate limits.** The nameserver limits `POST /v1/register`, `/v1/rotate` and
> `/v1/renew` per client IP (default 30/min) and per DID (default 10/min,
> counting only requests that succeed, each of which needs that DID's
> signature). Set them in `[alias_rate_limits]` (`enabled`, `per_ip_per_min`,
> `per_did_per_min`). Refused requests get HTTP 429 with code `RATE_LIMITED`
> and a `Retry-After` header. IPv6 clients are limited per /64. If the
> nameserver runs behind a reverse proxy, set `[network] trust_proxy = true`
> and `proxy_ip_header` (default `x-forwarded-for`); the nameserver uses the
> last address in that header, the one your proxy appended. With one proxy in
> front this is the client's address; behind several, the limit applies to the
> nearest proxy. Without `trust_proxy`, every client behind the proxy shares
> the proxy's address and its limit. Limits are in memory and reset when the
> nameserver restarts.

None of the nameserver's routes asks for proof-of-work.

`/v1/handles` enumerates every registered alias, so it stays off unless you
explicitly set `list_handles = true`.

**Suffixes.** `[[v0_0_2.nameserver.alias_suffixes]]` is required and has no
default: the nameserver refuses to start until you name at least one suffix
(see `deploy/jig-nameserver.example.toml`). One DID holds at most one name per
suffix. Each suffix sets its own policy: `registration = "open" | "closed"`
(a closed suffix still resolves, renews and rotates), `min_alias_len`
(default 3), reserved names, and `registration_allow`, a list of DIDs with the
exact aliases each may register past that policy. A single-label suffix such
as `jig` also needs `single_label_authority = true`: clients trust it only
through their own config, so its names verify only for clients whose config
names this nameserver's DID.

For a DNS-rooted suffix, `/.well-known/jig-ns-delegation` serves this
nameserver's signed delegation; a resolver treats it as authoritative only when
fetched from `https://<suffix>/`. `GET /v1/suffixes` lists the suffixes served
and this nameserver's DID.

**Key ceremony.** `jig-nameserver keygen --out <path>` writes a new signing key
(0600, never overwriting an existing file) and prints only the DID, so the DID
can be recorded on an offline machine before any server exists. Point
`[v0_0_2.server] server_did_keyfile` at the file.

---

## Gotchas worth knowing before they cost you an evening

- **`jig-nameserver serve --bind/--port` ARE honoured**, and they win over both
  the config file and `JIG_NS_BIND`/`JIG_NS_PORT`. The shipped unit sets the env
  vars instead, which is still correct and still applied after any TOML load.
  *(The comment inside `jig-nameserver.service` still says the flags are parsed
  and ignored; that comment is stale.)*
- **The nameserver needs no secret.** `JIG_NS_SECRET` and the `[pow]` section
  went with the legacy proof-of-work routes (#192), and `[rate_limits]` with the
  legacy rate limits (#197). An env file that still sets `JIG_NS_SECRET`,
  `JIG_NS_POW_*` or `JIG_NS_RATE_*`, or a config that still has `[pow]` or
  `[rate_limits]`, is harmless: nothing reads them, so remove them at your own
  pace. The unit's
  `EnvironmentFile=` is optional (leading `-`) and only carries any `JIG_NS_*`
  settings you choose to put there.
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
  is **1.95** (`jig-runtime` and `jig-server` inherit it), set by wasmtime 48.
  A 1 vCPU box wants ~2 GB of swap and 45–90 minutes. Cross-building on your Mac
  and copying the binary over is usually the better trade.
