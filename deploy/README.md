# Deploying jig on a tailnet VPS

Systemd units, a config template, and a backup job for running
`jig-server` + `jig-nameserver` on a single small VPS reachable **only over
Tailscale**.

| File | Purpose |
| --- | --- |
| `jig-server.service` | Block server, port **7117** |
| `jig-nameserver.service` | DID/alias registry, port **7070** |
| `config.example.toml` | The `/etc/jig/config.toml` template |
| `jig-backup.sh` | `VACUUM INTO` snapshots + the sealed `server.jigkey` |
| `jig-backup.service` / `.timer` | Daily 03:17 UTC backup |
| `setup-server-key.sh` | Seals the server's or nameserver's key to a systemd credential plus an offline passphrase ([Sealing the server key](#sealing-the-server-key)) |

Each unit file carries its own rationale in comments. This document covers the
sequence and the things that are not visible from inside a single file.

---

## 🔴 BACK UP `/var/lib/jig/server.jigkey`, AND A WAY TO OPEN IT, OFFSITE. TODAY.

**LOSING THE SERVER KEY CHANGES THE SERVER DID.**

The server DID is derived from a 32-byte ed25519 seed. `server_did_keyfile =
"/var/lib/jig/server.key"` names `/var/lib/jig/server.jigkey` beside it, which
holds the seed sealed (XChaCha20-Poly1305 under a key that one of its slots
unwraps). If the key is gone, the server comes back up with a **different
identity**:

- every receipt it signs from then on is under a new key, unlinkable to its
  earlier receipts;
- federation peers that list this server by `expected_did` now hold a stale value;
- every client that pinned the server DID on first contact (JEP-0002) sees what
  is indistinguishable from a man-in-the-middle.

Restoring a database without the key restores nothing useful.

User nickname pins (the server-side TOFU lock that binds a nickname to a user's
DID) live in the database, not in the key, and survive a key loss.

**A backup of `server.jigkey` restores only with a secret for one of its slots.**
The server boots with a systemd credential ([Sealing the server
key](#sealing-the-server-key)). Give the key a second slot, a passphrase kept
offline, so it can be opened on another machine:

```bash
# With jig-server running: root can read the credential [keys] unlock names.
sudo -i     # a root shell: nothing below lands in a unit, the journal or ps
read -rs -p 'new passphrase: ' JIG_KEY_PASSPHRASE; echo; export JIG_KEY_PASSPHRASE
/opt/jig/bin/jig-server --config /etc/jig/config.toml keys add-slot --slot passphrase
chown jig:jig /var/lib/jig/server.jigkey
unset JIG_KEY_PASSPHRASE
/opt/jig/bin/jig-server --config /etc/jig/config.toml keys show
```

The passphrase goes into the password manager; the sealed file goes into the
backups.

Two related traps:

- The server writes its key `0600` on first boot. A raw `server.key` must not be
  left beside `server.jigkey`: the server refuses to start until it is removed.
- Restoring the key onto a *different* host is what you want. Restoring the
  databases without it is not.

Teammates have the same problem one level down: see
[Teammate onboarding](#teammate-onboarding) — `~/.jig/keys/*.jigkey` is the only
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
> state carry over, because neither is keyed by the scheme.
>
> **jig-server terminates TLS itself; do not put a TLS-terminating proxy in
> front of it.** The signed welcome carries the connection's TLS exporter (#234),
> so a server behind a proxy that terminates TLS signs an empty exporter, and
> every remote client refuses it. If something must sit in front of jig-server,
> it passes TLS through (TCP or SNI passthrough). `[tls] enabled = false` serves
> plaintext for loopback or local testing only: the server lists
> `tls.enabled=false` in `/.well-known/jig`'s `unsafe_options_active` and logs a
> startup warning, and a `jig` CLI refuses a plaintext `http://` server that is
> not on its own machine (#142).
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
actually binds**. `[server]`, `[identity]`, `[auth]`, `[federation]`, `[debug]`,
`[bridges]` and `[limits]` configure the pipeline. Every table denies unknown fields, so a
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

### Size limits

`[limits]` sets explicit, configurable limits on how much jig-server reads at
once:

| Key | Covers | Over the limit |
|---|---|---|
| `max_request_body_bytes` | every HTTP request body, bridge webhooks included | `413 Payload Too Large`, before the body is parsed |
| `max_ws_message_bytes` | one WebSocket message, on connections from clients and on the ones it dials to federation peers | the connection is closed |
| `max_ws_frame_bytes` | one WebSocket frame, on the same connections | the connection is closed |

Unset, each is 2 162 688 bytes (`jig_core::bundle::MAX_ENVELOPE_BYTES`): the
largest block submission, a 1.5 MiB bundle (`MAX_BUNDLE_BYTES`) in base64 plus its
envelope. That is the smallest value that still carries every valid block, so
the server refuses to boot with a smaller one, or with a frame limit above the
message limit. Raise them only if a proxy or a bridge in front of the server
needs it.

```toml
[limits]
# max_request_body_bytes = 2162688
# max_ws_message_bytes = 2162688
# max_ws_frame_bytes = 2162688
```

The nameserver has its own body limit, `[network] max_body_bytes` (64 KiB by
default): see `repos/jig-nameserver/OPERATOR_GUIDE.md`.

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
| `/var/lib/jig/nameserver_v002.db` | **the nameserver's alias bindings** |
| `/var/lib/jig/server.jigkey` | server identity, sealed |
| `/var/lib/jig/server.key.link*` | the server's key links, when it serves one: the configured key path with `.link` appended, and earlier links kept as `.link.1`, `.link.2`, ... and `.link.pruned-N`. Without them, clients that pinned an earlier DID refuse the restored server |
| `/var/lib/jig/server.retired-*.jigkey` | keys a rotation retired, still sealed |
| `/var/lib/jig/nameserver_v002.jigkey` | **the nameserver's signing key**, sealed (set `JIG_NAMESERVER_KEYFILE` if `[v0_0_2.server] server_did_keyfile` puts it elsewhere) |

A key still in clear (`[keys] storage = "plaintext"`) is copied too, with a
warning, and the snapshot then holds it in clear. A snapshot holds no secret
that opens a sealed key; `MANIFEST.txt` records which keys were sealed. A
rotation's retired credential (`/etc/credstore.encrypted/*.retired-*`) is not in
the snapshot either: it is the operator's to move offline.

The nameserver files are skipped on a box that doesn't run the nameserver, but
a snapshot is refused if `nameserver_v002.db` exists without its key. **A
restore without `nameserver_v002.jigkey` loses the nameserver's DID**: the
nameserver mints a new key, and every attestation the old one signed stops
verifying for servers and clients whose delegation names the old DID.

**The `_v002` suffix is not a typo.** `jig-server` derives its store path from
`database_path` by appending `_v002` to the file stem, so a configured
`/var/lib/jig/jig.db` means blocks live in `/var/lib/jig/jig_v002.db`.
`jig.db` itself is no longer opened: the v0.0.1 store it held was removed
(#196). On a box upgraded from an older release the file is still there and
unused; delete it yourself once no backup you keep needs it. Nothing deletes
it for you.

**`nameserver.db` is the same story, with a key in it.** `jig-nameserver`
derives `nameserver_v002.db` and `nameserver_v002.key` from `database_path`
(`JIG_NS_DB_PATH`) the same way, and no longer opens `nameserver.db` itself:
its legacy registry, analytics and `analyze`/`export` subcommands were removed.
That file's `ns_identity` table holds a raw signing seed that signs nothing any
more. Once `nameserver_v002.db` and `nameserver_v002.key` are in place, delete
`nameserver.db` **and every old backup that contains it**. Keep
`JIG_NS_DB_PATH` set: it names where the `_v002` files live.

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
to object storage. At minimum, get `server.jigkey` and `nameserver_v002.jigkey` off the box, and
their passphrases into a password manager (top of this file).

### Restore

```bash
sudo systemctl stop jig-server jig-nameserver
sudo cp /path/to/snapshot/{jig_v002.db,nameserver_v002.db} /var/lib/jig/
sudo cp /path/to/snapshot/server.jigkey /var/lib/jig/server.jigkey
sudo cp /path/to/snapshot/nameserver_v002.jigkey /var/lib/jig/nameserver_v002.jigkey
sudo chown -R jig:jig /var/lib/jig          # -R, not /var/lib/jig/* — see the
                                            # glob note in the TLS section above
sudo chmod 600 /var/lib/jig/*.jigkey
sudo systemctl start jig-server jig-nameserver
curl -k https://100.x.y.z:7117/.well-known/jig  # server_did MUST match the old one
```

That last check is the whole point: if `server_did` changed, you restored the
databases without the key.

On the same machine the keys open with the credential they were sealed with. On
**another machine** a TPM-bound credential does not decrypt: make this host's
credential ([Sealing the server key](#sealing-the-server-key), step 1), then add
it as a slot, opening the key with its offline passphrase:

```bash
sudo -i
read -rs -p 'passphrase: ' JIG_KEY_PASSPHRASE; echo; export JIG_KEY_PASSPHRASE
/opt/jig/bin/jig-server --config /etc/jig/config.toml keys add-slot --slot \
  credential:<(systemd-creds decrypt --name=jig-server-key /etc/credstore.encrypted/jig-server-key -)
chown jig:jig /var/lib/jig/server.jigkey
unset JIG_KEY_PASSPHRASE
```

The old machine's credential slot stays in the file and opens nothing here.
`sudo deploy/setup-server-key.sh` does the same: it makes the credential, and
adds it after checking that the passphrase opens the key.

### Sealing the server key

A server boots unattended, so its key opens with a secret the server is handed
at start, never typed. `[keys] unlock` names it. The recommended one is a
systemd credential, encrypted to this machine's TPM where it has one, plus a
passphrase kept offline for restoring on other hardware.

`deploy/setup-server-key.sh` does all of it, and changes nothing when run again:

```bash
sudo deploy/setup-server-key.sh               # jig-server; asks for the passphrase
sudo systemctl restart jig-server
sudo deploy/setup-server-key.sh --nameserver  # jig-nameserver
sudo systemctl restart jig-nameserver
```

It makes the credential, then makes the key sealed (`keys generate`), seals a
raw one in place (`keys seal`, same DID), or adds whichever of the credential
and the passphrase does not open an existing sealed key yet (`keys verify`,
`keys add-slot`). Then it writes a drop-in with `LoadCredentialEncrypted=` and
sets `unlock`. It never prints a secret, refuses to replace a credential, a key
or a different `unlock` it finds, and moves them aside (a NEW DID) only with
`--force`. `--import SEED` seals a raw 32-byte seed from elsewhere as the key.
Without `systemd-creds` (systemd before 250), `--passphrase-only` seals the
key with the passphrase alone, and the server then needs `JIG_KEY_PASSPHRASE`
at every boot. Once it is done, store the passphrase offline: it is the only
thing that opens the key on another machine.

By hand, the same steps:

1. Make the secret, encrypted at rest. `--with-key=auto` uses the TPM2 when there
   is one, and otherwise a host key in `/var/lib/systemd/credential.secret`:
   ```bash
   sudo install -d -m 0700 /etc/credstore.encrypted
   head -c 48 /dev/urandom | base64 | sudo systemd-creds encrypt --with-key=auto \
     --name=jig-server-key - /etc/credstore.encrypted/jig-server-key
   ```
2. Hand it to the unit (`jig-server.service` carries the line, commented):
   `LoadCredentialEncrypted=jig-server-key:/etc/credstore.encrypted/jig-server-key`.
3. Name it in `/etc/jig/config.toml`:
   ```toml
   [keys]
   unlock = "credential:/run/credentials/jig-server.service/jig-server-key"
   ```
4. A new server seals its first key with it. A server upgraded from a release
   that wrote a raw `server.key` refuses to start and names this command, which
   seals the key in place, keeps its DID and removes the raw file:
   ```bash
   sudo systemctl stop jig-server
   sudo bash -c '/opt/jig/bin/jig-server --config /etc/jig/config.toml keys seal --slot \
     credential:<(systemd-creds decrypt --name=jig-server-key /etc/credstore.encrypted/jig-server-key -)'
   sudo chown jig:jig /var/lib/jig/server.jigkey
   sudo systemctl start jig-server
   ```
   Removing the raw file does not erase it from the disk or from earlier backups.
   Then add the offline passphrase slot (top of this file).

   An upgraded nameserver with a raw `nameserver_v002.key` refuses to start the
   same way. Seal it with `sudo deploy/setup-server-key.sh --nameserver`, or by
   hand with `jig-nameserver --config /etc/jig/jig-nameserver.toml keys seal
   --slot ...` and the same slot as `[v0_0_2.keys] unlock`.

To check, at any time, that a secret still opens the key without trying anything
else (the offline passphrase, say, before you rely on it):

```bash
sudo -i
read -rs -p 'passphrase: ' JIG_KEY_PASSPHRASE; echo; export JIG_KEY_PASSPHRASE
/opt/jig/bin/jig-server --config /etc/jig/config.toml keys verify --slot passphrase
unset JIG_KEY_PASSPHRASE
```

What each choice protects against:

| `[keys] unlock` | Protects the key against | Not against |
| --- | --- | --- |
| `credential:`, TPM-bound | a copied disk, image or backup: the secret decrypts only on this machine's TPM | root on the running machine |
| `credential:`, host key | a backup of `/var/lib/jig` alone | a copy of the whole disk, which holds the host key too |
| `env:NAME` from a secret manager | whatever the manager protects; nothing on this disk | anyone who can read the process environment |
| a secret in a file beside the key | almost nothing: whoever reads one reads both | |
| `storage = "plaintext"` | nothing; warned about on every boot | |

At-rest encryption does not protect a key from code running as the server's
user while it runs, and does not protect the key in memory.

### Rotating the server key

A server's DID is its key, so a new key is a new DID. `keys rotate` makes the
new key and a **key link** from the old DID to the new one, signed by both
keys (JEP-0012). The server serves the link in every welcome and at
`/.well-known/jig`, and clients and federation peers that pinned the old DID
follow it to the new one.

```bash
sudo deploy/setup-server-key.sh --rotate
sudo systemctl restart jig-server
```

It asks for a **new** offline passphrase (or reads `JIG_KEY_NEW_PASSPHRASE`)
and makes a new credential secret, so nothing that opened the old key opens
the new one. In place, so the config and the drop-in do not change:

| File | After `--rotate` |
| --- | --- |
| `/var/lib/jig/server.jigkey` | the new key, opened by the new credential and the new passphrase |
| `/var/lib/jig/server.key.link` | the link from the old DID to the new one: back it up with the key |
| `/var/lib/jig/server.key.link.N` | the links of earlier rotations, still served: back them up too |
| `/var/lib/jig/server.retired-<DID tail>.jigkey` | the old key, still sealed |
| `/etc/credstore.encrypted/jig-server-key.retired-<time>` | the old credential |

**Keep the retired key, never delete it:** move it and the old credential
offline. Nothing needs them to serve the link; they keep the old DID's key
usable if anything ever has to be signed by it again, such as a revocation
once there is one.

By hand, the same is
`jig-server keys rotate --slot credential:PATH --slot passphrase`, with the old
key opened by `[keys] unlock`, `JIG_KEY_UNLOCK` or `JIG_KEY_PASSPHRASE`, and the
new passphrase in `JIG_KEY_NEW_PASSPHRASE`. For a key made offline with
`keys generate`, `jig-server keys link --old-keyfile OLD --keyfile NEW` writes
only the link, beside `NEW`.

**Every rotation is followed.** The earlier link is kept as `server.key.link.1`
(then `.2`, and so on) and served with the new one, as a chain: a client pinned
on any earlier DID follows every hop. Back up `server.key.link*`, not only
`server.key.link`. A broken or missing earlier link only shortens the chain,
and the server logs which file it left out; clients pinned behind it are
refused until it is restored. A broken `server.key.link` stops the server.

A chain holds at most 16 links, the most a client follows. After that,
`--rotate --prune-oldest` moves the oldest aside (`server.key.link.pruned-1`,
kept, not served): a client still pinned on the DID it leaves is refused, with
an error saying the server changed its key more than once, and must re-pin,
which trusts the server on first use again.

A DID is linked to one new key only, ever: two links from one DID are what a
stolen key looks like (JEP-0012), and clients that see both follow neither.
`keys rotate` and `keys link` refuse to link a DID that a link beside the key
already leaves.

Not covered yet: federation peers follow the link, but their operators should
still update `expected_did`; JEP-0012's `server-rekey` block is not
implemented; and the nameserver has no key link, so a new nameserver key is a
new identity.

---

## Federation: sharing a channel with another server

Two servers federate only if each lists the other under `[[federation.peers]]`
(see `config.example.toml`), with the other's `/.well-known/jig` `server_did`
as `expected_did`. Restart both after editing.

To carry a channel on the other server (JEP-0005), so its users can read it
there in this server's order:

1. **The channel's owner, or an admin with the `share` right**, on this
   server:

   ```sh
   jig channel share '#team' did:jig:<other server> --grant read
   ```

   `--grant` is `read`, `write` or `member` (JEP-0005 rule 7a). The server
   checks the signer's right, and refuses a share naming a server that is not
   one of its peers: the refusal shows in the channel as `NOT_A_PEER`.
2. **The other server's operator** accepts the offer:

   ```sh
   sudo -u jig /opt/jig/bin/jig-server --config /etc/jig/config.toml contracts list
   sudo -u jig /opt/jig/bin/jig-server --config /etc/jig/config.toml contracts accept <offer-id>
   ```

   As `jig`, not root: the command writes to the server's database. The
   running server acts on it within 5 seconds. Skip this step by setting
   `offers = "accept"` in that server's peer entry for this one. `contracts
   refuse <offer-id>` turns an offer down.
3. **Users of the other server** read the channel by its id, which `jig channel
   share` prints: `jig read <channel-id>`. A slug names a channel only on the
   server that orders it, so `jig read '#team'` there finds nothing.

`jig channel unshare '#team' did:jig:<other server>` (or `contracts end
<offer-id>` on either server) ends the share. This server stops sending at
once. The other server keeps the copy it holds and lands nothing after.

Today, only open, unencrypted channels can be shared, and the other server
does not yet relay writes back: its users post on this server.

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
> the proxy's address and its limit. This applies only to a proxy that
> terminates TLS, so only to a nameserver for a DNS-rooted suffix, whose clients
> check its certificate against a CA. A nameserver for a `config` or `contract`
> suffix must not sit behind one: clients accept only the certificate its DID
> vouches for, so serve it directly or behind TCP/SNI passthrough. A
> passthrough proxy cannot add `x-forwarded-for`, so leave `trust_proxy` off
> there. Every client then shares the proxy's address and its limit: the
> nameserver does not read PROXY protocol either. Limits are in memory and
> reset when the nameserver restarts.

Register, renew and rotate ask for proof-of-work only on a suffix whose
`pow.min_effort` is above 0 (see **Proof-of-work** below).

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

**Proof-of-work.** Register, renew and rotate can carry JEP-0008
proof-of-work, set per suffix in `[v0_0_2.nameserver.alias_suffixes.pow]`. It
is on by default, at the recommended values: 2^20 to register, 4× more per
letter under 5, at most 2^24, and 1 to renew or rotate. `jig` solves it;
`min_effort = 0` turns it off. A client asks
`GET /v1/challenge?action=register|renew|rotate&did=&name=`, and the reply
states the effort, signed by the nameserver (`pow_offer`). The policy's
refusals (closed, too short, reserved, taken) come back
there, before any work. A per-suffix `[v0_0_2.nameserver.alias_suffixes.pool]` (on by default: 60 an
hour, burst 10) caps stranger registrations per hour and raises the effort under load; see the
nameserver's OPERATOR_GUIDE. `[alias_rate_limits]` caps `GET /v1/challenge` per IP
(`challenge_per_ip_per_min`, default 60) and the challenges pending at once
(`max_pending_challenges`, default 100 000; past it, `503 BUSY`, with a tenth
kept for renew and rotate).

For a DNS-rooted suffix, `/.well-known/jig-ns-delegation` serves this
nameserver's signed delegation; a resolver treats it as authoritative only when
fetched from `https://<suffix>/`. `GET /v1/suffixes` lists the suffixes served
and this nameserver's DID.

**Key ceremony.** `jig-nameserver keygen --out <path> --slot passphrase` writes
a new signing key, sealed (0600, never overwriting an existing file), and prints
only the DID, so the DID can be recorded on an offline machine before any
server exists. The key is never written in clear. Move the `.jigkey` to the
server, point `[v0_0_2.server] server_did_keyfile` at it, and add the server's
credential with `jig-nameserver keys add-slot --slot credential:...`, opening
it with the ceremony passphrase in `JIG_KEY_PASSPHRASE` (the same
root-shell pattern as for jig-server). A key made elsewhere as a raw 32-byte
seed is imported with `keys seal`, which keeps its DID. Nameserver keys open as
`[v0_0_2.keys]` says, the same section as jig-server's `[keys]`.

On the server, `sudo deploy/setup-server-key.sh --nameserver` finishes the
ceremony: with the `.jigkey` where the config names it, it asks for the
ceremony passphrase, checks that it opens the key, and adds the machine's
credential. For a raw seed from elsewhere, `--import SEED` seals it instead,
and then the seed file is the key in clear: destroy it, or keep it offline as
carefully as the passphrase.

**TLS in front of a nameserver.** Clients reach a nameserver over TLS only
when the certificate it presents is the one its DID binds in
`/.well-known/jig-ns`, and CA roots are not consulted. A TLS-terminating proxy
presents its own certificate and is refused, so put the nameserver on the
public address itself, or behind a proxy that passes TLS through (TCP or SNI
passthrough) without terminating it.

---

## Gotchas worth knowing before they cost you an evening

- **`jig-nameserver serve --bind/--port` ARE honoured**, and they win over both
  the config file and `JIG_NS_BIND`/`JIG_NS_PORT`. The shipped unit sets the env
  vars instead, which is still correct and still applied after any TOML load.
  *(The comment inside `jig-nameserver.service` still says the flags are parsed
  and ignored; that comment is stale.)*
- **The nameserver needs no secret, and its config is strict (#247).**
  `JIG_NS_SECRET` and `[pow]` went with the legacy proof-of-work routes (#192),
  `[rate_limits]` with the legacy rate limits (#197), and `[federation]` with
  nameserver federation (#237). A config that still has any of these sections,
  or `[transparency]`, `[runtime]`, `[anomaly_detection]`, `[hot]` or a
  `storage`/`analytics` `backend` key, **stops the nameserver from starting**,
  with a message naming the key: delete it. An env file that still sets
  `JIG_NS_SECRET`, `JIG_NS_POW_*`, `JIG_NS_RATE_*`, a federation variable or
  another removed `JIG_NS_*` variable starts, with a warning naming each one;
  remove them at your own pace. The unit's
  `EnvironmentFile=` is optional (leading `-`) and only carries any `JIG_NS_*`
  settings you choose to put there.
- **Secrets never go inline in a unit file.** `systemctl cat` is readable by any
  local user. `EnvironmentFile`, `chmod 600 root:jig`, always.
- **`MemoryDenyWriteExecute` is set on `jig-nameserver.service` only.** jig-server
  executes blocks through wasmtime's cranelift JIT, which maps pages W then X;
  W^X denial makes it fail to start. The nameserver runs no blocks and, built on
  its own, links no Wasm engine. Build it in its own cargo invocation
  (`cargo build --release -p jig-nameserver`): built together with jig-server,
  cargo unifies features and links the executor into it too. It still never
  creates an executable mapping, but the binary carries wasmtime for nothing.
- **`UMask=0077` is deliberate.** The server writes `server.jigkey` owner-only
  on first boot, and refuses a raw key whose mode is loose.
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
