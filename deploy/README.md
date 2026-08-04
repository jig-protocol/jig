# Deploying jig on a tailnet VPS

Systemd units, a hybrid config template, and a backup job for running
`jig-server` + `jig-nameserver` on a single small VPS reachable **only over
Tailscale**.

| File | Purpose |
| --- | --- |
| `jig-server.service` | Block server, port **7117** |
| `jig-nameserver.service` | DID/handle registry, port **7070** |
| `config.example.toml` | The hybrid `/etc/jig/config.toml` |
| `jig-backup.sh` | `VACUUM INTO` snapshots + `server.key` |
| `jig-backup.service` / `.timer` | Daily 03:17 UTC backup |

---

## 🔴 BACK UP `/var/lib/jig/server.key` OFFSITE. TODAY.

**LOSING `/var/lib/jig/server.key` CHANGES THE SERVER DID AND BREAKS TOFU
PINNING FOR EVERY CLIENT.**

The server DID is derived from that 32-byte ed25519 seed. Every client that has
talked to this server has pinned the resulting DID on first contact (TOFU). If
the key is gone, the server comes back up with a **different identity**, and
every client sees what is indistinguishable from a man-in-the-middle: they do
not silently re-pin, and there is no recovery short of every user wiping their
pin. Restoring a database without the key restores nothing useful.

It is 32 bytes. Copy it somewhere off this machine — a password manager entry is
fine — before you put a single message through the server.

```bash
sudo base64 /var/lib/jig/server.key   # paste into 1Password, then forget it exists
```

Two related traps:

- The server **generates** the key `0600` on first boot and **refuses to start**
  later if the file is group- or other-readable (it hard-fails on `mode & 0o077`).
  If you restore it from backup, `chmod 600` and `chown jig:jig` it.
- Restoring the key onto a *different* host is what you want. Restoring the
  databases without it is not.

---

## Security model: the tailnet IS the authentication

There is no authn and no authz in the server. None. **Tailnet membership is the
only authentication this deployment has.** What protects it is that
`bind_address` is a Tailscale `100.x.y.z` address, so only devices in your
tailnet can reach the socket at all.

Consequences to internalise:

- **Never set `bind_address = "0.0.0.0"`.** That publishes an unauthenticated
  block store to the internet.
- `admin_endpoints = true` (required, below) exposes unauthenticated channel
  creation and membership changes. Safe on a tailnet, catastrophic off it.
- The nameserver's `/v1/register` has no auth beyond proof-of-control of a
  self-minted key. Same rule.
- Removing someone from the tailnet is how you remove their access.

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

# 4. nameserver secret (MANDATORY — it panics at startup without one)
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
enabling it — see the gotcha below.

Verify:

```bash
curl http://100.x.y.z:7117/.well-known/jig     # server DID + active unsafe flags
curl http://100.x.y.z:7070/v1/health
systemctl status jig-server jig-nameserver
```

---

## ⚠️ The unit MUST order after tailscaled

Both units carry:

```ini
After=network-online.target tailscaled.service
Wants=network-online.target tailscaled.service
```

Binding a `100.x` address requires the Tailscale interface to already exist.
Without this ordering the service starts before tailscaled, `bind(2)` returns
`EADDRNOTAVAIL`, the unit dies — and because it happens on **reboot**, nobody
notices until the whole team tries to use it the next morning.

`After=` only orders unit *start*; tailscaled being "active" does not guarantee
the address is assigned yet. `Restart=on-failure` + `RestartSec=5s` covers that
residual race — the first attempt may lose it, the retry wins. Do not strip the
restart settings thinking the ordering is enough.

If your box is slow enough to lose the race repeatedly, add a gate:

```ini
ExecStartPre=/usr/bin/tailscale ip -4
```

(left out by default so a missing/relocated `tailscale` binary can't
permanently wedge the unit).

---

## The hybrid config, in one paragraph

`main.rs` loads the same `--config` file into **two unrelated structs**.
Root-level keys (`database_path`, `bind_address`, `port`, `[tls]`) become
`ServerConfig` and are **what actually binds**. `[server]`, `[identity]`,
`[federation]`, `[debug]`, `[bridges]` become `JigServerConfig`. Neither type
uses `deny_unknown_fields`, so each ignores the other's sections in silence —
which is exactly why editing the wrong half produces no error and no effect.

Two specific landmines, both called out in `config.example.toml`:

- **`[server] listen` is DECORATIVE.** It only builds the `ws://…` origin-tag
  string. It does **not** control the bind address. Keep it in sync with the
  root-level values anyway, or clients get handed a URL the server isn't on.
- **`[debug] admin_endpoints = true` is REQUIRED.** With it false, the
  `/_admin_v0_0_2/*` router is never mounted and `jig channel create` returns a
  bare **404** that looks like a wrong URL, wrong port, or a bad build.

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
sudo chown jig:jig /var/lib/jig/tls/*
sudo chmod 600 /var/lib/jig/tls/*.key
```

Point the server's existing `[tls]` block at them:

```toml
[tls]
enabled = true
cert_path = "/var/lib/jig/tls/<host>.<tailnet>.ts.net.crt"
key_path  = "/var/lib/jig/tls/<host>.<tailnet>.ts.net.key"
```

`systemctl restart jig-server`, and
`curl https://<host>.<tailnet>.ts.net:7117/.well-known/jig` works from any
tailnet device **without `-k`**. Clients use `wss://` for the same host.

**Renewal is not automatic here.** The server reads the cert once at startup
(no hot reload). Certs are ~90 days, so re-run `tailscale cert` and restart the
service on a monthly timer, or leave TLS off for a short-lived dogfood — the
tailnet is already an encrypted transport, so plain HTTP over it is not the
exposure it would be on the public internet.

---

## Backups

`jig-backup.timer` runs `jig-backup.sh` daily at 03:17 UTC (`Persistent=true`,
so a rebooted box catches up). It snapshots:

| What | Why |
| --- | --- |
| `/var/lib/jig/jig.db` | v0.0.1 store |
| `/var/lib/jig/jig_v002.db` | **the v0.0.2 block store — where the actual messages are** |
| `/var/lib/jig/nameserver.db` | handle registry |
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
sudo chown jig:jig /var/lib/jig/*
sudo chmod 600 /var/lib/jig/server.key      # or the server refuses to start
sudo systemctl start jig-server jig-nameserver
curl http://100.x.y.z:7117/.well-known/jig  # server_did MUST match the old one
```

That last check is the whole point: if `server_did` changed, you restored the
databases without the key.

---

## Gotchas worth knowing before they cost you an evening

- **`jig-nameserver serve --bind/--port` are parsed and ignored** (documented
  TODO in its `main.rs`). Bind and port come from `JIG_NS_BIND` / `JIG_NS_PORT`,
  which is why the unit sets them as `Environment=`. Env is applied *after* any
  TOML config load, so it wins.
- **`JIG_NS_SECRET` is mandatory** — the nameserver panics at startup without
  it. It is in a required (no leading `-`) `EnvironmentFile` so a missing secret
  fails loudly instead of booting with a default PoW secret.
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
