# GCP runbook: the internal MVP box

**Audience:** DJ, solo, traveling, on a Mac, needs a box up today.
**Scope:** one GCP VM running `jig-server` (:7117) and `jig-nameserver` (:7070),
reachable **only** over Tailscale.

> **What I could not verify.** I have no GCP access. Every price below is
> approximate, region-dependent, list-price, and possibly stale — **confirm in
> the console / pricing calculator before you commit.** I also could not check
> your quota (a fresh project caps CPUs per region, often at 8 — enough for
> everything here, but check if `instances create` fails with a quota error).
> Build wall-clock numbers are estimates extrapolated from the workspace's
> dependency graph, not measured on GCP.

---

## RECOMMENDATION BOX — if you stop reading here, do this

**Create it big, build on it, shrink it.** GCP lets you stop an instance, change
its machine type, and start it again on the same boot disk and the same
Tailscale identity. Build on 4 vCPU / 16 GB in ~30 minutes instead of fighting
swap for 90; then run on 2 GB for the rest of its life.

| | |
|---|---|
| **Build machine type** | `e2-standard-4` (4 vCPU, 16 GB) |
| **Run machine type** | `e2-small` (2 vCPU shared, 2 GB) |
| **Image** | `debian-12` (`debian-cloud`) |
| **Disk** | 50 GB `pd-balanced` |
| **Region/zone** | `us-west1-a` — what the live `jig-internal` box actually runs, so the commands below are copy-pasteable as written |
| **External IP** | **none** (`--no-address`) — required by org policy and correct anyway |
| **Egress** | Cloud NAT (mandatory — see below) |
| **Ingress firewall rules** | **none**, after you delete the temporary IAP rule |
| **Steady-state cost** | ~$21/month for the VM **plus Cloud NAT** (see the cost table — approximate) |

> **If you change the zone, change it everywhere.** Every command below is
> `us-west1-a` / `us-west1` so it works unedited. Should you move regions, note
> that **the Cloud Router / NAT is regional and its `--region` must match the
> instance's region** (`us-west1-a` → `--region=us-west1`) — a mismatch there
> yields a VM with no route to the internet and *no error at create time*, which
> is the worst combination to debug.

Why `e2-standard-4` and not `c4-standard-4`: **C4 requires Hyperdisk Balanced,
and E2 cannot attach Hyperdisk.** If you build on C4 you cannot shrink to E2
afterwards without migrating the disk. Staying inside the E2 family makes the
resize a three-command no-op. That single constraint decides the machine family.

### The commands, in order

```bash
# 0. one-time project setup
gcloud config set project <PROJECT_ID>
gcloud config set compute/zone us-west1-a
gcloud services enable compute.googleapis.com

# 1. a dedicated VPC with NO ingress rules (default-deny is the whole security model)
gcloud compute networks create jig-net --subnet-mode=auto

# 2. Cloud NAT — outbound only. MANDATORY, not optional: a VM with no external
#    IP also has no outbound internet, so it cannot apt-get, fetch rustup, or
#    reach controlplane.tailscale.com to join the tailnet. --region MUST match
#    the instance's region.
gcloud compute routers create jig-nat-router \
  --network=jig-net --region=us-west1

gcloud compute routers nats create jig-nat \
  --router=jig-nat-router --region=us-west1 \
  --auto-allocate-nat-external-ips \
  --nat-all-subnet-ip-ranges

# 3. ONE temporary SSH rule for the bootstrap, deleted in step 7.
#    Scoped to Google's IAP range — NOT your IP, NOT 0.0.0.0/0. With no
#    external IP there is nothing to reach directly; IAP tunnels in.
gcloud compute firewall-rules create jig-iap-ssh \
  --network=jig-net --direction=INGRESS --action=ALLOW \
  --rules=tcp:22 --source-ranges=35.235.240.0/20 \
  --description='TEMPORARY: IAP TCP forwarding for bootstrap. Delete once tailscale ssh works.'

# 4. the box, built big, with NO external IP
gcloud compute instances create jig-vps \
  --zone=us-west1-a \
  --machine-type=e2-standard-4 \
  --image-family=debian-12 --image-project=debian-cloud \
  --boot-disk-size=50GB --boot-disk-type=pd-balanced --boot-disk-device-name=jig-vps \
  --network=jig-net --subnet=jig-net \
  --no-address \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
  --metadata=enable-oslogin=TRUE \
  --no-service-account --no-scopes

# 5. get on it, through the IAP tunnel
gcloud compute ssh jig-vps --zone=us-west1-a --tunnel-through-iap

# 6. (on the box) everything else — see "Provisioning the box" below

# 7. (back on your Mac, AFTER tailscale ssh is verified working)
gcloud compute firewall-rules delete jig-iap-ssh
```

### Why `--no-address`, and what it costs you

Omit it and `instances create` assigns an ephemeral external IP by default. On
an org with `constraints/compute.vmExternalIpAccess` set — which `jig-internal`
has — that fails outright:

```
ERROR: Constraint constraints/compute.vmExternalIpAccess violated for project ...
```

Work with the policy rather than requesting an exception: jig is tailnet-only by
design and never wanted a public address. The policy and the architecture agree.

Three consequences, none of them blockers but all of them surprises if you meet
them at 2am:

- **Cloud NAT is a real line item.** It bills per gateway-hour *plus* per-GB
  processed, so it can be a meaningful fraction of the VM's ~$21/month. Check
  the pricing calculator — the figure is not quoted here because it was not
  verified. There is no way to avoid it: `tailscaled` must reach its
  coordination server even if you build the binaries somewhere else.
- **IAP needs an IAM grant on *you*, not just the firewall rule** —
  `roles/iap.tunnelResourceAccessor`. If step 5 fails with a permissions error
  rather than a network timeout, that is why.
- **`--no-service-account --no-scopes` blocks the GCS backup** described later
  in this document. A VM with no service account cannot call any Google API.
  Keep the flags for now (safer default, and backup is not day-one); §8b
  ("A write-only service account") has the `set-service-account` sequence, which
  requires stopping the instance.

`--no-service-account --no-scopes` means the VM has no Google API credentials at
all. That is the right default; **Section 8** re-attaches a narrow, write-only
service account when you set up GCS backups, during the stop you are already
doing for the resize.

---

## 1. Machine type — the decision

The build, not the runtime, is what sizes this box. Three verified properties of
this workspace make the build unusually heavy for a Rust service:

1. **The release profile is fat LTO.** `repos/Cargo.toml` sets `lto = true`
   (fat, not thin) and `codegen-units = 1`. The final link is **single-threaded
   and memory-hungry** — for a wasmtime-containing binary, expect multiple GB of
   RSS in one process. Extra vCPUs do not speed up that phase; RAM is what keeps
   it from dying.
2. **Cranelift, possibly twice — check which tree you are building.** At `HEAD`
   (`13ccfa4`), `jig-server` depends directly on `wasmtime 16.0.0` *and* — via
   `jig-runtime` — on `wasmtime 23.0.3`, so `cranelift-codegen` **0.103 and
   0.110 both compile**. Cranelift is among the slowest crates in the
   ecosystem, and at `HEAD` you pay for it twice. **An uncommitted change in
   this worktree (not mine) unifies both on `wasmtime 24.0.12` /
   `cranelift-codegen 0.111.12`**, which drops the union graph from 472 to
   **420 crates**. If that dedup has landed by the time you build, the build is
   materially cheaper; if you build a tag that predates it, assume the heavier
   number. Either way, cranelift dominates the compile.
3. **420-472 unique crates** in the union graph of `jig-server` +
   `jig-nameserver` + `jig-cli` (420 with the wasmtime dedup, 472 without),
   including `ring` (needs a C compiler) and `rusqlite` with `bundled`
   (compiles SQLite from source).

| Option | Specs | Build? | Run? | Verdict |
|---|---|---|---|---|
| `e2-micro` | 2 shared vCPU (0.25 baseline), 1 GB | **No** | Yes, with swap | Free-tier eligible. See Section 2. |
| `e2-small` | 2 shared vCPU (0.5 baseline), 2 GB | Marginal — fat-LTO link will thrash or OOM | Yes, comfortably | **The run target.** |
| `e2-medium` | 2 shared vCPU (1.0 baseline), 4 GB | Slow but survivable (~60-90 min) | Yes | Fallback if you skip the resize dance. |
| `e2-standard-4` | 4 vCPU, 16 GB | **Yes, ~25-40 min** | Overkill | **The build target.** Resizes to E2 cleanly. |
| `c4-standard-4` | 4 vCPU, 15 GB | Yes, fastest | Overkill | **Avoid** — Hyperdisk requirement blocks the shrink to E2. |

### The e2-micro build failure mode, plainly

`e2-micro` gives you 1 GB of RAM and a **0.25 vCPU baseline** with burst credits
that deplete in minutes. `rustc` on a 400+-crate graph will exhaust burst credits
in the first few minutes, then run at a quarter of one core. Meanwhile the fat
LTO link needs more RAM than the machine has, so it goes to swap — and swap on a
network-attached persistent disk means every page fault is a round-trip over the
network. The observable symptom is not a crash but a build that appears to hang
at `Compiling wasmtime` with `%wa` (iowait) pegged near 100 and load average
climbing past 8. If it does not OOM-kill `rustc` outright, it takes many hours.
**Do not build on `e2-micro`.**

### The resize sequence (exact)

```bash
# instance MUST be TERMINATED to change machine type
gcloud compute instances stop  jig-vps --zone=us-west1-a
gcloud compute instances set-machine-type jig-vps --zone=us-west1-a \
  --machine-type=e2-small
gcloud compute instances start jig-vps --zone=us-west1-a
```

What survives the stop/start: the boot disk, `/var/lib/jig`, `server.key`, the
Tailscale node identity and its `100.x` address, and the MagicDNS name (Tailscale
state lives in `/var/lib/tailscale`). What changes: the ephemeral **external** IP
— which you do not care about, because nothing ever connects to it.

Do the resize *after* the build and *after* you have verified the services come
up, so that a bad build and a bad resize can never be confused for each other.

### Alternative A — let CI build it (probably your fastest path)

`.github/workflows/release.yml` **already has an `x86_64-unknown-linux-gnu` row**
building on `ubuntu-latest`, packaging `jig-server`, `jig`, `jig-nameserver` and
`text_block.wasm` into `jig-linux-x86_64.tar.gz`. Tagging a release gets you
prebuilt Linux binaries with zero build on the VM.

Two caveats, both real:

- The workflow triggers **only on `v*` tags** — there is no `workflow_dispatch`.
  Cutting a tag is your call and outside this runbook.
- **glibc.** `ubuntu-latest` is Ubuntu 24.04 (glibc 2.39). Debian 12 is glibc
  2.36. A binary linked against 2.39 will refuse to start on Debian 12 with
  `version 'GLIBC_2.38' not found`. **If you take the CI-tarball path, create
  the VM with `--image-family=ubuntu-2404-lts --image-project=ubuntu-os-cloud`
  instead of `debian-12`.** Do not mix.

### Alternative B — cross-build on your Mac, `scp` the binary

Your Mac is arm64. A GCP E2/N2/C4 instance is amd64. Building
`x86_64-unknown-linux-gnu` inside Colima/Docker on Apple Silicon means qemu
user-mode emulation for the entire 400+-crate compile, cranelift included. That
is **slower than the 1 vCPU GCP build you are trying to avoid**. Rejected.

### Should you use an ARM GCP instance instead (`t2a` / `c4a`)?

Tempting — it would let you build natively in a `linux/arm64` container on the
Mac. My assessment: **no, not today.**

- Dependency-tree risk is **low**: `ring` 0.17, `wasmtime` with cranelift,
  and `libsqlite3-sys` (bundled) all support `aarch64-unknown-linux-gnu` as a
  tier-1-ish target. I would expect it to compile.
- The risk is **operational, not technical**: `release.yml` explicitly dropped
  `aarch64-linux` ("nobody on the team consumes them"). So an ARM box is a target
  with **zero CI coverage** — the first time anyone finds a problem is you, alone,
  traveling. `t2a` is also restricted to a handful of zones and does not support
  live migration.
- The payoff is small. You would trade a 30-minute one-time cloud build for a
  novel unsupported architecture on the one machine the whole team depends on.

Revisit ARM when you want the ~40% price/perf win at steady state and you can add
a CI row to prove it.

---

## 2. The free-tier question: can `e2-micro` *run* it?

**Yes, running is fine. Building is not.** These are separate questions and only
the second one disqualifies `e2-micro`.

Memory arithmetic for 1 GB (estimates; measure with `systemd-cgtop` once live):

| Process | Expected RSS |
|---|---|
| Debian 12 base (systemd, journald, sshd, cron) | 130-200 MB |
| `tailscaled` | 40-70 MB |
| `jig-server` (idle, 10 users, SQLite + wasmtime) | 60-120 MB |
| `jig-nameserver` | 40-90 MB |
| **Total** | **~270-480 MB** |

That leaves 500+ MB of headroom on a 1 GB box, which is genuinely comfortable for
a 10-person text chat. Two things to watch:

- **wasmtime's pooling allocator reserves large *virtual* address space.**
  `jig-runtime` enables `pooling-allocator`. Virtual is not resident, so it does
  not consume RAM — but it looks alarming in `top`'s VIRT column, and it can trip
  a memory *overcommit* policy if you have tightened `vm.overcommit_memory`.
  Leave Debian's default (`0`) alone.
- **`[execution] memory_max_mb = 64`** is per-instantiation. Concurrent block
  execution multiplies it. At 10 users this is noise; at 100 it is not.

**But:** you cannot build there, so the free box has to receive binaries built
elsewhere — which puts you back on Alternative A (CI tarball, and therefore
Ubuntu 24.04, not Debian 12) or on a second throwaway build VM. Also note the
free tier covers `e2-micro` in `us-west1` / `us-central1` / `us-east1` only, one
instance, 30 GB-months of **`pd-standard`** (not balanced), and 1 GB/month of
North-America egress — and **it does not obviously cover the external IPv4
charge** (~$3.65/mo), so "free" is realistically "a few dollars". Confirm that
line item yourself; it is the one people get surprised by.

**Verdict: not worth it for the MVP.** The delta between free and `e2-small` is
roughly $12/month, and you are buying the ability to rebuild on the box at 2am
when something is broken and you are in a different timezone. Take `e2-small`.

If you do take `e2-micro`, add swap anyway as a safety net, not as a build
strategy — and read the SQLite warning below before you do.

---

## 3. Disk

**Recommendation: 50 GB `pd-balanced`.** Do not go smaller: GCP persistent disks
can grow but **cannot shrink**, so this is a one-shot decision, and on
`pd-standard` the IOPS budget scales with size — a 30 GB `pd-standard` disk gets
you roughly 37 read IOPS, which turns a cargo build into a disk-bound crawl.

### Measured data point: the cargo target dir is enormous

Measured just now on this checkout (`du -sh repos/target`):

```
 18G  repos/target          <- ALL debug
 15G    target/debug/deps
3.9G    target/debug/incremental
232M    target/debug/build
```

That is the **debug** profile with all workspace members (including the
riverdance GUI crates and `integration-tests`) and incremental artifacts. A
`--release` build of only `-p jig-server -p jig-cli -p jig-nameserver` is much
smaller — no incremental, no GUI, fewer dev-deps — but with cranelift in the
graph I would still budget **4-6 GB** for `target/release` (estimate; I could
not measure it without running the build). Add ~1-2 GB for
`~/.cargo/registry` after `cargo fetch` (`~/.cargo` on this Mac is 3.4 GB, but
that is accumulated across many projects, so treat it as an upper bound).

Budget:

| | |
|---|---|
| Debian 12 base image | ~2.5 GB |
| `~/.cargo` after fetch | ~1-2 GB |
| source checkout | ~30 MB (498 tracked files) |
| `target/release` (3 packages) | ~4-6 GB (estimate) |
| **Build peak** | **~10-12 GB** |
| **Runtime** (after `cargo clean`) | **~4 GB** |

50 GB leaves room for the build, `/var/backups/jig`, and journald, and you never
have to think about it again. It costs about $5/month.

### Where `/var/lib/jig` lives

**On the boot disk. Do not add a second disk.** The systemd units already use
`StateDirectory=jig` (systemd creates and chowns `/var/lib/jig` at 0750) plus
`ReadWritePaths=/var/lib/jig` (because `ProtectSystem=strict` makes everything
else read-only, and SQLite must write its `-wal`/`-shm` siblings *in the
directory*). A separate data disk buys you nothing here — the databases for a
10-person chat are megabytes, and a second disk is a second thing to forget to
snapshot.

After the build, reclaim the space:

```bash
cd ~/jig/repos && cargo clean          # frees the whole target dir
```

Keep `~/.cargo/registry` — it makes the next rebuild dramatically faster.

### SQLite and swap — read before adding swap

If you add swap (required on `e2-micro`, optional on `e2-small`, unnecessary on
`e2-standard-4`), understand the interaction: SQLite's durability guarantees
assume `fsync` reaches stable storage. Swap does not break that — but a box under
memory pressure swapping heavily will stall SQLite writes for seconds at a time
while the page cache is evicted, and the WAL grows because checkpoints cannot
complete. The symptom is "chat feels frozen", not corruption. **Swap is a
safety net against OOM-kill, not a substitute for RAM.** 2 GB is the right size
if you use it at all.

---

## 4. Provisioning the box

Everything from here runs **on the VM**, over
`gcloud compute ssh … --tunnel-through-iap` (step 5 of the recommendation box)
until noted otherwise.

### 4a. Tailscale first — before anything else

```bash
curl -fsSL https://tailscale.com/install.sh | sh

# --ssh enables Tailscale SSH, which is what lets you delete the GCP SSH rule.
# --hostname fixes the MagicDNS name so the TLS cert path is predictable.
sudo tailscale up --ssh --hostname=jig-vps

# follow the printed URL, authenticate in a browser, approve the node

tailscale ip -4          # <- THE 100.x.y.z ADDRESS. Everything below needs it.
tailscale status
```

Now, **from your Mac, in a second terminal**, prove Tailscale SSH works before
you burn the bridge:

```bash
tailscale status | grep jig-vps
ssh jig-vps                      # or: ssh <user>@jig-vps.<tailnet>.ts.net
```

Only once that succeeds, run the step-6 firewall deletion.

**Tailscale SSH requires an ACL grant.** In the tailnet admin console your policy
needs an `ssh` rule permitting your user to `jig-vps` (default tailnets ship one;
a locked-down policy may not). Check this *now*, while you still have the GCP SSH
rule.

### 4b. Firewall — the key insight is that you need no ingress rules at all

Tailscale is **outbound-only**. `tailscaled` dials out (UDP 41641 and DERP relays
over TCP 443) and NAT-traverses; nothing on the internet ever needs to initiate a
connection to this VM. GCP's default egress policy is allow-all, so **the correct
ingress configuration is the empty set.**

Concretely:

- **Never** create a rule for `tcp:7117` or `tcp:7070`. The server now
  authenticates reads and enforces channel membership (see `deploy/README.md`,
  "Security model"), but it has **no admission policy**: any self-minted key
  is admitted, unthrottled, and can create channels and post to open ones. The
  nameserver's `/v1/register` has no auth beyond proof-of-control of a
  self-minted key. Publishing either of these is a footgun, not merely untidy.
- **Never** set `bind_address = "0.0.0.0"`. Bind the `100.x` address.
- The dedicated `jig-net` VPC exists precisely so that a rule someone adds to the
  `default` network later cannot reach this box. This is why the runbook creates
  a network rather than reusing `default` and deleting `default-allow-ssh` —
  deleting that rule would affect every other VM in the project.

**Tradeoff on removing SSH access.** After step 7 there is no inbound path except
Tailscale. If `tailscaled` fails to start after a reboot, or the tailnet auth key
expires, or you get removed from your own tailnet, you are locked out of the
guest OS. Your break-glass options, best first:

1. **Re-add the IAP rule.** You still have full control-plane access via
   `gcloud`; it is one command and ~30 seconds. This is the real answer.
   ```bash
   gcloud compute firewall-rules create jig-iap-ssh --network=jig-net \
     --direction=INGRESS --action=ALLOW --rules=tcp:22 --source-ranges=35.235.240.0/20
   gcloud compute ssh jig-vps --zone=us-west1-a --tunnel-through-iap
   ```
   **It must be the IAP range, not `<YOUR_IP>/32`.** The box has no external
   address, so a rule scoped to your own IP allows traffic that can never
   arrive — a trap that only reveals itself at the moment you are locked out.
2. **Serial console.** Requires enabling it *and* having a local account with a
   password set — GCP hands you a login prompt, not a root shell. Set that up in
   advance or it is useless in the moment:
   ```bash
   gcloud compute instances add-metadata jig-vps --metadata=serial-port-enable=TRUE
   gcloud compute connect-to-serial-port jig-vps --zone=us-west1-a
   ```

Because option 1 exists, deleting the SSH rule is low-risk. Do it.

To also make node key expiry a non-event, **disable key expiry for this node** in
the tailnet admin console (Machines → jig-vps → Disable key expiry). A server
whose key silently expires in 180 days is exactly the failure you will not
diagnose from an airport.

### 4c. Build dependencies — the exact apt line

```bash
sudo apt-get update
sudo apt-get install -y build-essential curl git ca-certificates sqlite3
```

That is the whole list. Justification, verified against the actual dependency
graph rather than assumed:

- **`build-essential`** — mandatory. Supplies `cc`, `libc6-dev`, `make`. `ring`
  0.17 (pulled by `rustls` and `jsonwebtoken`) and `libsqlite3-sys` 0.28 with
  `bundled` (compiles SQLite from source) both invoke a C compiler. A fresh image
  has none.
- **`sqlite3`** — mandatory, and easy to miss. `deploy/jig-backup.sh` calls
  `sqlite3 … 'VACUUM INTO …'` and **hard-fails** without it: *"a backup that
  silently skips the databases is worse than no backup at all."*
- **`curl`, `git`, `ca-certificates`** — rustup installer and the clone.
- **`libssl-dev` — NOT needed. Do not install it.** I checked:
  `cargo tree -p jig-server -i openssl-sys` returns *"did not match any
  packages"*, same for `jig-nameserver` and `jig-cli`. The workspace pins
  `reqwest = { version = "0.12", default-features = false, features = ["json",
  "rustls-tls"] }`, so the `native-tls` → `openssl-sys` path is never enabled.
  The `openssl` entries still visible in `Cargo.lock` are unactivated optional
  deps, not a build requirement.
- **`pkg-config` — not required either**, for the same reason (nothing in these
  three graphs is a `-sys` crate that probes the system). Adding it costs
  nothing and is harmless insurance if you later flip a feature; it is not
  needed for the build described here.

### 4d. Rust toolchain

There is no `rust-toolchain.toml` at `repos/` — the only one in the tree is
`repos/jig-spec/rust-toolchain.toml`, which is not a workspace member and pins
`channel = "stable"`. So: **plain stable**. The workspace is `edition = 2024`
and uses let-chains, so it needs a recent stable (1.85+); installing today's
stable is correct.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"
rustc --version        # expect 1.8x stable
```

`--profile minimal` skips docs and clippy — you are not developing on this box.

### 4e. Swap (skip entirely on `e2-standard-4`)

Only if you chose `e2-small`/`e2-micro` and are building on it:

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
sudo sysctl vm.swappiness=10          # prefer reclaiming cache over swapping
free -h
```

Re-read the SQLite/swap note in Section 3 before you rely on this.

### 4f. Clone and build

```bash
git clone git@github.com:jig-protocol/jig.git ~/jig
cd ~/jig/repos
git checkout main          # NOT a worktree branch — see the dogfood plan's "rule zero"

cargo build --release -p jig-server -p jig-cli -p jig-nameserver
```

Run it under `tmux` or `screen` so a dropped hotel wifi connection does not kill
the build:

```bash
sudo apt-get install -y tmux
tmux new -s build
# ... run cargo build ...
# detach: Ctrl-b then d      reattach: tmux attach -t build
```

**If you are building on a 2-4 GB box and the LTO link is thrashing**, you can
downgrade the link without touching a committed file:

```bash
CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  cargo build --release -p jig-server -p jig-cli -p jig-nameserver
```

That trades a few percent of runtime performance and some binary size for a
link step that parallelises and fits in memory. It leaves `repos/Cargo.toml`
untouched, which matters — the release profile is shared with CI.

Expected release binary sizes (measured on arm64 macOS; amd64 will be close):
`jig` 3.0 MB, `jig-server` 8.4 MB, `jig-nameserver` 9.4 MB. `lto` and `strip`
are already on.

### 4g. Install — user, dirs, binaries, units

This is `deploy/README.md`'s install block, reproduced so you do not have to
switch files:

```bash
cd ~/jig

# 1. dedicated non-root user, no shell
sudo useradd --system --home-dir /var/lib/jig --shell /usr/sbin/nologin jig
sudo install -d -o jig -g jig -m 0750 /var/lib/jig /var/backups/jig
sudo install -d -m 0755 /etc/jig /opt/jig/bin

# 2. binaries + backup script
sudo install -m 0755 repos/target/release/jig-server     /opt/jig/bin/
sudo install -m 0755 repos/target/release/jig-nameserver /opt/jig/bin/
sudo install -m 0755 deploy/jig-backup.sh                /opt/jig/bin/

# 3. config — EDIT IT. the 100.x.y.z placeholders are not real.
sudo install -m 0644 deploy/config.example.toml /etc/jig/config.toml
tailscale ip -4
sudoedit /etc/jig/config.toml
#   set root-level  bind_address = "<the 100.x address>"   <- this is what binds
#   set [server]    listen = "<the 100.x address>:7117"    <- decorative, but keep in sync
#   leave [debug]   admin_endpoints = true                 <- REQUIRED or channel create 404s

# 4. nameserver secret — MANDATORY, it panics at startup without one
printf 'JIG_NS_SECRET=%s\n' "$(openssl rand -hex 32)" \
  | sudo tee /etc/jig/jig-nameserver.env >/dev/null
sudo chown root:jig /etc/jig/jig-nameserver.env
sudo chmod 600 /etc/jig/jig-nameserver.env

# 5. units — EDIT jig-nameserver.service's Environment=JIG_NS_BIND first
sudoedit deploy/jig-nameserver.service        # JIG_NS_BIND=<the 100.x address>
sudo install -m 0644 deploy/jig-server.service deploy/jig-nameserver.service \
                     deploy/jig-backup.service deploy/jig-backup.timer \
                     /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now jig-server jig-nameserver jig-backup.timer
```

Verify:

```bash
curl http://<100.x.y.z>:7117/.well-known/jig    # server DID + active unsafe flags
curl http://<100.x.y.z>:7070/v1/health
systemctl status jig-server jig-nameserver
```

**Do not skip the `After=tailscaled.service` check.** Both shipped units already
carry `After=network-online.target tailscaled.service` plus `Restart=on-failure`
/ `RestartSec=5s`. Both halves are load-bearing: `After=` only orders unit
*start*, and tailscaled being "active" does not guarantee the `100.x` address is
assigned yet — the restart is what wins the residual race. Prove it before you
walk away:

```bash
sudo reboot
# wait ~60s, then from your Mac:
curl http://<100.x.y.z>:7117/.well-known/jig
```

A reboot that silently fails to rebind is the failure mode where the whole team
discovers it at once the next morning.

### 4h. Get `server.key` off the box. Now. Before the first message.

```bash
sudo base64 /var/lib/jig/server.key
```

Paste it into 1Password. It is 32 bytes. **Losing it changes the server DID and
breaks TOFU pinning for every client** — every user sees what is
indistinguishable from a MITM and there is no recovery short of everyone wiping
their pin. Restoring databases without the key restores nothing useful. Do this
before you put a single message through the server, not after.

---

## 5. Real HTTPS with `tailscale cert`

Tailscale issues genuine Let's Encrypt certificates for MagicDNS names, so you
get real HTTPS/WSS with **no certbot, no public DNS record, no port-80 challenge,
and no public exposure**. Clients need no `-k`.

**Prerequisite (admin console, do it first):** tailnet Settings → DNS → enable
**MagicDNS**, then enable **HTTPS Certificates**. Without both, `tailscale cert`
fails.

```bash
# find your full MagicDNS name
tailscale status --json | grep -i dnsname     # e.g. jig-vps.tailfoo-bar.ts.net
HOST=jig-vps.<tailnet>.ts.net

sudo install -d -o jig -g jig -m 0750 /var/lib/jig/tls
sudo tailscale cert \
  --cert-file /var/lib/jig/tls/$HOST.crt \
  --key-file  /var/lib/jig/tls/$HOST.key \
  "$HOST"
# NOT `sudo chown jig:jig /var/lib/jig/tls/*` — your shell expands the glob
# BEFORE sudo runs, and the directory is 0750 jig:jig, so an unprivileged
# shell cannot list it. The glob stays literal and chown reports
# "cannot access '/var/lib/jig/tls/*': No such file or directory" while the
# files are sitting there perfectly. sudo elevates the command, not the globbing.
sudo chown -R jig:jig /var/lib/jig/tls
sudo sh -c 'chmod 600 /var/lib/jig/tls/*.key'
```

Wire it into the server's existing `[tls]` block in `/etc/jig/config.toml` — the
struct is `enabled` / `cert_path` / `key_path`, and `enabled = true` with either
path missing is a loud startup failure, which is what you want:

```toml
[tls]
enabled = true
cert_path = "/var/lib/jig/tls/jig-vps.<tailnet>.ts.net.crt"
key_path  = "/var/lib/jig/tls/jig-vps.<tailnet>.ts.net.key"
```

```bash
sudo systemctl restart jig-server
curl https://jig-vps.<tailnet>.ts.net:7117/.well-known/jig     # no -k
```

Clients use `wss://jig-vps.<tailnet>.ts.net:7117/...` for the same host.

### Renewal — the part that bites in 90 days

**The server reads the cert once at startup. There is no hot reload.** Certs are
~90 days. `tailscale cert` renews when run within 30 days of expiry, so a
periodic re-issue plus a restart is the whole story. Add a timer:

```bash
sudo tee /opt/jig/bin/jig-cert-renew.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
HOST="$(tailscale status --json | sed -n 's/.*"DNSName": *"\([^"]*\)\.".*/\1/p' | head -1)"
[ -n "$HOST" ] || { echo "no MagicDNS name"; exit 1; }
CRT=/var/lib/jig/tls/$HOST.crt
KEY=/var/lib/jig/tls/$HOST.key
BEFORE=$(sha256sum "$CRT" | cut -d' ' -f1)
tailscale cert --cert-file "$CRT" --key-file "$KEY" "$HOST"
chown jig:jig "$CRT" "$KEY"; chmod 600 "$KEY"
AFTER=$(sha256sum "$CRT" | cut -d' ' -f1)
# only bounce the service when the cert actually changed
[ "$BEFORE" = "$AFTER" ] || systemctl restart jig-server
EOF
sudo chmod 755 /opt/jig/bin/jig-cert-renew.sh

sudo tee /etc/systemd/system/jig-cert-renew.service >/dev/null <<'EOF'
[Unit]
Description=Renew tailscale cert for jig-server and restart if it changed
After=tailscaled.service
Wants=tailscaled.service
[Service]
Type=oneshot
ExecStart=/opt/jig/bin/jig-cert-renew.sh
EOF

sudo tee /etc/systemd/system/jig-cert-renew.timer >/dev/null <<'EOF'
[Unit]
Description=Weekly tailscale cert renewal for jig-server
[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=3600
[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now jig-cert-renew.timer
sudo systemctl start jig-cert-renew.service      # prove it works today
journalctl -u jig-cert-renew.service -n 30
```

The `sha256sum` guard means the weekly run is a no-op for the first ~60 days and
only bounces the server when there is a genuinely new cert.

**Note:** `jig-nameserver` has no TLS config at all — it is plain HTTP on :7070.
That is fine here: the tailnet is a WireGuard tunnel, so the transport is already
encrypted. Do not "fix" it by putting a reverse proxy in front.

---

## 6. Cost — approximate, confirm in the console

All figures were quoted for `us-central1` and are left as-is rather than
silently relabelled — **the deploy is `us-west1`, where prices differ slightly.**
Treat these as the right order of magnitude, not the bill. On-demand list price,
**before** E2's automatic
sustained-use discount (up to ~20% for a full month). **These are estimates and
may be out of date. Verify at cloud.google.com/products/calculator.**

| Component | Rate (approx) | Monthly (approx) |
|---|---|---|
| `e2-micro` (2 shared vCPU, 1 GB) | ~$0.0084/hr | ~$6 (or $0 in free tier) |
| `e2-small` (2 shared vCPU, 2 GB) | ~$0.017/hr | **~$12** |
| `e2-medium` (2 shared vCPU, 4 GB) | ~$0.034/hr | ~$25 |
| `e2-standard-4` (4 vCPU, 16 GB) | ~$0.134/hr | ~$98 if left running |
| `c4-standard-4` (4 vCPU, 15 GB) | ~$0.19-0.21/hr | ~$140-155 if left running |
| 50 GB `pd-balanced` | ~$0.10/GB-mo | **~$5** |
| 50 GB `pd-standard` | ~$0.04/GB-mo | ~$2 |
| External IPv4 (in use) | ~$0.005/hr | **~$3.65** — now billed to the NAT gateway, not the VM |
| Cloud NAT gateway | per gateway-hour **plus** per-GB processed | **NOT VERIFIED — check the calculator** |
| Internet egress | first ~200 GB/mo free, then ~$0.085-0.12/GB | **~$0** at this scale |

### Recommended configuration, totalled

| Line | Approx |
|---|---|
| `e2-small` running 24/7 | ~$12.25 |
| 50 GB `pd-balanced` | ~$5.00 |
| External IPv4 (on the NAT gateway) | ~$3.65 |
| Egress (10-person chat) | ~$0.00 |
| Cloud NAT gateway + data processing | **unverified** |
| **Steady state** | **~$21/month + Cloud NAT** |

The VM has no external IP (`--no-address`, org policy), so that ~$3.65 moves to
the NAT gateway's auto-allocated address rather than disappearing — and Cloud NAT
adds its own gateway and data-processing charges on top. That figure is
deliberately left blank rather than guessed; it is the one line item in this
table that changed structurally and was never measured. Price it before assuming
~$21 still holds.
| One-time: `e2-standard-4` for a ~1.5 h build | **~$0.20** |

The build burst is a rounding error. **The external IP is ~17% of your bill and
nothing ever connects to it** — but removing it means adding Cloud NAT for
outbound (Tailscale must reach the internet), and a NAT gateway is roughly
$32/month. Keep the IP.

### Egress and tailnet traffic

Yes, tailnet traffic that leaves the VM is billed as normal GCP egress —
Tailscale is WireGuard over the public internet, not a private interconnect. For
a 10-person text chat this is genuinely nothing: text blocks are hundreds of
bytes, and even at 10,000 messages/day you are in the low tens of MB/month,
against a ~200 GB/month free allowance. Two things *would* move the needle and
neither is in scope: file/media attachments, and federation gossip to an
off-box peer.

Note that `cargo` downloads and `apt` are **ingress**, which is free.

---

## 7. Teardown and cost control

### Pause it while traveling

```bash
gcloud compute instances stop jig-vps --zone=us-west1-a
```

A **stopped** instance bills **no vCPU and no RAM** — you keep paying only for
the boot disk (~$5/mo for 50 GB balanced) and, if you promoted it to static, the
IP. The Tailscale node, `/var/lib/jig`, and `server.key` all persist. Start it
again with:

```bash
gcloud compute instances start jig-vps --zone=us-west1-a
```

Give it ~60 seconds; the units order after `tailscaled` and will retry once the
`100.x` address exists.

### Delete it

```bash
# check what you would destroy first
gcloud compute instances describe jig-vps --zone=us-west1-a \
  --format='value(disks[].deviceName,disks[].autoDelete)'

gcloud compute instances delete jig-vps --zone=us-west1-a   # boot disk goes with it by default

# Cloud NAT + its router bill independently of the VM, and `networks delete`
# refuses while they exist. Remove them before the network, in this order.
gcloud compute routers nats delete jig-nat --router=jig-nat-router --region=us-west1
gcloud compute routers delete jig-nat-router --region=us-west1

gcloud compute firewall-rules delete jig-iap-ssh   # if you re-added it for break-glass
gcloud compute networks delete jig-net
```

> **Stopping the VM does not stop the NAT bill.** If you are pausing the box
> while travelling rather than tearing it down, delete the NAT gateway and
> router too and recreate them on return — they are two commands each way.

**Before you ever run that:** confirm `server.key` is in 1Password and the
databases are in GCS. `--keep-disks=boot` preserves the disk if you want an
escape hatch, at ~$5/month to keep it around.

### Budget alerts (do this once, takes two minutes)

```bash
gcloud billing accounts list                 # note the ACCOUNT_ID
gcloud billing budgets create \
  --billing-account=<BILLING_ACCOUNT_ID> \
  --display-name="jig internal MVP" \
  --budget-amount=50USD \
  --threshold-rule=percent=0.5 \
  --threshold-rule=percent=0.9 \
  --threshold-rule=percent=1.0
```

That mails you at $25 / $45 / $50. It does **not** stop spending — GCP budgets
are alerts, not caps. The realistic thing it protects you from is leaving
`e2-standard-4` running after the build, which is the single most likely
$98 surprise in this runbook. Set a phone reminder for the resize too.

Also worth knowing: `gcloud compute instances list --format='table(name,zone,
machineType.basename(),status)'` is the ten-second sanity check for "did I
actually shrink it".

---

## 8. Off-box backup to GCS

`deploy/jig-backup.sh` already does the local half correctly — `VACUUM INTO`
snapshots (safe on a live WAL database, unlike `cp`), a `MANIFEST.txt` of sha256
sums, `umask 077`, partial-snapshot cleanup, and retention pruning that only
ever touches timestamp-shaped directories. It backs up four things:
`jig.db`, **`jig_v002.db`** (the v0.0.2 block store — where the messages actually
are; the `_v002` suffix is derived from `database_path`, not a typo),
`nameserver.db`, and `server.key`.

Its stated gap is the one this section closes: *"`/var/backups/jig` is on the
same disk as the thing it is backing up."*

### 8a. Bucket (from your Mac)

```bash
gcloud storage buckets create gs://<PROJECT_ID>-jig-backups \
  --location=us-west1 \
  --uniform-bucket-level-access \
  --public-access-prevention \
  --soft-delete-duration=30d

# versioning: an overwrite or a bad script cannot destroy history
gcloud storage buckets update gs://<PROJECT_ID>-jig-backups --versioning

# lifecycle: expire noncurrent versions after 90 days so it stays cheap
cat > /tmp/lifecycle.json <<'EOF'
{"rule":[{"action":{"type":"Delete"},
          "condition":{"daysSinceNoncurrentTime":90}}]}
EOF
gcloud storage buckets update gs://<PROJECT_ID>-jig-backups \
  --lifecycle-file=/tmp/lifecycle.json
```

`--uniform-bucket-level-access` kills per-object ACLs (the classic way a bucket
accidentally goes public) and `--public-access-prevention` makes it impossible to
grant `allUsers` even deliberately. Both matter here: **these snapshots contain
`server.key`.**

### 8b. A write-only service account

The VM should be able to *write* backups and nothing else — it should not be able
to read them back or delete them. That way a compromise of the box cannot
exfiltrate old snapshots or ransomware your backups.

```bash
gcloud iam service-accounts create jig-vps-backup \
  --display-name="jig-vps backup writer"

SA=jig-vps-backup@<PROJECT_ID>.iam.gserviceaccount.com

# objectCreator = create only. NOT objectAdmin (delete), NOT objectViewer (read).
gcloud storage buckets add-iam-policy-binding gs://<PROJECT_ID>-jig-backups \
  --member="serviceAccount:$SA" --role=roles/storage.objectCreator
```

Attach it to the VM. **The instance must be stopped**, so fold this into the
resize you are already doing:

```bash
gcloud compute instances stop jig-vps --zone=us-west1-a
gcloud compute instances set-service-account jig-vps --zone=us-west1-a \
  --service-account="$SA" --scopes=https://www.googleapis.com/auth/devstorage.read_write
gcloud compute instances set-machine-type jig-vps --zone=us-west1-a \
  --machine-type=e2-small
gcloud compute instances start jig-vps --zone=us-west1-a
```

(The `devstorage.read_write` scope is a ceiling, not a grant — IAM still limits
the SA to create-only. Scopes are legacy and there is no create-only scope; IAM
is the real control.)

### 8c. Ship the snapshots (on the box)

`jig-backup.sh` writes `/var/backups/jig/<UTC timestamp>/`. Push each new
snapshot up right after the timer runs:

```bash
sudo tee /opt/jig/bin/jig-backup-gcs.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
BUCKET="gs://<PROJECT_ID>-jig-backups"
SRC="${JIG_BACKUP_DIR:-/var/backups/jig}"
HOST="$(hostname -s)"
# newest snapshot only — the local script already handled retention
LATEST="$(ls -1d "$SRC"/*/ 2>/dev/null | sort | tail -1)"
[ -n "$LATEST" ] || { echo "no snapshot to ship"; exit 1; }
STAMP="$(basename "$LATEST")"
gcloud storage cp -r "$LATEST" "$BUCKET/$HOST/$STAMP/"
echo "shipped $STAMP -> $BUCKET/$HOST/$STAMP/"
EOF
sudo chmod 755 /opt/jig/bin/jig-backup-gcs.sh
```

Chain it to the existing backup unit by dropping in an override rather than
editing the shipped unit file:

```bash
sudo systemctl edit jig-backup.service
# add:
#   [Service]
#   ExecStartPost=/opt/jig/bin/jig-backup-gcs.sh
```

Prove the whole chain today, before you need it:

```bash
sudo -u jig /opt/jig/bin/jig-backup.sh          # take a snapshot
sudo /opt/jig/bin/jig-backup-gcs.sh             # ship it
gcloud storage ls -r gs://<PROJECT_ID>-jig-backups/   # from your Mac
```

`gcloud storage` is the current CLI; `gsutil` still works (`gsutil -m rsync -r
/var/backups/jig gs://.../`) but is on the way out — prefer `gcloud storage`.

### 8d. Two honest caveats

- **`server.key` is inside these snapshots.** GCS encrypts at rest with
  Google-managed keys, and the bucket is private and public-access-prevented —
  but anyone with project-level `storage.objectViewer` can read it. If that
  bothers you, `age`- or `gpg`-encrypt the snapshot before upload. **Regardless:
  the 1Password copy from Section 4h is the backup that actually matters.** GCS
  is for the message history; 1Password is for the identity.
- **A backup you have not restored is a hypothesis.** The restore drill is in
  `deploy/README.md`. The one assertion that matters afterwards is that
  `curl http://<100.x>:7117/.well-known/jig` returns **the same `server_did` as
  before** — if it changed, you restored the databases without the key, and every
  client's TOFU pin is now broken.

---

## Appendix: verified facts and their sources

Everything below was checked against this checkout, not assumed.

| Claim | How it was verified |
|---|---|
| No OpenSSL in the build path; `libssl-dev` unnecessary | `cargo tree -p {jig-server,jig-nameserver,jig-cli} -i openssl-sys` → "did not match any packages"; workspace `reqwest` is `default-features = false, features = ["json", "rustls-tls"]` |
| `ring` and bundled SQLite need a C compiler | `cargo tree -p jig-server -i ring` (via `rustls` 0.22/0.23 + `jsonwebtoken`); `libsqlite3-sys` 0.28 under `rusqlite` with `bundled` |
| **Two wasmtime/cranelift backends compile at `HEAD`** | at `13ccfa4`: `cargo tree -p jig-server -i wasmtime@16.0.0` **and** `@23.0.3` both resolve; `cranelift-codegen` 0.103 *and* 0.110 in `Cargo.lock`. On the current working tree (uncommitted, not mine) both unify on `wasmtime 24.0.12` / `cranelift-codegen 0.111.12` |
| 472 crates at `HEAD`, 420 with the wasmtime dedup | `cargo tree -p jig-server -p jig-nameserver -p jig-cli --prefix none --no-dedupe -e normal,build \| sort -u \| wc -l`, run against both states |
| `target/` is 18 GB | `du -sh repos/target` — all debug; 15 GB in `deps`, 3.9 GB `incremental` |
| Fat LTO + `codegen-units = 1` | `repos/Cargo.toml` `[profile.release]` |
| Toolchain is plain `stable` | no `rust-toolchain.toml` at `repos/`; only `repos/jig-spec/rust-toolchain.toml` (`channel = "stable"`, not a workspace member) |
| CI already builds `x86_64-unknown-linux-gnu` | `.github/workflows/release.yml` matrix row, `runs_on: ubuntu-latest`, tag-triggered only |
| No `aarch64-linux` CI coverage | same file, header comment: "Windows, musl and aarch64-linux were dropped" |
| `[tls]` shape is `enabled`/`cert_path`/`key_path` | `repos/jig-server/src/config.rs` `TlsConfig`, incl. `resolved_paths()` hard-failing when `enabled` without both paths |
| Units order after `tailscaled` | `deploy/jig-server.service`, `deploy/jig-nameserver.service` |
| `sqlite3` is mandatory for backups | `deploy/jig-backup.sh` `die`s if `sqlite3` is absent |

### Still unverified — check these yourself

1. **Every price.** No live pricing access. Confirm in the console.
2. **Quota.** A fresh project may cap regional CPUs below 4.
3. **Build wall-clock on GCP.** The 25-40 min estimate for `e2-standard-4` is
   extrapolated, not measured.
4. **`target/release` size (~4-6 GB).** Estimated from the 18 GB debug tree; the
   50 GB disk recommendation has enough margin that being wrong is cheap.
5. **Tailscale SSH ACL.** Your tailnet policy may not grant it by default —
   check before deleting the GCP SSH rule.
6. **The free-tier external-IP question.** I believe the always-free `e2-micro`
   does not include the ~$3.65/mo IPv4 charge. Confirm before calling it free.
7. **Which commit you actually build.** This worktree had uncommitted wasmtime
   changes in flight while this runbook was written (see the appendix table).
   Build `main`, per the dogfood plan's "rule zero", and re-check the crate
   count with the `cargo tree` line above if the build cost matters to your
   machine-type choice.
