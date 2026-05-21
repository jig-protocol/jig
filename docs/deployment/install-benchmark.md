# v0.0.2 Install Benchmark (H8)

Acceptance gate: `curl -fsSL https://jig.onl/install.sh | bash` completes in
under 60 seconds on a fresh Ubuntu 22.04 VM ($5/mo droplet class), landing
the user in an interactive `jig chat #hello` session.

This is a manual benchmark — it requires a fresh VM, real DNS, and the
release tarballs published to `releases.jig.onl`. Until those operational
pieces land, the benchmark is run by hand on an arbitrary cloud VM.

## Procedure

1. **Provision a fresh VM**
   - Provider: any (DigitalOcean, Linode, Hetzner, Vultr)
   - OS: Ubuntu 22.04 LTS
   - Size: 1 vCPU, 1 GB RAM (the "$5 potato" class)
   - Region: `nyc3` or `sfo3` for North-America baseline

2. **Connect via SSH** (don't pre-install anything)

   ```
   ssh root@<vm-ip>
   ```

3. **Run the install** (record wall-clock time)

   ```bash
   time curl -fsSL https://jig.onl/install.sh | bash
   ```

   Acceptance: total wall time (the `real` row of `time`) is **under 60s**.

4. **Verify the post-install state**

   The script should leave the VM in a state where the user can immediately
   run `jig chat #hello` and send/receive blocks against the local server.

   ```bash
   ~/.jig/bin/jig chat '#hello'
   ```

   Type a message; the TUI should echo it back via the local server.

5. **Repeat on a second VM in a different region** to bound network
   variance. Both runs must pass to count as a green benchmark.

## What "60s" actually measures

The 60s budget covers, in this order:

| Phase                                       | Approx. cost | Notes |
|---------------------------------------------|--------------|-------|
| `curl` install.sh                           | <1s          |       |
| Detect platform + download release tarball  | 5-15s        | Bandwidth-bound. |
| Extract + chmod + place binaries            | <2s          | Tarball is <20 MB. |
| Generate ed25519 keypair                    | <1s          |       |
| Write default config (TOFU mode)            | <1s          |       |
| Launch background server                    | 1-2s         | Wait for /.well-known/jig 200 OK. |
| Hand off to `jig chat #hello`               | <1s          |       |
| (User now sees the TUI)                     |              |       |

If any single phase blows past these budgets, the corresponding install.sh
step needs investigation. Common culprits historically:

- **DNS slow-resolve for releases.jig.onl** — keep the host on a fast CDN.
- **`cargo build` triggered by mistake** — install.sh detects this and
  switches modes; ensure the standalone path is taken on fresh VMs.
- **Interactive prompts hanging** — set `JIG_NONINTERACTIVE=1` for the
  benchmark and verify the script doesn't ask for confirmation.

## Failure modes that block v0.0.2 ship

- Install fails on Ubuntu 22.04 (default OS for $5 VMs).
- Wall-clock exceeds 60s on a fast VM in normal network conditions.
- Post-install `jig chat` doesn't open or can't send blocks locally.

## Why this isn't automated

A reasonable automated test would spin up a fresh container, run the
install, and benchmark. v0.0.2 doesn't ship CI for that for three reasons:

1. **Release tarballs need to exist.** They're produced by the Phase G2
   GitHub Actions workflow; until they're consistently published and DNS
   points at them, an automated install would be testing against a moving
   target.
2. **The "potato VM" is not Docker.** Docker runtimes are faster than a
   real $5 VM in most ways (kernel, network, disk). The benchmark is
   inherently about real-world VPS performance — automating that requires
   spinning up real cloud instances, which is a separate operational
   concern.
3. **One-off acceptance, not regression.** This is a release-gating
   benchmark, not a per-commit assertion. Adding it to CI before the
   release pipeline exists is premature.

When v0.1.0 ships the per-platform release pipeline matures, this will
move into an opt-in CI job that boots a fresh VM and records the install
wall-clock — gating tagged releases, not main-branch commits.

## Related tests

The other H-series tests (H1-H7) run via `cargo nextest run -p integration-tests`
and cover the protocol correctness gates. H8 is the deployment-experience
gate; the protocol can be 100% correct and still fail the user experience
goal if the install is slow.
