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

## Automated (2026-10-05)

[`scripts/install-smoke.sh`](../../scripts/install-smoke.sh) runs install.sh in a throwaway
`$HOME`, times `curl … | bash` to "hello, world" accepted in `#hello`, reads it back over
`jig tail`, and fails above 60s. It runs in
[`release.yml`](../../.github/workflows/release.yml) before publishing (Linux x86_64, Apple
Silicon, aarch64 under qemu), against the published release after, and on PRs touching the
installer ([`install-smoke.yml`](../../.github/workflows/install-smoke.yml)).

First measurement (throwaway prerelease `v0.0.0-relpipe.1`, GitHub-hosted runners, assets
downloaded from GitHub Releases): **3.5s** Linux x86_64 (`ubuntu-24.04`), **3.2s** macOS
arm64 (`macos-15`). From a local mirror: 1.0s / 0.9s, and 7.7s for aarch64 under qemu.

A hosted runner is not a $5 VM. The manual procedure above still applies for that number.

## Related tests

The other H-series tests (H1-H7) run via `cargo nextest run -p integration-tests`
and cover the protocol correctness gates. H8 is the deployment-experience
gate; the protocol can be 100% correct and still fail the user experience
goal if the install is slow.
