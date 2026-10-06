# Documentation index

Every doc in this repo, with a status. **CURRENT** means it describes the tree as it
is today. **HISTORICAL** means it is preserved for its reasoning or its record and
should not be read as a status page.

## Start here

| I want to… | Read |
| --- | --- |
| Stand up a server on a box I already have | [`deploy/README.md`](../deploy/README.md) |
| Get the box first, on GCP | [`docs/deployment/gcp-vps-runbook.md`](deployment/gcp-vps-runbook.md) |
| Know what actually works today | the STATUS section of [`internal-dogfood-3day.md`](deployment/internal-dogfood-3day.md) |
| Know what is left before a public release | `docs/RELEASE_READINESS.md` (arriving in this batch) |
| Understand why something was built the way it was | [`docs/superpowers/`](superpowers/) |

## Deployment and operations

| Doc | Status | What it is |
| --- | --- | --- |
| [`deploy/README.md`](../deploy/README.md) | CURRENT | Operator runbook: systemd units, hybrid `/etc/jig/config.toml`, backups, and the `server.key` warning. The unit files carry their own rationale in comments; this doc covers sequence. |
| [`deployment/gcp-vps-runbook.md`](deployment/gcp-vps-runbook.md) | CURRENT | GCP-specific box setup — machine sizing, the build-big-then-shrink recommendation, Tailscale-only reachability. Prices and build times in it are the author's estimates, unverified against the console. |
| [`deployment/internal-dogfood-3day.md`](deployment/internal-dogfood-3day.md) | CURRENT | The internal-MVP plan. Opens with a STATUS section listing what shipped and where to check it; the plan body below that predates the implementation and is kept for its reasoning. |
| [`deployment/internal-dogfood-24h.md`](deployment/internal-dogfood-24h.md) | HISTORICAL | Superseded by the 3-day plan. Retained for its verified state-of-the-union table, which was proven by running binaries rather than reading code. |
| [`deployment/install-benchmark.md`](deployment/install-benchmark.md) | CURRENT | Manual procedure for the 60-second `curl \| bash` install acceptance gate. Not yet run: it needs `jig.onl` serving `install.sh` and release tarballs at `releases.jig.onl`, neither of which exists. |

## Design and implementation records

| Path | Status | What it is |
| --- | --- | --- |
| [`superpowers/specs/`](superpowers/specs/) | HISTORICAL | Dated design documents — the shape of a change and why, written before implementation. |
| [`superpowers/plans/`](superpowers/plans/) | HISTORICAL | Dated implementation plans derived from those specs, task by task. Useful for reconstructing intent; not maintained after a plan ships. |
| [`archive/`](archive/) | HISTORICAL | Root-level docs that went stale. Each carries a header saying what it described and when. |

## Security

| Doc | Status | What it is |
| --- | --- | --- |
| [`../SECURITY.md`](../SECURITY.md) | CURRENT | How to report a vulnerability, response targets, disclosure policy and scope. |
| [`security/operator-threat-model.md`](security/operator-threat-model.md) | CURRENT | The model and evidence behind the spec's operator [threat register](../repos/jig-spec/src/threat-register.md). |
| [`security/encryption.md`](security/encryption.md) | CURRENT | Why the v0.1 encryption groundwork is shaped as it is: suite field, refusals, MLS, DMs as locked channels. |

## Crate documentation

Per-crate READMEs live next to the code under [`repos/`](../repos/):
`jig-core`, `jig-server`, `jig-cli`, `jig-config`, `jig-runtime`, `jig-nameserver`,
`jig-gui`, `bridges/email`.

Two directories under `repos/` are documentation rather than crates and are not
workspace members:

| Path | Status | What it is |
| --- | --- | --- |
| [`repos/jig-spec/`](../repos/jig-spec/) | CURRENT | mdBook protocol specification plus JSON schemas and the JEP directory. Self-described as draft scaffolding; no publishing pipeline is wired up. |
| [`repos/jig-docs/`](../repos/jig-docs/) | CURRENT | Working-notes directory, explicitly a placeholder. Excluded from crate tarballs. |

## Archive contents

| Doc | Described | Why archived |
| --- | --- | --- |
| [`archive/IMPLEMENTATION_PLAN.md`](archive/IMPLEMENTATION_PLAN.md) | 2025-11-09 | Receipt v0.2 cross-binary alignment; all 50 tasks still marked "Not Started" and never reconciled with what shipped. |
| [`archive/TRIAGE_REPORT.md`](archive/TRIAGE_REPORT.md) | 2026-03-26 | Workspace snapshot; its test count, per-crate table, and file paths no longer match the tree. |
| [`archive/V0.0.1_CHANGES.md`](archive/V0.0.1_CHANGES.md) | 2026-03-26 | Changelog for a hygiene pass; mostly still true, but at least one entry has since been superseded in code. |
