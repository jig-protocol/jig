# Documentation index

Every doc in this repo, with a status. **CURRENT** means it describes the tree as it
is today. **HISTORICAL** means it is preserved for its reasoning or its record and
should not be read as a status page.

## Start here

| I want to… | Read |
| --- | --- |
| Stand up a server on a box I already have | [`deploy/README.md`](../deploy/README.md) |
| Get the box first, on GCP | [`docs/deployment/gcp-vps-runbook.md`](deployment/gcp-vps-runbook.md) |
| Know what actually works today | [What works, what does not](../README.md#what-works-what-does-not) in the root README, and the [threat register](../repos/jig-spec/src/threat-register.md) for security status |
| Know what is left before a public release | [`RELEASE_READINESS.md`](RELEASE_READINESS.md) |
| See where the project is headed, phase by phase | [`ROADMAP.md`](ROADMAP.md) |
| See end-to-end encryption work, on a throwaway server | [`scripts/demo-e2ee.sh`](../scripts/demo-e2ee.sh) |
| Understand why something was built the way it was | [`docs/superpowers/`](superpowers/) |

## Deployment and operations

| Doc | Status | What it is |
| --- | --- | --- |
| [`deploy/README.md`](../deploy/README.md) | CURRENT | Operator runbook: systemd units, the strict `/etc/jig/config.toml`, backups, sealing the server key, and the server-key warning. The unit files carry their own rationale in comments; this doc covers sequence. |
| [`deployment/gcp-vps-runbook.md`](deployment/gcp-vps-runbook.md) | CURRENT | GCP-specific box setup — machine sizing, the build-big-then-shrink recommendation, Tailscale-only reachability. Prices and build times in it are the author's estimates, unverified against the console. |
| [`deployment/internal-dogfood-3day.md`](deployment/internal-dogfood-3day.md) | HISTORICAL | The internal-MVP plan. Its STATUS section is a snapshot of what had shipped by that batch, not maintained; the plan body predates the implementation and is kept for its reasoning. |
| [`deployment/internal-dogfood-24h.md`](deployment/internal-dogfood-24h.md) | HISTORICAL | Superseded by the 3-day plan. Retained for its verified state-of-the-union table, which was proven by running binaries rather than reading code. |
| [`deployment/install-benchmark.md`](deployment/install-benchmark.md) | CURRENT | The 60-second `curl \| bash` install gate: the manual procedure on a $5-class VM, still the only measure on target hardware, and the CI runs (`scripts/install-smoke.sh` in `release.yml` and `install-smoke.yml`) with their first measurements. |
| [`operations/nameserver-abuse-runbook.md`](operations/nameserver-abuse-runbook.md) | HISTORICAL | Nameserver incident runbooks: harassment reports, registration and relay abuse, a compromised nameserver, a rogue or contradicting nameserver. Mostly out of date since #154 removed the legacy routes it calls; a banner lists the steps that still apply; tribunal steps are marked future. |

## Design and implementation records

| Path | Status | What it is |
| --- | --- | --- |
| [`superpowers/specs/`](superpowers/specs/) | HISTORICAL | Dated design documents — the shape of a change and why, written before implementation. The newest, [`2026-10-11-m2-mls-and-channel-dynamics-design.md`](superpowers/specs/2026-10-11-m2-mls-and-channel-dynamics-design.md), is the M2 plan: MLS, channel dynamics, M1 cleanup. |
| [`superpowers/plans/`](superpowers/plans/) | HISTORICAL | Dated implementation plans derived from those specs, task by task. Useful for reconstructing intent; not maintained after a plan ships. |
| [`archive/`](archive/) | HISTORICAL | Root-level docs that went stale. Each carries a header saying what it described and when. |

## Security

| Doc | Status | What it is |
| --- | --- | --- |
| [`../SECURITY.md`](../SECURITY.md) | CURRENT | How to report a vulnerability, response targets, disclosure policy and scope. |
| [`security/audit-scope.md`](security/audit-scope.md) | CURRENT | Proposed scope for the external security audit (D27): seven areas by priority, entry points and threat-register rows for each, how to split the work, and what must be code-complete first. |
| [`security/operator-threat-model.md`](security/operator-threat-model.md) | CURRENT | The model and evidence behind the spec's operator [threat register](../repos/jig-spec/src/threat-register.md). |
| [`security/encryption.md`](security/encryption.md) | CURRENT | Why encryption is shaped as it is: suite field, refusals, MLS, DMs as locked channels, the DID key as MLS signer, a validating delivery service, the client plaintext cache. |
| [`security/nameserver-abuse-economics.md`](security/nameserver-abuse-economics.md) | CURRENT | Why nameserver proof-of-work, rate limits and penalties are shaped as they are: Sybil and spam cost models, decay, griefing, federation, tribunals per ruleset group, and the known weaknesses the design must close. Rationale for the spec's [Identity and Reputation](../repos/jig-spec/src/identity-and-reputation.md) chapter. |
| [`whitepaper/trust-federation-identity.md`](whitepaper/trust-federation-identity.md) | CURRENT | Whitepaper (non-normative): identity, `--anon`, reputation, security levels and ruleset groups, anchor nameservers, federation as a data contract, and the threat families beyond operators. Separates, for each topic, what jig must guarantee, what v0.2 does today, and what is still to design. |

## Crate documentation

Per-crate READMEs live next to the code under [`repos/`](../repos/):
`jig-core`, `jig-server`, `jig-cli`, `jig-config`, `jig-runtime`, `jig-nameserver`,
`bridges/email`. `jig-mls` documents itself in its crate docs (`src/lib.rs`).

One directory under `repos/` is documentation rather than a crate and is not a
workspace member:

| Path | Status | What it is |
| --- | --- | --- |
| [`repos/jig-spec/`](../repos/jig-spec/) | CURRENT | mdBook protocol specification plus JSON schemas and the JEP directory. Self-described as draft scaffolding; no publishing pipeline is wired up. |

## Archive contents

| Doc | Described | Why archived |
| --- | --- | --- |
| [`archive/IMPLEMENTATION_PLAN.md`](archive/IMPLEMENTATION_PLAN.md) | 2025-11-09 | Receipt v0.2 cross-binary alignment; all 50 tasks still marked "Not Started" and never reconciled with what shipped. |
| [`archive/TRIAGE_REPORT.md`](archive/TRIAGE_REPORT.md) | 2026-03-26 | Workspace snapshot; its test count, per-crate table, and file paths no longer match the tree. |
| [`archive/V0.0.1_CHANGES.md`](archive/V0.0.1_CHANGES.md) | 2026-03-26 | Changelog for a hygiene pass; mostly still true, but at least one entry has since been superseded in code. |
