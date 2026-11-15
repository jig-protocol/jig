# Ownership map

Who reviews what, and what a review in each area checks. Today one maintainer, DJ
([@the-jig-is-up](https://github.com/the-jig-is-up)), owns every path; [`CODEOWNERS`](../.github/CODEOWNERS)
requests that review on every pull request, and `main` requires it. The table says where a
second owner would go first as the team grows, and what any reviewer should look for.

| Area | Paths | Owner | A review checks |
| --- | --- | --- | --- |
| Spec and JEPs | `repos/jig-spec/` | DJ | The JEP came before the code; normative text is terse and matches `main`; chapter banners and threat-register status cells stay true |
| Cryptography and identity | `repos/jig-core/`, `repos/jig-mls/` | DJ | Domain strings are unique and versioned; deterministic encodings; no new algorithm or suite outside the registry; test vectors updated |
| Handshake and auth gates | `repos/jig-pipeline/src/handshake.rs`, `repos/jig-server/src/auth/` | DJ | Fail closed; no new path skips a gate; threat-register rows updated |
| Write path | `repos/jig-pipeline/` | DJ | Every surface still goes through `ingest` (the follower stream is the one deliberate exception); effects and records persist together |
| Sandbox and receipts | `repos/jig-runtime/`, `repos/text-block/` | DJ | No new host import without a grant; determinism profile unchanged or versioned |
| Server, client, CLI | `repos/jig-server/`, `repos/jig-client/`, `repos/jig-cli/`, `repos/jig-config/` | DJ | Config denies unknown keys; client pins and evidence still checked |
| Nameserver | `repos/jig-nameserver/` | DJ | Links no Wasm engine; proof-of-work and rate limits unchanged unless the JEP says so |
| Bridges | `repos/bridges/` | DJ | Bridged blocks go through `ingest` |
| Release and installer | `.github/`, `install.sh`, `scripts/`, `deny.toml` | DJ | Signing key pins unchanged; installer fails closed; no new advisory ignore without a reason that names when it goes |
| Docs | `docs/`, root `*.md` | DJ | Every status claim checked against `main`; no infrastructure details in this public repository |

Security reports go to [SECURITY.md](../SECURITY.md), not to an area owner. Triage of ordinary
issues is DJ's ([ROADMAP](ROADMAP.md) D9).
