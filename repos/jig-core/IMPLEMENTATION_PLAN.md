# jig-core Execution Plan (Executable Internet Alignment)

**Created:** 2025-11-03  
**Status:** Draft – drives remaining P0 gaps for pricing & determinism  
**Owners:** Core protocol team (runtime + pricing verification pod)

## Action Plan

| Step | Focus Area                           | Key Deliverables                                                                                                                                                 | Acceptance / Exit Criteria                                                                                                                      | Downstream Touchpoints                                 | KPIs & Guardrails                   | Status                                                                              |
| ---- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | ----------------------------------- | ----------------------------------------------------------------------------------- |
| 1    | Canonical Serialization & Signatures | Shared JCS-style serializer (`to_canonical_bytes`) for manifests & receipts, signing payload helper, explicit `receipt_schema_version` and hash algorithm fields | Canonical bytes round-trip matches golden fixtures; server/CLI sign identical payload without field renames; backwards compatibility maintained | `jig-runtime`, `jig-server`, `jig-cli`                 | SOC, DRY, curl-to-hello-world < 60s | Complete (2025-11-03, awaiting downstream rollout)                                  |
| 2    | Determinism Verification API         | Public `verify_determinism` with import allowlist, float policy flags, RNG/clock/socket denial, memory/timeout checks wired into `BlockBundle::validate_code`    | Nondeterministic modules rejected with actionable reason; deterministic fixtures accepted; spec docs updated                                    | `jig-runtime`, `architecture/EXECUTION_ENVIRONMENT.md` | TDD, SOC, dead-simple defaults      | Complete (2025-11-11: strict+relaxed toggle, default helper, lint facade)           |
| 3    | Capability Scope Semantics           | `CapabilityScopePattern` parser, canonical scope formatter, `requested ⊆ granted` validator, receipt scope normalization                                         | Invalid scopes rejected early; receipts emit canonical scope keys; compat tests cover wildcards                                                 | `jig-runtime`, `jig-server`, `jig-cli`                 | LOB, DRY                            | Complete (2025-11-03; runtime adoption next)                                        |
| 4    | Outcome & Metering Model             | `ReasonCode` enum, affordance gating, host-only counter builders with status bins and byte attribution                                                           | Receipts fail validation on misuse; matrix fixtures cover ok/soft_fail/hard_fail/capability_denied/timeouts                                     | `jig-runtime`, `architecture/BLOCK_RUNTIME_SPEC.md`    | TDD, SOC                            | Complete (2025-11-11: lint/allowlist wiring, CLI/server-ready helper surface)       |
| 5    | Timing Semantics Enforcement         | Validation ensuring `total == init + exec`, monotonic clock guidance, optional clock-source metadata hook                                                        | Tests enforce timing math; docs clarify monotonic requirement; runtime consumers ack change                                                     | `jig-runtime`, `BLOCK_RUNTIME_SPEC.md`                 | LOB, dead-simple defaults           | Complete (2025-11-05: tests added; README/spec/docs aligned; `RECEIPT_V0_2.md` updated; jig-server runtime maps timings with total=exec and passes suite) |
| 6    | Golden Receipts & Regression Tests   | Fixture generator for canonical receipts (matrix of outcomes), property tests for serializers & scopes, determinism regression suite                             | `cargo nextest -p jig-core` passes; byte equality enforced in CI; fixtures documented                                                           | `jig-server`, `jig-cli` CI pipelines                   | TDD, SOC                            | Complete (2025-11-03; golden ok/soft_fail/hard_fail receipts added)                 |
| 7    | Documentation & Change Broadcast     | Update `RECEIPT_V0_2.md` (jig-docs), this plan, spec cross-links, CHANGELOG entry                                                                                | Docs reflect new enums/helpers; downstream PRs reference plan; CHANGELOG updated                                                                | `executable-internet-master-plan`, `jig-docs/core`     | DRY, curl-to-hello-world < 60s      | Complete (2025-11-05: docs/spec/README updated; CHANGELOG added)                     |

## KPI & Agent LOE Tracking

| KPI / Principle              | Current Focus                                                                               | Planned Evidence                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| TDD (tests-first)            | Golden receipt fixtures, determinism regression tests land alongside code                   | Added receipt canonicalisation + signing payload tests (2025-11-03); strict determinism + scope + outcome gating tests guard regressions |
| SOC (Separation of Concerns) | Keep canonicalization/signature logic in `jig-core`, execution enforcement in `jig-runtime` | API boundaries reviewed with runtime team; no cross-crate leaks                                                                          |
| LOB (Locality of Behavior)   | Scope parsing & validation colocated with manifest logic for debuggability                  | Inline unit tests demonstrate normalization without external deps                                                                        |
| DRY                          | Single canonical serializer + scope formatter reused across crates                          | Provide shared helper; update docs discouraging ad-hoc serializers                                                                       |
| Curl-to-hello-world < 60s    | Maintain backwards-compatible receipt payloads & defaults                                   | Avoid field renames; include migration notes for CLI/server consumers                                                                    |
| Dead-simple defaults         | Determinism enforcement enabled by default with explicit escape hatches                     | Config flag required to relax policies; docs warn about trade-offs                                                                       |

---

#### ReasonCode Catalog (2025-11-03)

The canonical failure codes emitted by `jig-core::ReasonCode` are:

```
NET_TIMEOUT
UPSTREAM_5XX
CAPABILITY_DENIED
MANIFEST_INVALID
NONDETERMINISM_DETECTED
RENDER_MISMATCH
RUNTIME_TIMEOUT
RUNTIME_TRAP
FUEL_EXHAUSTED
MEMORY_LIMIT_EXCEEDED
TABLE_LIMIT_EXCEEDED
HOST_PANIC
UNKNOWN
```

Downstream runtimes/CLIs should map host errors to these identifiers and keep their local docs/config (e.g., `jig-config`) in sync until spec updates land.

Track progress directly in this file; update status cells and evidence as tasks complete. Changes affecting external crates require coordination notes before merge.

## Deferred / Follow-ups (non-docs)

- [x] Determinism API: add unit test that `BlockBundle::validate_code_with_allowlist` permits `jig_host::http_fetch` when explicitly allowed and rejects it otherwise (policy hook coverage).
- [x] Capability scope parser: add negative tests for invalid scopes (empty segment, wildcard not final, partial-segment wildcard) to complement `parse_scope` success cases.
- [x] Outcome gating: add unit test asserting `OutcomeStatus::{SoftFail,HardFail}` with non-empty `affordances` fails validation.
- [x] Timings: add property test ensuring `Timings::new(queue, init, exec)` always sets `total == init + exec` across randomized inputs.
- [x] Counters bins: add unit test asserting `CountersBuilder::add_status(.., status)` normalizes `status` to uppercase in `status_by_capability`.
- [x] Receipt validation: add unit test that empty `hash_algorithms` fields are rejected (explicit negative), complementing default-value test.
- [x] Canonical bytes: add unit test proving `to_canonical_bytes` is stable regardless of insertion order for `fuel_by_capability` and `status_by_capability` maps (metadata order is already covered).

Downstream (tracked in server/runtime plans, not blocking jig-core):
- [ ] jig-server: ensure runtime populates `init` vs `exec` and `queue_wait` from a monotonic clock; consider stamping `metadata["timing.clock_source"] = "monotonic"` via builder helper.
- [ ] jig-server: exercise `validate_code_with_allowlist` with a capability-derived allowlist (e.g., allow `http_fetch` only when `net:http:fetch` is declared).
