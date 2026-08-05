# Cross-Binary Protocol Implementation Plan

**Created:** 2025-11-09
**Based on:** `executable-internet-master-plan/20251102_REVIEW.md` and current repo state
**Scope:** Align jig-core, jig-runtime, jig-nameserver, jig-config, jig-server, jig-cli on Receipt v0.2 and cross-binary contracts

---

## Overview

This plan synchronizes the cross-binary protocol after Receipt v0.2 completion in jig-core. Key changes:

- Receipt v0.2 integration across all binaries
- Analytics schema (ClickHouse + DuckDB/Parquet)
- Deterministic execution parity (server ↔ CLI)
- Pricing and capability metering
- Spec document updates

**Sequencing Philosophy:** Core → Runtime → Server → CLI → Docs

---

## Task Matrix

| #                                    | Task                                                     | Component      | Priority | Size       | Dependencies          | Status      |
| ------------------------------------ | -------------------------------------------------------- | -------------- | -------- | ---------- | --------------------- | ----------- |
| **Phase A: Spec & Documentation**    |
| 1                                    | ☐ Update BLOCK_RUNTIME_SPEC.md with Receipt v0.2 details | jig-docs       | P0       | M (1h)     | Receipt v0.2 complete | Not Started |
| 2                                    | ☐ Add outcome-based pricing examples to spec             | jig-docs       | P1       | S (0.5h)   | Task 1                | Not Started |
| 3                                    | ☐ Document canonical affordances (3-5 types)             | jig-docs       | P1       | M (1h)     | Task 1                | Not Started |
| 4                                    | ☐ Create analytics schema reference doc                  | jig-docs       | P1       | M (1h)     | Task 1                | Not Started |
| **Phase B: Analytics Layer**         |
| 5                                    | ☐ Create ClickHouse schema DDL                           | jig-server     | P0       | L (2h)     | Task 4                | Not Started |
| 6                                    | ☐ Create DuckDB/Parquet schema for potato tier           | jig-server     | P0       | M (1h)     | Task 4                | Not Started |
| 7                                    | ☐ Implement profile-driven analytics sink                | jig-server     | P0       | XL (4h)    | Tasks 5,6             | Not Started |
| 8                                    | ☐ Add receipt → analytics table mapping                  | jig-server     | P1       | L (2h)     | Task 7                | Not Started |
| 9                                    | ☐ Write analytics migration tests                        | jig-server     | P1       | M (1h)     | Task 8                | Not Started |
| **Phase C: Server Integration**      |
| 10                                   | ☐ Update receipt emitter to populate v0.2 fields         | jig-server     | P0       | XL (4h)    | Receipt v0.2          | Not Started |
| 11                                   | ☐ Implement per-capability fuel attribution              | jig-server     | P0       | XL (4h)    | Task 10               | Not Started |
| 12                                   | ☐ Add timing collection (queue/init/exec)                | jig-server     | P0       | L (2h)     | Task 10               | Not Started |
| 13                                   | ☐ Snapshot limits from config to receipts                | jig-server     | P1       | M (1h)     | Task 10               | Not Started |
| 14                                   | ☐ Implement outcome status detection                     | jig-server     | P0       | L (2h)     | Task 10               | Not Started |
| 15                                   | ☐ Add renders_match validation                           | jig-server     | P1       | M (1h)     | Task 10               | Not Started |
| 16                                   | ☐ Write server receipt integration tests                 | jig-server     | P0       | L (2h)     | Tasks 10-15           | Not Started |
| **Phase D: Pricing & Metering**      |
| 17                                   | ☐ Define fuel bands in jig-config                        | jig-config     | P1       | M (1h)     | None                  | Not Started |
| 18                                   | ☐ Implement per-capability pricing engine                | jig-server     | P1       | XL (4h)    | Tasks 11,17           | Not Started |
| 19                                   | ☐ Add outcome-based pricing adjustments                  | jig-server     | P1       | L (2h)     | Tasks 14,18           | Not Started |
| 20                                   | ☐ Integrate useful work discounts                        | jig-server     | P2       | L (2h)     | Tasks 18,19           | Not Started |
| 21                                   | ☐ Create pricing calculation tests                       | jig-server     | P1       | M (1h)     | Tasks 18-20           | Not Started |
| **Phase E: CLI Parity**              |
| 22                                   | ☐ Implement `jig block run` command                      | jig-cli        | P0       | L (2h)     | jig-runtime           | Not Started |
| 23                                   | ☐ Add `--receipt <path>` flag for local execution        | jig-cli        | P0       | M (1h)     | Task 22               | Not Started |
| 24                                   | ☐ Implement receipt parity verification                  | jig-cli        | P0       | L (2h)     | Tasks 22,23           | Not Started |
| 25                                   | ☐ Add deterministic replay tests (CLI vs server)         | jig-cli        | P0       | XL (4h)    | Task 24               | Not Started |
| 26                                   | ☐ Document CLI receipt workflow                          | jig-docs       | P1       | S (0.5h)   | Tasks 22-24           | Not Started |
| **Phase F: Runtime Symmetry**        |
| 27                                   | ☐ Verify jig-runtime used by server                      | jig-server     | P0       | XS (0.25h) | jig-runtime           | Not Started |
| 28                                   | ☐ Verify jig-runtime used by CLI                         | jig-cli        | P0       | XS (0.25h) | jig-runtime           | Not Started |
| 29                                   | ☐ Ensure symmetric capability handling                   | jig-runtime    | P0       | M (1h)     | Tasks 27,28           | Not Started |
| 30                                   | ☐ Verify identical fuel metering                         | jig-runtime    | P0       | M (1h)     | Tasks 27,28           | Not Started |
| 31                                   | ☐ Add cross-binary symmetry tests                        | jig-runtime    | P1       | L (2h)     | Tasks 29,30           | Not Started |
| **Phase G: Configuration Alignment** |
| 32                                   | ☐ Verify profile inheritance in jig-config               | jig-config     | P1       | S (0.5h)   | None                  | Not Started |
| 33                                   | ☐ Add execution constraints validation                   | jig-config     | P1       | M (1h)     | Task 32               | Not Started |
| 34                                   | ☐ Ensure analytics backend profile-driven                | jig-config     | P0       | M (1h)     | Tasks 5,6             | Not Started |
| 35                                   | ☐ Add receipt requirements to profiles                   | jig-config     | P1       | S (0.5h)   | Task 1                | Not Started |
| 36                                   | ☐ Create config validation tests                         | jig-config     | P1       | M (1h)     | Tasks 32-35           | Not Started |
| **Phase H: Nameserver Integration**  |
| 37                                   | ☐ Add useful work receipt verification                   | jig-nameserver | P1       | L (2h)     | Receipt v0.2          | Not Started |
| 38                                   | ☐ Implement attestation validation                       | jig-nameserver | P1       | L (2h)     | Task 37               | Not Started |
| 39                                   | ☐ Create transparency log receipt entries                | jig-nameserver | P1       | M (1h)     | Task 37               | Not Started |
| 40                                   | ☐ Add receipt-based reputation scoring                   | jig-nameserver | P2       | XL (4h)    | Tasks 37,38           | Not Started |
| 41                                   | ☐ Write nameserver receipt integration tests             | jig-nameserver | P1       | M (1h)     | Tasks 37-39           | Not Started |
| **Phase I: Federation & Discovery**  |
| 42                                   | ☐ Ensure receipt v0.2 in federation protocol             | jig-server     | P1       | M (1h)     | Task 10               | Not Started |
| 43                                   | ☐ Add receipt signature verification                     | jig-server     | P0       | L (2h)     | Task 42               | Not Started |
| 44                                   | ☐ Implement receipt relay/attestation                    | jig-server     | P2       | XL (4h)    | Tasks 42,43           | Not Started |
| 45                                   | ☐ Add federation receipt tests                           | jig-server     | P1       | L (2h)     | Tasks 42-44           | Not Started |
| **Phase J: Testing & Validation**    |
| 46                                   | ☐ Create end-to-end receipt flow tests                   | Integration    | P0       | XL (4h)    | Tasks 10,22           | Not Started |
| 47                                   | ☐ Add determinism validation tests                       | Integration    | P0       | L (2h)     | Task 46               | Not Started |
| 48                                   | ☐ Create pricing calculation regression tests            | Integration    | P1       | L (2h)     | Tasks 18-21           | Not Started |
| 49                                   | ☐ Add cross-binary parity tests                          | Integration    | P0       | XL (4h)    | Tasks 27-30           | Not Started |
| 50                                   | ☐ Write golden receipt fixtures                          | Integration    | P1       | M (1h)     | Task 46               | Not Started |

---

## Dependencies Graph

```
Spec Updates (1-4)
    ↓
Analytics Layer (5-9) ←─────┐
    ↓                       │
Server Integration (10-16)  │
    ↓                       │
Pricing Engine (17-21) ─────┘
    ↓
CLI Parity (22-26)
    ↓
Runtime Symmetry (27-31)
    ↓
Config Alignment (32-36)
    ↓
Nameserver Integration (37-41)
    ↓
Federation (42-45)
    ↓
Testing & Validation (46-50)
```

---

## Size Legend

- **XS** (<0.25 hr): Quick verification tasks
- **S** (<0.5 hr): Simple implementation or config changes
- **M** (<1 hr): Moderate complexity, single-file changes
- **L** (<2 hr): Multi-file changes, integration work
- **XL** (<4 hr): Complex features, significant testing required

---

## Priority Legend

- **P0**: Blocking for other work, must complete before next phase
- **P1**: Important for feature completeness, complete within phase
- **P2**: Nice-to-have, can defer if timeline pressure

---

## Critical Path (P0 Tasks Only)

1. **Phase A:** Task 1 (Spec update) - 1h
2. **Phase B:** Tasks 5-7 (Analytics schema) - 7h
3. **Phase C:** Tasks 10-12, 14, 16 (Server integration) - 14h
4. **Phase E:** Tasks 22-25 (CLI parity) - 11h
5. **Phase F:** Tasks 27-28, 30 (Runtime symmetry) - 1.5h
6. **Phase G:** Task 34 (Config analytics) - 1h
7. **Phase I:** Task 43 (Receipt signatures) - 2h
8. **Phase J:** Tasks 46-47, 49 (Integration tests) - 10h

**Critical Path Total:** ~47.5 hours

---

## Phase Completion Criteria

### Phase A: Spec & Documentation

- [ ] BLOCK_RUNTIME_SPEC.md includes Receipt v0.2 JSON schema
- [ ] Canonical affordances documented (email.delivered, net.http_2xx, etc.)
- [ ] Analytics schema tables documented with field descriptions
- [ ] All docs pass markdown linting

### Phase B: Analytics Layer

- [ ] ClickHouse DDL creates receipts + receipt_capability_counters tables
- [ ] DuckDB schema matches ClickHouse structure
- [ ] Profile config switches between ClickHouse/DuckDB/Parquet
- [ ] Receipt → table mapping preserves all v0.2 fields
- [ ] Schema migrations tested (empty → populated → queried)

### Phase C: Server Integration

- [ ] Server emits all required v0.2 receipt fields
- [ ] Per-capability fuel counters accurate (sum equals total)
- [ ] Timing breakdown captures queue/init/exec correctly
- [ ] Limits snapshot matches config at execution time
- [ ] Outcome status reflects execution result
- [ ] renders_match validation works
- [ ] 10+ receipt integration tests passing

### Phase D: Pricing & Metering

- [ ] Fuel bands defined in jig-config for CPU/bandwidth/crypto/storage
- [ ] Pricing engine charges per capability correctly
- [ ] Outcome-based adjustments apply (ok=100%, soft_fail=0%, hard_fail=0%)
- [ ] Useful work discounts integrate with reputation tiers
- [ ] Pricing tests cover edge cases (zero fuel, missing caps, etc.)

### Phase E: CLI Parity

- [ ] `jig block run <block_id>` executes locally
- [ ] `--receipt out.json` writes full v0.2 receipt
- [ ] Receipt parity verification detects mismatches
- [ ] Deterministic replay tests pass (10+ blocks)
- [ ] CLI documentation complete

### Phase F: Runtime Symmetry

- [ ] Server and CLI both use jig-runtime (no duplicate code)
- [ ] Capability handling identical across binaries
- [ ] Fuel metering produces byte-identical results
- [ ] Cross-binary symmetry tests pass

### Phase G: Configuration Alignment

- [ ] Profile inheritance validated (potato < standard < hyperscale)
- [ ] Execution constraints propagate to receipts correctly
- [ ] Analytics backend selected by profile
- [ ] Receipt requirements enforced per profile
- [ ] Config validation catches misconfigurations

### Phase H: Nameserver Integration

- [ ] Nameserver validates useful work receipts
- [ ] Attestations verified against transparency log
- [ ] Receipt entries added to transparency log
- [ ] Integration tests cover receipt flows

### Phase I: Federation & Discovery

- [ ] Federated servers exchange v0.2 receipts
- [ ] Receipt signatures verified on ingestion
- [ ] Federation tests include receipt relay

### Phase J: Testing & Validation

- [ ] End-to-end flow: block creation → execution → receipt → analytics
- [ ] Determinism tests: same block produces same receipt 100% of time
- [ ] Pricing regression tests prevent billing drift
- [ ] Cross-binary parity tests prevent symmetry violations
- [ ] Golden fixtures cover common receipt scenarios

---

## Risk Assessment

| Risk                                | Impact | Probability | Mitigation                              |
| ----------------------------------- | ------ | ----------- | --------------------------------------- |
| Receipt v0.2 breaking changes       | High   | Low         | Already complete, backwards compatible  |
| Server/CLI receipt mismatch         | High   | Medium      | Extensive parity testing (Task 24-25)   |
| Analytics schema migration issues   | Medium | Medium      | Test with empty→populated→query flow    |
| Pricing calculation bugs            | High   | Medium      | Property tests + golden fixtures        |
| Federation protocol incompatibility | Medium | Low         | Version negotiation already in place    |
| ClickHouse deployment complexity    | Medium | High        | Keep DuckDB/Parquet as default (potato) |

---

## Open Questions

1. **Canonical Affordances:** Should we define a registry, or allow free-form strings with conventions?

   - **Recommendation:** Start with 3-5 canonical affordances in spec, allow custom with namespace (e.g., `custom:myapp:action`)

2. **Pricing Schedule Versioning:** How do we version fuel band changes?

   - **Recommendation:** Include `schedule_version` in receipt metadata, track changes in analytics

3. **Receipt Retention:** Should receipts be archived after N days to reduce storage costs?

   - **Recommendation:** Use jig-config retention policies (30d potato, 90d standard, 365d hyperscale)

4. **Cross-Domain Pricing:** How do federated servers handle different pricing models?

   - **Recommendation:** Pricing stays local; receipts include fuel but not currency-denominated costs

5. **CLI Receipt Storage:** Where should CLI store local receipts?
   - **Recommendation:** `~/.jig/receipts/<block_id>.json` with configurable path

---

## Success Metrics

- **Deterministic Render Rate:** 100% of identical blocks produce identical receipts
- **Receipt Completeness:** 100% of server executions emit all v0.2 fields
- **CLI Parity:** 100% of CLI executions match server receipts (fuel, hash, outcome)
- **Analytics Coverage:** 100% of receipts ingested to analytics layer
- **Pricing Accuracy:** Zero pricing drift over 10K test executions
- **Test Coverage:** >90% line coverage for receipt-related code

---

## Timeline Estimate

Based on task sizing:

- **Phase A (Spec):** 3.5 hours
- **Phase B (Analytics):** 9 hours
- **Phase C (Server):** 17 hours
- **Phase D (Pricing):** 12 hours
- **Phase E (CLI):** 12.5 hours
- **Phase F (Runtime):** 5.25 hours
- **Phase G (Config):** 4 hours
- **Phase H (Nameserver):** 8 hours
- **Phase I (Federation):** 8 hours
- **Phase J (Testing):** 12 hours

**Total Estimated Effort:** 91.25 hours (~12 days at 8hr/day)

**Critical Path:** 47.5 hours (~6 days)

With parallelization (e.g., docs + analytics in parallel), realistic timeline is **8-10 days**.

---

## Next Steps

1. **Review this plan** with team for alignment on priorities and sequencing
2. **Clarify open questions** (affordances, pricing schedule, etc.)
3. **Begin Phase A** (spec updates) immediately - no blockers
4. **Spin up analytics test environment** (ClickHouse + DuckDB) for Phase B
5. **Create tracking issue** with checkboxes for each task
6. **Schedule daily standups** to track progress and unblock dependencies

---

## Notes

- **Potato-Friendly Principle:** Default to SQLite + DuckDB, make ClickHouse opt-in
- **Backwards Compatibility:** All changes additive, v0.1 receipts still valid
- **Zero Breaking Changes:** Existing code continues to work without modification
- **Test-First:** Write tests before implementation for critical path items
- **Documentation Last:** Update docs after implementation to reflect actual behavior
