# M4: Test Hardening + Deprecations

**Status:** 🔄 IN PROGRESS  
**Started:** 2025-11-03  
**Exit Criteria:** Vestigial repos archived; docs updated; fuzz/soak/security tests passing thresholds.

---

## Context

M1-M3 complete:
- ✅ M1: Core engine + Runtime API stable (59 tests passing)
- ✅ M2: Fuel metering + Receipt v0.2 with pricing
- ✅ M3: Consumer integration (jig-server complete, jig-cli documented, jig-gui N/A)

**M4 Focus:** Clean up vestigial code, harden tests, prepare for production use.

---

## P0: Critical Deprecations

### Vestigial Repository Archival

| Task | Status | Owner | Notes |
|------|--------|-------|-------|
| Archive jig-docker repo with README pointer | ☐ | Runtime team | Add deprecation notice: "WASM-only core runtime" |
| Archive jig-podman repo with README pointer | ☐ | Runtime team | Same message as jig-docker |
| Archive jig-runtime-select repo with migration notes | ☐ | Runtime team | Point to jig-runtime direct usage |
| Remove jig-runtime-select from jig-cli Cargo.toml | ☐ | CLI team | Feature-gated, should be minimal change |
| Remove jig-runtime-select from workspace Cargo.toml | ☐ | Runtime team | After all consumers cleaned up |

**Deliverable:** 3 repos archived, 2 dependency removals committed.

### Documentation Updates

| Task | Status | Owner | Notes |
|------|--------|-------|-------|
| Update top-level README to state WASM-only runtime | ☐ | Runtime team | Clear migration path from old repos |
| Search-and-replace docker/podman/runtime-select refs | ☐ | Runtime team | Across all docs and examples |
| Add deprecation notices to CHANGELOG | ☐ | Runtime team | Link to migration guides |

**Deliverable:** Documentation clearly reflects current architecture (WASM-only).

---

## P1: Test Hardening

### Determinism & Parity

| Task | Status | Owner | Priority | Notes |
|------|--------|-------|----------|-------|
| Determinism tests: same inputs → same receipts | ☐ | Runtime team | P0 | Multiple runs, same machine + cross-machine |
| Parity tests: server/cli produce identical receipts | ☐ | Integration team | P0 | Allow timing tolerance |
| Capability security tests (deny-by-default) | ☐ | Security team | P0 | Verify allowlist enforcement |
| Fuel exhaustion scenarios | ☐ | Runtime team | P0 | Soft fail vs hard fail mapping |

**Success Criteria:**
- Same WASM + context → identical receipt (except timestamps)
- jig-server and jig-cli produce receipts that validate as equivalent
- Capability violations properly denied
- Fuel exhaustion returns LimitsExceeded outcome

### Golden Receipt Suite

| Task | Status | Owner | Priority | Notes |
|------|--------|-------|----------|-------|
| Create golden receipt fixtures | ☐ | Runtime team | P1 | 5-10 representative scenarios |
| Receipt snapshot tests | ☐ | Runtime team | P1 | Detect unintended changes |
| Receipt validation tooling | ☐ | CLI team | P2 | `jig-cli validate-receipt` command |

**Deliverable:** Golden receipt test suite with version pinning.

### Performance Baselines

| Task | Status | Owner | Priority | Notes |
|------|--------|-------|----------|-------|
| Cold start benchmark | ☐ | Runtime team | P1 | Time to first execution |
| Warm execution benchmark | ☐ | Runtime team | P1 | Subsequent runs |
| Fuel cost profiling | ☐ | Runtime team | P1 | Per-operation fuel usage |
| Memory usage baseline | ☐ | Runtime team | P2 | Peak and sustained |

**Target Baselines:**
- Cold start: < 50ms (local development)
- Warm execution: < 10ms (cached module)
- Fuel predictability: ±5% variance for identical operations
- Memory: < 32MB per execution

---

## P2: Advanced Testing

### Security & Robustness

| Task | Status | Owner | Priority | Notes |
|------|--------|-------|----------|-------|
| Fuzz hostcall inputs | ☐ | Security team | P1 | cargo-fuzz integration |
| Resource exhaustion tests | ☐ | Runtime team | P1 | Memory/fuel/time limits |
| Malicious WASM detection | ☐ | Security team | P1 | Invalid modules, traps |
| Soak tests (long-running) | ☐ | QA team | P2 | 24hr continuous execution |

**Deliverable:** Security test suite with CI integration (feature-gated).

### CI/CD

| Task | Status | Owner | Priority | Notes |
|------|--------|-------|----------|-------|
| CI matrix: macOS + Linux | ☐ | DevOps | P1 | Both stable Rust |
| Nightly Rust compatibility check | ☐ | DevOps | P2 | Early warning system |
| Code coverage reporting | ☐ | DevOps | P2 | Target: 80%+ for core modules |
| Performance regression detection | ☐ | DevOps | P2 | Benchmark on each PR |

**Deliverable:** Full CI pipeline with quality gates.

---

## Open Questions for M4

1. **Archival Timeline:** Should we archive repos immediately or after a grace period?
2. **Migration Support:** Do we need to provide automated migration tooling for old consumers?
3. **Performance Targets:** Are the baseline targets realistic given current hardware?
4. **Fuzz Testing Scope:** Which hostcalls are highest priority for fuzzing?
5. **Golden Receipt Versioning:** How do we handle receipt schema evolution in tests?

---

## M4 Completion Checklist

### Exit Criteria

- [ ] **Deprecations Complete:**
  - [ ] 3 vestigial repos archived with clear README pointers
  - [ ] jig-runtime-select removed from all consumers
  - [ ] Top-level docs updated to reflect WASM-only architecture

- [ ] **Tests Hardened:**
  - [ ] Determinism tests passing (same inputs → same receipts)
  - [ ] Parity tests passing (server/cli receipt equivalence)
  - [ ] Security tests passing (capability deny-by-default, fuel limits)
  - [ ] Golden receipt suite established

- [ ] **CI/CD:**
  - [ ] CI matrix running on macOS + Linux
  - [ ] All quality gates passing (tests, fmt, clippy, deny)

- [ ] **Documentation:**
  - [ ] Migration guides complete
  - [ ] Performance baselines documented
  - [ ] Security model documented

### Success Metrics

- **Test Coverage:** 80%+ for core modules (engine, fuel, receipt)
- **CI Green:** All tests passing on supported platforms
- **Performance:** Within baseline targets (±10% acceptable variance)
- **Security:** Zero known vulnerabilities; fuzz tests passing

---

## Next Steps After M4

Once M4 complete:
1. **Release Candidate:** Tag jig-runtime v0.2.0-rc1
2. **Consumer Migrations:** jig-cli and remaining consumers
3. **Production Hardening:** Load testing, monitoring integration
4. **Community Feedback:** Solicit external reviews

**Timeline Estimate:** M4 completion ~2-3 weeks (depends on archival approvals and test scope).

---

## Notes

- **Parallel Work:** Deprecations and test hardening can proceed in parallel
- **Blocking Dependencies:** Repository archival requires org-level permissions
- **Risk Mitigation:** Golden receipt tests prevent unintended protocol changes
- **Performance:** Baselines are guidelines; actual requirements TBD based on use cases
