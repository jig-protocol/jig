# jig-cli Implementation Plan - Alignment Summary

**Date:** 2025-11-11
**Status:** 🟡 AWAITING APPROVAL
**Full Plan:** [JIG_CLI_IMPLEMENTATION_PLAN.md](./JIG_CLI_IMPLEMENTATION_PLAN.md)

---

## TL;DR

**What's Complete:**
- ✅ Simple message path (`jig send "hello"`)
- ✅ Receipt v0.2 types and viewing/comparison commands
- ✅ HTTP client integration with jig-server

**What's Blocked:**
- 🔄 Local WASM execution - waiting on jig-runtime Receipt v0.2 API
- 🔄 Deterministic parity testing - waiting on jig-server `/receipts/{cid}` endpoint
- 🔄 Wasm validation - waiting on jig-core validation API

**What's Next:**
Once blockers clear: Runtime adapter → Block execution → Parity testing → Block authoring (32.5h critical path)

---

## Key Numbers

| Metric | Value | Notes |
|--------|-------|-------|
| Total Tasks | 97 tasks across 10 phases | Comprehensive coverage |
| Critical Path (P0) | 32.5 hours | CLI work only, excludes external deps |
| Total Effort | ~55 hours | Including P1 tasks |
| External Blockers | 7 tasks (Phase A) | jig-runtime, jig-server, jig-core |
| Timeline Estimate | 5-7 days | Once dependencies resolve |

---

## Phase Breakdown

### ✅ Complete (Before This Plan)
- Phase 1: Simple message path
- Phase 2: Receipt v0.2 foundation

### 🔄 Pending Execution

| Phase | Tasks | Est. Time | Priority | Blocker |
|-------|-------|-----------|----------|---------|
| A: External Dependencies | 7 | Varies | P0 | Other teams |
| B: Runtime Integration | 5 | 4h | P0 | Phase A |
| C: Block Execution | 10 | 9.5h | P0 | Phase B |
| D: Parity Testing | 8 | 5h | P0 | Phase C |
| E: Block Authoring | 10 | 6h | P0/P1 | Phase C |
| F: Analytics (Optional) | 7 | 5.5h | P2 | Phase E |
| G: Config Alignment | 6 | 3h | P0/P1 | Phase E |
| H: Nameserver | 6 | 6h | P1 | Phase G |
| I: Polish & Features | 8 | 4h | P1/P2 | Phase H |
| J: Testing & Validation | 8 | 12h | P0/P1 | All phases |

---

## Critical Dependencies (MUST RESOLVE FIRST)

### From jig-runtime (P0 Blockers)
1. **Receipt v0.2 API** - `execute_with_receipt()` method that returns full Receipt v0.2
2. **Per-capability fuel tracking** - `fuel_by_capability: BTreeMap<String, u64>` populated accurately
3. **Deterministic seed support** - Accept seed parameter, ensure reproducible execution

**Estimated by jig-runtime team:** ~8-12 hours
**API Contract:**
```rust
pub fn execute_with_receipt(
    &self,
    wasm_bytes: &[u8],
    manifest: &BlockManifest,
    seed: u64,
    limits: ExecutionLimits,
    capability_allowlist: &[String],
) -> Result<BlockReceipt>
```

### From jig-server (P0 Blockers)
1. **Receipt endpoint** - `GET /receipts/{cid}` returns Receipt v0.2 as JSON
2. **Receipt v0.2 emission** - All server-side executions produce full v0.2 receipts

**Estimated by jig-server team:** ~6 hours

### From jig-core (P0 Blockers)
1. **Wasm validation API** - `verify_determinism(module_bytes)` callable
2. **Capability DSL** - Types and macros for capability declarations

**Estimated by jig-core team:** ~4 hours

**TOTAL EXTERNAL DEPENDENCY TIME:** ~18-22 hours

---

## Key Design Decisions

### 1. Receipt Storage Strategy
**Decision Needed:** Where should CLI store receipts?

**Options:**
- A) Only when `--receipt <path>` specified (lean, no clutter)
- B) Always to `~/.jig/receipts/` (convenient for analysis)
- C) Profile-based (potato=none, standard=local)

**Recommendation:** Option A with optional persistent storage via config

### 2. Template Distribution
**Decision Needed:** How to distribute block templates?

**Options:**
- A) Embed 2-3 core templates in binary
- B) Fetch from remote catalog on demand
- C) Hybrid: embed core, add `--template-url`

**Recommendation:** Option C (pragmatic balance)

### 3. Analytics Default Behavior
**Decision Needed:** Should local analytics be enabled by default?

**Options:**
- A) Always on (DuckDB required)
- B) Opt-in via `--analytics` flag
- C) Profile-based (off for potato)

**Recommendation:** Option C aligns with potato-friendly principle

### 4. Parity Tolerance
**Decision Needed:** What variance is acceptable between CLI and server?

**Proposal:**
- Render hash: **Exact match** (determinism requirement)
- Fuel usage: **5% tolerance** (timing/hardware variance)
- Timings: **Noted but not fail** (informational only)
- Outcome status: **Exact match**

### 5. Key Management
**Decision Needed:** Where to store signing keys?

**Options:**
- A) File-based `~/.jig/keys/` with 0600 permissions
- B) System keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- C) Hardware tokens (YubiKey, etc.)

**Recommendation:** Start with A, add B in Phase I, C as future enhancement

---

## Open Questions for Review

1. **Scope Adjustment:** Are all 97 tasks in scope, or should we cut P2 tasks?
   - My recommendation: Keep P2 for visibility, defer if needed

2. **Timeline Pressure:** Is 5-7 days (post-blockers) acceptable?
   - Can compress by parallelizing phases B+E (authoring doesn't need execution)

3. **Testing Strategy:** Should we write tests before or alongside implementation?
   - My recommendation: Unit tests alongside (Phase tasks), integration tests in Phase J

4. **Breaking Changes:** Any concerns about backward compatibility?
   - All Phase 1 & 2 work preserved, no breaking changes planned

5. **Resource Allocation:** Do we wait for all Phase A tasks, or start Phase E (authoring) in parallel?
   - Phase E (block init/lint/sign) doesn't need runtime, could start immediately

6. **Documentation Priority:** Should we write docs as we go, or batch in Phase I?
   - My recommendation: Core docs with implementation, polish in Phase I

---

## Success Criteria (Confirm Agreement)

### Must-Have (P0)
- [ ] `jig block run test.wasm --receipt out.json` produces full Receipt v0.2
- [ ] Same seed produces identical receipt 100% of time
- [ ] CLI receipts match server receipts (render hash exact, fuel within 5%)
- [ ] Simple send path (`jig send "hello"`) still works with zero config
- [ ] Test coverage >80% for core execution paths

### Should-Have (P1)
- [ ] Block authoring workflow (init → edit → lint → build → sign → run)
- [ ] Nameserver integration (register, prove, status)
- [ ] Configuration profiles work correctly
- [ ] Comprehensive help text and error messages

### Nice-to-Have (P2)
- [ ] Local analytics with DuckDB
- [ ] Shell completions
- [ ] Template catalog integration
- [ ] Fuzz testing

---

## Risk Mitigation

| Risk | Impact | Mitigation Strategy |
|------|--------|---------------------|
| jig-runtime API instability | 🔴 High | Lock API contract early, version carefully |
| Cross-team coordination delays | 🟡 Medium | Weekly sync meetings, shared Slack channel |
| Determinism edge cases | 🟡 Medium | Extensive property-based testing (Phase D7) |
| Performance regressions | 🟠 Low | Establish baselines early, CI benchmarks |
| Config complexity | 🟡 Medium | Clear examples, validation, helpful errors |

---

## Approval Checklist

Before proceeding, please confirm:

- [ ] **Scope:** All phases (A-J) approved, or adjustments needed?
- [ ] **Priorities:** P0/P1/P2 assignments look correct?
- [ ] **Dependencies:** Agreement on Phase A requirements for other teams?
- [ ] **Timeline:** 5-7 days post-blockers is acceptable?
- [ ] **Design Decisions:** Open questions (#1-5 above) resolved?
- [ ] **Success Criteria:** Must-have/should-have/nice-to-have split approved?
- [ ] **Next Steps:** Ready to create GitHub issues and start Phase B?

---

## Recommended Next Actions

### If Approved As-Is:
1. Create GitHub project "jig-cli Receipt v0.2 Implementation"
2. Convert tasks to issues with labels (P0/P1/P2, phase tags)
3. Assign Phase B tasks to CLI team
4. Schedule kickoff meeting with jig-runtime, jig-server, jig-core teams
5. Begin Phase E (block authoring) in parallel while waiting for Phase A

### If Adjustments Needed:
1. Review and discuss open questions
2. Update task priorities or scope
3. Revise timeline estimates
4. Re-align with cross-binary plan
5. Get final sign-off before implementation

---

## Communication Plan

### Daily
- Stand-up: CLI team progress update
- Slack: Phase A blocker status from other teams

### Weekly
- Cross-team sync: jig-runtime, jig-server, jig-core, jig-cli
- Review: Completed tasks, updated timeline, risks

### On Completion
- Demo: Full block execution → receipt → parity testing workflow
- Retrospective: What worked, what to improve
- Documentation: Update main README and tutorial

---

## Questions to Resolve Before Starting

1. **Do you want me to start implementing Phase B/E now, or wait for your review?**
2. **Are there any priority adjustments needed based on other work?**
3. **Should I create GitHub issues for tracking, or use another system?**
4. **Any concerns about the 97-task scope or timeline estimates?**
5. **Are the design decisions (#1-5 above) acceptable, or need discussion?**

---

**Status:** 🟡 Awaiting your approval to proceed

**Next Step:** Your review and decision on:
- Scope adjustments (if any)
- Design decisions (receipt storage, templates, etc.)
- Timeline confirmation
- Go/no-go on starting implementation

