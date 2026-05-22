# jig-cli Cross-Binary Alignment Implementation Plan

**Created:** 2025-11-11
**Based on:** `executable-internet-master-plan/20251102_REVIEW.md`, `IMPLEMENTATION_PLAN.md`, and current jig-cli state
**Current Status:** Phase 1 & 2 ✅ Complete, Phase 3-7 🔄 Pending
**Scope:** Align jig-cli with Receipt v0.2, cross-binary parity, analytics integration, and deterministic execution

---

## Executive Summary

**Completed Work:**
- ✅ Simple message path (text blocks with zero WASM knowledge)
- ✅ Receipt v0.2 types and viewing commands
- ✅ Receipt comparison/parity testing infrastructure

**Remaining Work:**
- 🔄 Runtime adapter integration (blocked on jig-runtime Receipt v0.2 API)
- 🔄 Local block execution with receipts
- 🔄 Deterministic parity testing with jig-server
- 🔄 Block authoring lifecycle (init, lint, build, sign)
- 🔄 Analytics integration (optional local DuckDB)
- 🔄 Configuration alignment with jig-config profiles

**Critical Dependencies:**
1. **jig-runtime** must complete Receipt v0.2 API with per-capability fuel tracking
2. **jig-server** must implement `/receipts/{cid}` endpoint for parity testing
3. **jig-core** must finalize Wasm validation and capability DSL (P0)

---

## Task Matrix

### Phase A: Dependencies & Blockers (External)

| # | Task | Component | Priority | Size | Dependencies | Owner | Test Conditions | Status |
|---|------|-----------|----------|------|--------------|-------|-----------------|--------|
| A1 | jig-runtime Receipt v0.2 API complete | jig-runtime | P0 | XL (4h) | jig-core types | runtime team | `execute_with_receipt()` returns full v0.2 | 🔄 Blocked |
| A2 | jig-runtime fuel tracking per capability | jig-runtime | P0 | XL (4h) | A1 | runtime team | `fuel_by_capability` map accurate | 🔄 Blocked |
| A3 | jig-runtime deterministic seed support | jig-runtime | P0 | M (1h) | A1 | runtime team | Same seed → same receipt 100% | 🔄 Blocked |
| A4 | jig-server `/receipts/{cid}` endpoint | jig-server | P0 | L (2h) | Receipt v0.2 | server team | Returns Receipt v0.2 JSON | 🔄 Blocked |
| A5 | jig-server receipt v0.2 emission | jig-server | P0 | XL (4h) | Receipt v0.2 | server team | All v0.2 fields populated | 🔄 Blocked |
| A6 | jig-core Wasm validation API | jig-core | P0 | L (2h) | wasmparser | core team | `verify_determinism()` callable | 🔄 Blocked |
| A7 | jig-core capability DSL | jig-core | P0 | L (2h) | A6 | core team | `Capability` types usable | 🔄 Blocked |

### Phase B: Runtime Integration (CLI)

| # | Task | Component | Priority | Size | Dependencies | Owner | Test Conditions | Status |
|---|------|-----------|----------|------|--------------|-------|-----------------|--------|
| B1 | Create `src/runtime/mod.rs` adapter | jig-cli | P0 | M (1h) | A1, A2, A3 | cli team | Compiles, thin wrapper | 🔄 TODO |
| B2 | Add Cargo features for runtime adapter | jig-cli | P0 | S (0.5h) | B1 | cli team | `local-runtime` feature works | 🔄 TODO |
| B3 | Implement `WasmtimeAdapter` struct | jig-cli | P0 | L (2h) | B1 | cli team | Delegates to jig-runtime | 🔄 TODO |
| B4 | Add `ExecutionSpec` and `ExecutionLimits` | jig-cli | P0 | M (1h) | B1 | cli team | Types match runtime API | 🔄 TODO |
| B5 | Write runtime adapter unit tests | jig-cli | P1 | M (1h) | B3 | cli team | Basic execution works | 🔄 TODO |

### Phase C: Block Execution Commands

| # | Task | Component | Priority | Size | Dependencies | Owner | Test Conditions | Status |
|---|------|-----------|----------|------|--------------|-------|-----------------|--------|
| C1 | Implement `jig block run` command | jig-cli | P0 | L (2h) | B3 | cli team | Executes WASM, prints receipt | 🔄 TODO |
| C2 | Add `--receipt <path>` flag | jig-cli | P0 | S (0.5h) | C1 | cli team | Writes JSON to file | 🔄 TODO |
| C3 | Add `--seed <u64>` for determinism | jig-cli | P0 | S (0.5h) | C1 | cli team | Same seed → same output | 🔄 TODO |
| C4 | Add `--fuel`, `--memory`, `--timeout` flags | jig-cli | P0 | M (1h) | C1 | cli team | Limits enforced correctly | 🔄 TODO |
| C5 | Add `--cap <capability>` allowlist | jig-cli | P0 | M (1h) | C1, A7 | cli team | Deny-by-default enforced | 🔄 TODO |
| C6 | Implement manifest auto-loading | jig-cli | P1 | M (1h) | C1 | cli team | Loads `block.toml` if present | 🔄 TODO |
| C7 | Add pricing flag `--pricing` | jig-cli | P1 | M (1h) | C1 | cli team | Receipt includes cost estimate | 🔄 TODO |
| C8 | Pretty-print execution results | jig-cli | P0 | M (1h) | C1 | cli team | Human-readable format | 🔄 TODO |
| C9 | Exit code based on outcome status | jig-cli | P1 | S (0.5h) | C1 | cli team | 0=ok, 1=fail, 2=limit | 🔄 TODO |
| C10 | Write integration tests for `block run` | jig-cli | P0 | L (2h) | C1-C9 | cli team | 5+ test blocks pass | 🔄 TODO |

### Phase D: Deterministic Parity Testing

| # | Task | Component | Priority | Size | Dependencies | Owner | Test Conditions | Status |
|---|------|-----------|----------|------|--------------|-------|-----------------|--------|
| D1 | Implement seed recording in receipt | jig-cli | P0 | S (0.5h) | C3 | cli team | Seed in receipt metadata | 🔄 TODO |
| D2 | Create parity test harness | jig-cli | P0 | L (2h) | C1, A4 | cli team | Compares local vs server | 🔄 TODO |
| D3 | Add golden receipt fixtures | jig-cli | P0 | M (1h) | D2 | cli team | 10+ canonical receipts | 🔄 TODO |
| D4 | Implement render hash validation | jig-cli | P0 | M (1h) | D2 | cli team | Determinism check passes | 🔄 TODO |
| D5 | Implement fuel parity check (5% tolerance) | jig-cli | P0 | S (0.5h) | D2 | cli team | Fuel within tolerance | 🔄 TODO |
| D6 | Add timing comparison (tolerant) | jig-cli | P1 | S (0.5h) | D2 | cli team | Timing diff noted, not fail | 🔄 TODO |
| D7 | Write determinism property tests | jig-cli | P1 | L (2h) | D2 | cli team | 100 runs → 100 matches | 🔄 TODO |
| D8 | Document parity testing workflow | jig-cli | P1 | S (0.5h) | D2 | cli team | README section complete | 🔄 TODO |

### Phase E: Block Authoring Lifecycle

| # | Task | Component | Priority | Size | Dependencies | Owner | Test Conditions | Status |
|---|------|-----------|----------|------|--------------|-------|-----------------|--------|
| E1 | Implement `jig block init` command | jig-cli | P0 | L (2h) | jig-core | cli team | Creates block.toml + stub | 🔄 TODO |
| E2 | Create rust-wasi template | jig-cli | P0 | M (1h) | E1 | cli team | Template compiles to WASM | 🔄 TODO |
| E3 | Create tinygo-wasi template (optional) | jig-cli | P2 | M (1h) | E1 | cli team | Go template works | 🔄 TODO |
| E4 | Implement template selection UI | jig-cli | P1 | M (1h) | E1 | cli team | User can pick template | 🔄 TODO |
| E5 | Implement `jig block lint` command | jig-cli | P1 | L (2h) | A6 | cli team | Validates manifest + WASM | 🔄 TODO |
| E6 | Implement `jig block build` helper | jig-cli | P1 | M (1h) | E1 | cli team | Runs cargo/tinygo build | 🔄 TODO |
| E7 | Implement `jig block sign` command | jig-cli | P1 | L (2h) | jig-core | cli team | Ed25519 signature added | 🔄 TODO |
| E8 | Implement `jig block verify` command | jig-cli | P1 | M (1h) | E7 | cli team | Validates signatures | 🔄 TODO |
| E9 | Implement `jig block capabilities` inspector | jig-cli | P1 | M (1h) | A7 | cli team | Lists required capabilities | 🔄 TODO |
| E10 | Write block authoring tutorial | jig-cli | P1 | M (1h) | E1-E9 | cli team | End-to-end example works | 🔄 TODO |

### Phase F: Analytics Integration (Local)

| # | Task | Component | Priority | Size | Dependencies | Owner | Test Conditions | Status |
|---|------|-----------|----------|------|--------------|-------|-----------------|--------|
| F1 | Add DuckDB dependency (optional feature) | jig-cli | P2 | S (0.5h) | None | cli team | Feature-gated correctly | 🔄 TODO |
| F2 | Create local analytics schema (DuckDB) | jig-cli | P2 | M (1h) | F1 | cli team | Matches ClickHouse schema | 🔄 TODO |
| F3 | Implement receipt → DuckDB ingestion | jig-cli | P2 | L (2h) | F2 | cli team | Receipts stored locally | 🔄 TODO |
| F4 | Add `jig analyze` command | jig-cli | P2 | M (1h) | F3 | cli team | Queries local receipts | 🔄 TODO |
| F5 | Implement basic analytics queries | jig-cli | P2 | M (1h) | F4 | cli team | Fuel usage, timing stats | 🔄 TODO |
| F6 | Add export to Parquet format | jig-cli | P2 | M (1h) | F3 | cli team | Parquet files loadable | 🔄 TODO |
| F7 | Document local analytics workflow | jig-cli | P2 | S (0.5h) | F4 | cli team | README section complete | 🔄 TODO |

### Phase G: Configuration Alignment

| # | Task | Component | Priority | Size | Dependencies | Owner | Test Conditions | Status |
|---|------|-----------|----------|------|--------------|-------|-----------------|--------|
| G1 | Integrate jig-config dependency | jig-cli | P1 | M (1h) | jig-config | cli team | Reads profiles correctly | 🔄 TODO |
| G2 | Support profile selection flag | jig-cli | P1 | S (0.5h) | G1 | cli team | `--profile potato` works | 🔄 TODO |
| G3 | Load execution limits from profile | jig-cli | P0 | M (1h) | G1 | cli team | Limits match profile | 🔄 TODO |
| G4 | Load analytics backend from profile | jig-cli | P2 | M (1h) | G1, F2 | cli team | DuckDB vs none per profile | 🔄 TODO |
| G5 | Add config validation on load | jig-cli | P1 | S (0.5h) | G1 | cli team | Invalid configs rejected | 🔄 TODO |
| G6 | Document config hierarchy | jig-cli | P1 | S (0.5h) | G1 | cli team | CLI flags > env > file | 🔄 TODO |

### Phase H: Nameserver Integration

| # | Task | Component | Priority | Size | Dependencies | Owner | Test Conditions | Status |
|---|------|-----------|----------|------|--------------|-------|-----------------|--------|
| H1 | Implement `jig id register` command | jig-cli | P1 | L (2h) | jig-nameserver | cli team | DID registered successfully | 🔄 TODO |
| H2 | Implement `jig id prove` command | jig-cli | P1 | L (2h) | H1 | cli team | Useful work proof submitted | 🔄 TODO |
| H3 | Implement `jig id status` command | jig-cli | P1 | M (1h) | H1 | cli team | Shows reputation tier | 🔄 TODO |
| H4 | Add nameserver token management | jig-cli | P1 | M (1h) | H1 | cli team | Tokens stored securely | 🔄 TODO |
| H5 | Integrate DID resolution | jig-cli | P1 | L (2h) | H1 | cli team | Resolves DIDs to metadata | 🔄 TODO |
| H6 | Write nameserver integration tests | jig-cli | P1 | M (1h) | H1-H5 | cli team | Full lifecycle tested | 🔄 TODO |

### Phase I: Enhanced Features & Polish

| # | Task | Component | Priority | Size | Dependencies | Owner | Test Conditions | Status |
|---|------|-----------|----------|------|--------------|-------|-----------------|--------|
| I1 | Implement `jig send --block <path>` | jig-cli | P1 | M (1h) | C1 | cli team | Sends prebuilt blocks | 🔄 TODO |
| I2 | Add `jig block from-stdin` command | jig-cli | P2 | M (1h) | E1 | cli team | Piping workflow works | 🔄 TODO |
| I3 | Implement shell completions (bash/zsh/fish) | jig-cli | P2 | M (1h) | None | cli team | Completions install | 🔄 TODO |
| I4 | Add progress indicators for long operations | jig-cli | P2 | S (0.5h) | C1 | cli team | Spinner shows during exec | 🔄 TODO |
| I5 | Implement `--verbose` and `--debug` flags | jig-cli | P2 | S (0.5h) | None | cli team | Detailed logging works | 🔄 TODO |
| I6 | Add color output support (with NO_COLOR) | jig-cli | P2 | S (0.5h) | None | cli team | Colors work, can disable | 🔄 TODO |
| I7 | Implement `jig version --check` | jig-cli | P2 | S (0.5h) | None | cli team | Checks for updates | 🔄 TODO |
| I8 | Write comprehensive CLI help text | jig-cli | P1 | M (1h) | All commands | cli team | `--help` is clear | 🔄 TODO |

### Phase J: Testing & Validation

| # | Task | Component | Priority | Size | Dependencies | Owner | Test Conditions | Status |
|---|------|-----------|----------|------|--------------|-------|-----------------|--------|
| J1 | Write unit tests for all commands | jig-cli | P0 | XL (4h) | All phases | cli team | >80% line coverage | 🔄 TODO |
| J2 | Create integration test suite | jig-cli | P0 | XL (4h) | All phases | cli team | E2E scenarios pass | 🔄 TODO |
| J3 | Add snapshot tests for CLI output | jig-cli | P1 | M (1h) | J1 | cli team | Output format stable | 🔄 TODO |
| J4 | Create performance benchmarks | jig-cli | P1 | L (2h) | C1 | cli team | Baseline established | 🔄 TODO |
| J5 | Write security audit checklist | jig-cli | P1 | M (1h) | All phases | cli team | Security review passed | 🔄 TODO |
| J6 | Add cross-platform CI tests | jig-cli | P0 | L (2h) | J1, J2 | cli team | macOS/Linux pass | 🔄 TODO |
| J7 | Create golden test fixtures | jig-cli | P0 | M (1h) | D3 | cli team | 20+ test blocks | 🔄 TODO |
| J8 | Add fuzz testing for parsers | jig-cli | P2 | L (2h) | J1 | cli team | No panics on bad input | 🔄 TODO |

---

## Dependencies Graph

```
Phase A (External Blockers)
    ↓
Phase B (Runtime Integration)
    ↓
Phase C (Block Execution) ←─────┐
    ↓                           │
Phase D (Parity Testing)        │
    ↓                           │
Phase E (Block Authoring) ──────┘
    ↓
Phase G (Config Alignment)
    ↓
Phase F (Analytics - Optional)
    ↓
Phase H (Nameserver)
    ↓
Phase I (Polish)
    ↓
Phase J (Testing)
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

### Blocked on External Dependencies (47.5h estimated for all repos)
1. **Phase A:** Tasks A1-A7 (wait for other teams)

### CLI Implementation (once unblocked)
1. **Phase B:** B1, B3, B4 (4h) - Runtime adapter
2. **Phase C:** C1, C2, C3, C4, C5, C8, C10 (9.5h) - Block execution
3. **Phase D:** D1-D5 (5h) - Deterministic parity
4. **Phase E:** E1-E2 (3h) - Basic block authoring
5. **Phase G:** G3 (1h) - Config limits
6. **Phase J:** J1, J2, J6 (10h) - Testing

**CLI-Specific Critical Path Total:** ~32.5 hours

---

## Phase Completion Criteria

### Phase A: External Dependencies
- [ ] jig-runtime exports stable `execute_with_receipt()` API
- [ ] jig-runtime produces full Receipt v0.2 with per-capability fuel
- [ ] jig-runtime supports deterministic seed injection
- [ ] jig-server exposes `/receipts/{cid}` endpoint
- [ ] jig-core exports Wasm validation and capability DSL

### Phase B: Runtime Integration
- [ ] `src/runtime/mod.rs` exists and compiles
- [ ] `WasmtimeAdapter` delegates to jig-runtime correctly
- [ ] Feature flags isolate runtime dependencies
- [ ] Basic unit tests pass

### Phase C: Block Execution
- [ ] `jig block run test.wasm` executes and prints receipt
- [ ] `--receipt out.json` writes full Receipt v0.2
- [ ] `--seed <u64>` produces deterministic results
- [ ] Limits (fuel, memory, timeout) enforced correctly
- [ ] Capabilities deny-by-default, allowlist works
- [ ] Pretty-printing shows human-readable output
- [ ] Integration tests cover happy path + errors

### Phase D: Deterministic Parity
- [ ] Same WASM + same seed → identical receipt 100% of time
- [ ] Render hash matches between CLI and server
- [ ] Fuel usage within 5% tolerance
- [ ] `jig receipt compare` detects mismatches
- [ ] Golden fixtures for 10+ common block types
- [ ] Property tests validate determinism

### Phase E: Block Authoring
- [ ] `jig block init` creates valid block scaffold
- [ ] Rust WASM template compiles successfully
- [ ] Block authoring tutorial complete and tested
- [ ] `jig block lint` catches common errors

### Phase F: Analytics (Optional)
- [ ] DuckDB schema matches server ClickHouse schema
- [ ] Local receipts stored and queryable
- [ ] `jig analyze` shows basic stats
- [ ] Parquet export works

### Phase G: Configuration
- [ ] jig-config integration complete
- [ ] Profile-based limits work correctly
- [ ] Config validation catches errors
- [ ] CLI flags override config hierarchy

### Phase H: Nameserver
- [ ] DID registration workflow complete
- [ ] Useful work proof submission works
- [ ] Token management secure
- [ ] Integration tests pass

### Phase I: Polish
- [ ] All commands have clear help text
- [ ] Output formatting consistent and professional
- [ ] Error messages actionable
- [ ] Shell completions available

### Phase J: Testing
- [ ] Unit test coverage >80%
- [ ] Integration tests cover all commands
- [ ] CI passes on macOS and Linux
- [ ] Performance baselines established
- [ ] Security audit complete

---

## Risk Assessment

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| jig-runtime API changes | High | Medium | Lock API contract early, version carefully |
| Receipt v0.2 breaking changes | High | Low | Already stable in jig-core |
| Performance regression | Medium | Medium | Establish baselines early (Phase J4) |
| Cross-platform compatibility | Medium | Low | CI matrix tests (Phase J6) |
| Determinism violations | High | Medium | Extensive property tests (Phase D7) |
| Configuration complexity | Medium | High | Clear docs + validation (Phase G) |

---

## Open Questions

1. **Receipt Storage:** Should CLI store all receipts locally by default, or only on `--receipt` flag?
   - **Recommendation:** Only on explicit `--receipt` flag to avoid clutter; add `~/.jig/receipts/` for persistent storage if user wants

2. **Template Registry:** Embed templates or fetch from remote catalog?
   - **Recommendation:** Embed 2-3 core templates, add `--template-url` for custom

3. **Analytics Default:** Should DuckDB analytics be on by default or opt-in?
   - **Recommendation:** Opt-in via `--analytics` or profile setting; keep CLI lean by default

4. **Parity Tolerance:** What's acceptable variance in fuel usage between CLI and server?
   - **Recommendation:** 5% tolerance for fuel, strict equality for render hash

5. **Nameserver Tokens:** File-based storage or system keychain integration?
   - **Recommendation:** Start with file-based (~/.jig/tokens.json), add keychain in Phase I

6. **Block Signing Keys:** Where should CLI store signing keys?
   - **Recommendation:** `~/.jig/keys/` with permissions 0600, document key rotation

---

## Success Metrics

- **Deterministic Render Rate:** 100% of identical blocks + seed produce identical receipts
- **CLI Parity:** 100% of CLI executions match server receipts (fuel within 5%)
- **60-Second KPI:** Preserved - simple `jig send` still works with zero WASM knowledge
- **Test Coverage:** >80% line coverage for core execution paths
- **Performance:** `jig block run` completes in <500ms for simple blocks (p95)
- **Zero Breaking Changes:** All Phase 1 & 2 functionality continues to work

---

## Timeline Estimate

### By Phase (CLI work only, excluding blocked Phase A)

- **Phase B (Runtime):** 4 hours
- **Phase C (Execution):** 9.5 hours
- **Phase D (Parity):** 5 hours
- **Phase E (Authoring):** 6 hours
- **Phase F (Analytics):** 5.5 hours (optional)
- **Phase G (Config):** 3 hours
- **Phase H (Nameserver):** 6 hours
- **Phase I (Polish):** 4 hours
- **Phase J (Testing):** 12 hours

**Total CLI Effort:** ~55 hours (excluding optional P2 tasks)

**Critical Path (P0 only):** ~32.5 hours

**Realistic Timeline:** 5-7 days of focused development once Phase A dependencies resolve

---

## Cross-Binary References

### Depends On:
- **jig-runtime** (Phase A: A1, A2, A3) - Receipt v0.2 API, fuel tracking, determinism
- **jig-server** (Phase A: A4, A5) - Receipt endpoint, v0.2 emission
- **jig-core** (Phase A: A6, A7) - Wasm validation, capability DSL
- **jig-config** (Phase G: G1) - Profile-based configuration
- **jig-nameserver** (Phase H: H1) - DID registration and useful work

### Provides To:
- **jig-server** - Parity testing reference implementation
- **jig-gui** - Block authoring workflow example
- **Integration tests** - Golden receipt fixtures
- **Documentation** - End-to-end usage examples

---

## Next Steps

### Immediate (User Action Required)
1. **Review this plan** for alignment on scope and priorities
2. **Confirm open questions** (receipt storage, template strategy, etc.)
3. **Track Phase A blockers** with other teams
4. **Approve sequencing** or adjust phase order

### Once Approved
1. **Create GitHub project** with tasks as issues
2. **Assign Phase B tasks** to CLI team
3. **Schedule daily standups** for Phase A blocker tracking
4. **Establish integration testing** schedule with server team

### Monitoring
- **Weekly:** Review Phase A blocker status
- **Daily:** Track CLI implementation progress (Phases B-J)
- **Continuous:** Run test suite, update completion checklist

---

## Notes

- **Preserve Simplicity:** Never break the `jig send "hello"` workflow
- **Test-First:** Write tests before implementation for critical paths
- **Incremental:** Each phase must leave CLI in working state
- **Document Everything:** Update README as features land
- **Coordinate Carefully:** Align with jig-runtime and jig-server on API contracts
- **Profile-Aware:** Respect potato-friendly defaults (no heavy dependencies by default)

---

**Last Updated:** 2025-11-11
**Next Review:** After Phase A dependencies resolve
**Maintainer:** jig-cli team
