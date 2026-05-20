# jig-cli Implementation Roadmap

**Visual guide to bringing jig-cli up to cross-binary spec compliance**

---

## Current State vs. Target State

### ✅ What Works Today (Phase 1 & 2 Complete)

```
User Input
    ↓
jig send "hello"
    ↓
┌──────────────────────┐
│  jig-cli (current)   │
│                      │
│  ✅ Text blocks      │
│  ✅ HTTP client      │
│  ✅ Receipt types    │
│  ✅ Receipt viewing  │
│  ✅ Receipt compare  │
│                      │
│  ❌ WASM execution   │
│  ❌ Local runtime    │
│  ❌ Block authoring  │
│  ❌ Parity testing   │
└──────────────────────┘
    ↓
jig-server (HTTP)
```

### 🎯 Target State (All Phases Complete)

```
                    ┌─────────────────────────────┐
                    │    Block Development        │
                    │                             │
User ──→ jig block init (template)               │
         jig block lint (validate)               │
         jig block build (compile)               │
         jig block sign (ed25519)                │
                    └─────────────────────────────┘
                                ↓
                    ┌─────────────────────────────┐
                    │    Local Execution          │
                    │                             │
                    │  jig-cli                    │
                    │    ↓                        │
                    │  jig-runtime (adapter)      │
                    │    ↓                        │
                    │  Wasmtime Engine            │
                    │    • Fuel metering          │
                    │    • Capability sandbox     │
                    │    • Deterministic mode     │
                    │    • Seed injection         │
                    └─────────────────────────────┘
                                ↓
                    ┌─────────────────────────────┐
                    │    Receipt v0.2             │
                    │                             │
                    │  • block_id                 │
                    │  • render_hash              │
                    │  • fuel_used                │
                    │  • fuel_by_capability ✨    │
                    │  • counters (bytes, calls)  │
                    │  • timings (queue/init/exec)│
                    │  • limits (snapshot)        │
                    │  • outcome (status/reason)  │
                    │  • signature                │
                    └─────────────────────────────┘
                                ↓
                    ┌─────────────────────────────┐
                    │    Parity Testing           │
                    │                             │
        CLI Receipt │         vs.         │ Server Receipt
            ↓       │                     │       ↓
        render_hash │  ← MUST MATCH →    │  render_hash
        fuel_used   │  ← WITHIN 5% →     │  fuel_used
        counters    │  ← VALIDATE →      │  counters
        outcome     │  ← MUST MATCH →    │  outcome
                    └─────────────────────────────┘
                                ↓
                    ┌─────────────────────────────┐
                    │    Analytics (Optional)     │
                    │                             │
                    │  DuckDB (local)             │
                    │    • receipts table         │
                    │    • capability_counters    │
                    │    • blocks table           │
                    │                             │
                    │  jig analyze                │
                    │    • Query fuel usage       │
                    │    • Export to Parquet      │
                    └─────────────────────────────┘
                                ↓
                    ┌─────────────────────────────┐
                    │    Integration              │
                    │                             │
                    │  jig-nameserver             │
                    │    • DID registration       │
                    │    • Useful work proofs     │
                    │    • Reputation tiers       │
                    │                             │
                    │  jig-config                 │
                    │    • Profile-based limits   │
                    │    • Potato → hyperscale    │
                    └─────────────────────────────┘
```

---

## Implementation Phases (Visual Timeline)

```
Week 0: BLOCKED - Waiting on Dependencies
├─ Phase A: jig-runtime Receipt v0.2 API (other team)
├─ Phase A: jig-server /receipts endpoint (other team)
└─ Phase A: jig-core Wasm validation (other team)

Week 1: Foundation
├─ Phase B: Runtime adapter (4h)
│   └─ Tasks: B1, B3, B4
├─ Phase C: Block execution (9.5h)
│   └─ Tasks: C1-C5, C8, C10
└─ Phase E: Block authoring (can start in parallel)
    └─ Tasks: E1, E2 (3h)

Week 2: Parity & Polish
├─ Phase D: Parity testing (5h)
│   └─ Tasks: D1-D5
├─ Phase G: Config alignment (3h)
│   └─ Tasks: G1, G3, G5
└─ Phase E: Complete authoring
    └─ Tasks: E5-E10 (3h)

Week 3: Integration & Testing (if needed)
├─ Phase H: Nameserver (6h)
│   └─ Tasks: H1-H6
├─ Phase I: Polish (4h)
│   └─ Tasks: I1, I8
└─ Phase J: Testing (12h)
    └─ Tasks: J1, J2, J6

Optional: Analytics
└─ Phase F: DuckDB analytics (5.5h)
    └─ Tasks: F1-F7 (P2 - defer if needed)
```

---

## Critical Path Visualization

```
START
  ↓
[WAIT] Phase A: External Dependencies (blocking)
  ↓
[4h] Phase B: Runtime Adapter
  ├─ B1: Create src/runtime/mod.rs
  ├─ B3: WasmtimeAdapter struct
  └─ B4: ExecutionSpec types
  ↓
[9.5h] Phase C: Block Execution ⭐ CRITICAL
  ├─ C1: jig block run command
  ├─ C2: --receipt flag
  ├─ C3: --seed flag
  ├─ C4: limits (fuel/memory/timeout)
  ├─ C5: --cap allowlist
  ├─ C8: pretty-print
  └─ C10: integration tests
  ↓
[5h] Phase D: Parity Testing ⭐ CRITICAL
  ├─ D1: seed recording
  ├─ D2: parity test harness
  ├─ D3: golden fixtures
  ├─ D4: render hash validation
  └─ D5: fuel parity check
  ↓
[3h] Phase E: Core Authoring
  ├─ E1: jig block init
  └─ E2: rust-wasi template
  ↓
[1h] Phase G: Config Limits
  └─ G3: load limits from profile
  ↓
[10h] Phase J: Testing ⭐ CRITICAL
  ├─ J1: unit tests
  ├─ J2: integration tests
  └─ J6: CI tests
  ↓
DONE (32.5h critical path)
```

---

## Dependency Tree

```
jig-cli Implementation
├─ DEPENDS ON (Phase A - External)
│   ├─ jig-runtime
│   │   ├─ Receipt v0.2 API .................. A1 (P0)
│   │   ├─ Per-capability fuel tracking ...... A2 (P0)
│   │   └─ Deterministic seed support ........ A3 (P0)
│   ├─ jig-server
│   │   ├─ /receipts/{cid} endpoint .......... A4 (P0)
│   │   └─ Receipt v0.2 emission ............. A5 (P0)
│   └─ jig-core
│       ├─ Wasm validation API ............... A6 (P0)
│       └─ Capability DSL .................... A7 (P0)
│
├─ IMPLEMENTS (Phase B-J - Internal)
│   ├─ Runtime adapter (Phase B)
│   ├─ Block execution (Phase C)
│   ├─ Parity testing (Phase D)
│   ├─ Block authoring (Phase E)
│   ├─ Config alignment (Phase G)
│   ├─ Nameserver integration (Phase H)
│   ├─ Polish (Phase I)
│   └─ Testing (Phase J)
│
└─ PROVIDES TO (Outputs)
    ├─ jig-server ............................ Parity reference
    ├─ jig-gui ............................... Authoring example
    ├─ Integration tests ..................... Golden fixtures
    └─ Documentation ......................... E2E examples
```

---

## Feature Matrix: Current vs. Target

| Feature            | Current | After Phase B | After Phase C | After Phase D | Target State |
| ------------------ | ------- | ------------- | ------------- | ------------- | ------------ |
| Simple send        | ✅      | ✅            | ✅            | ✅            | ✅           |
| Receipt types      | ✅      | ✅            | ✅            | ✅            | ✅           |
| Receipt viewing    | ✅      | ✅            | ✅            | ✅            | ✅           |
| Receipt compare    | ✅      | ✅            | ✅            | ✅            | ✅           |
| Runtime adapter    | ❌      | ✅            | ✅            | ✅            | ✅           |
| Local WASM exec    | ❌      | ❌            | ✅            | ✅            | ✅           |
| Fuel metering      | ❌      | ❌            | ✅            | ✅            | ✅           |
| Capability sandbox | ❌      | ❌            | ✅            | ✅            | ✅           |
| Deterministic seed | ❌      | ❌            | ✅            | ✅            | ✅           |
| Parity testing     | ❌      | ❌            | ❌            | ✅            | ✅           |
| Block authoring    | ❌      | ❌            | ❌            | ❌            | ✅ (Phase E) |
| Config profiles    | ❌      | ❌            | ❌            | ❌            | ✅ (Phase G) |
| Analytics          | ❌      | ❌            | ❌            | ❌            | ✅ (Phase F) |
| Nameserver         | ❌      | ❌            | ❌            | ❌            | ✅ (Phase H) |

---

## Test Coverage Roadmap

```
Current Coverage: ~40% (Phase 1 & 2 only)
                   ↓
Phase B Complete: ~50% (runtime adapter tests)
                   ↓
Phase C Complete: ~65% (execution command tests)
                   ↓
Phase D Complete: ~75% (parity tests)
                   ↓
Phase E Complete: ~80% (authoring tests)
                   ↓
Phase J Complete: >80% (comprehensive tests)
                   ↓
Target: >80% line coverage, 100% critical path
```

---

## Risk Timeline

```
Week 0 (Current)
├─ 🔴 HIGH: Blocked on jig-runtime API
├─ 🔴 HIGH: Blocked on jig-server endpoint
└─ 🟡 MEDIUM: jig-core API uncertainty

Week 1 (Phase B-C)
├─ 🟡 MEDIUM: Runtime API stability
├─ 🟠 LOW: Performance concerns
└─ 🟢 MINIMAL: Well-defined scope

Week 2 (Phase D-E)
├─ 🟡 MEDIUM: Determinism edge cases
├─ 🟠 LOW: Cross-platform issues
└─ 🟢 MINIMAL: Clear requirements

Week 3 (Phase H-J)
├─ 🟠 LOW: Integration complexity
├─ 🟢 MINIMAL: Polish work
└─ 🟢 MINIMAL: Known test patterns
```

---

## Milestone Checklist

### Milestone 1: Runtime Ready (Phase B)

- [ ] `src/runtime/mod.rs` exists and compiles
- [ ] `WasmtimeAdapter` can call jig-runtime
- [ ] Basic unit tests pass
- [ ] **Blocker cleared:** jig-runtime API stable

### Milestone 2: Execution Works (Phase C)

- [ ] `jig block run test.wasm` succeeds
- [ ] Receipt v0.2 written to file
- [ ] Limits enforced correctly
- [ ] Integration tests pass
- [ ] **Demo-able:** Can show local execution

### Milestone 3: Parity Achieved (Phase D)

- [ ] Deterministic execution verified
- [ ] CLI receipt matches server receipt
- [ ] Render hash identical
- [ ] Fuel within 5% tolerance
- [ ] **Blocker cleared:** jig-server endpoint ready

### Milestone 4: Authoring Complete (Phase E)

- [ ] `jig block init` creates scaffold
- [ ] Template compiles to WASM
- [ ] Full lifecycle works: init → build → run
- [ ] **Demo-able:** Can show block development

### Milestone 5: Production Ready (Phase J)

- [ ] Test coverage >80%
- [ ] CI passing on all platforms
- [ ] Documentation complete
- [ ] Security audit passed
- [ ] **Ready for release**

---

## Quick Reference: Key Files

### Already Exists

- ✅ `src/main.rs` - CLI entry point
- ✅ `src/commands.rs` - Simple send/read/tail
- ✅ `src/config.rs` - Config management
- ✅ `src/receipt/v0_2.rs` - Receipt types
- ✅ `src/cmd/receipt.rs` - Receipt commands
- ✅ `src/http_client.rs` - Server communication

### To Be Created

- 🆕 `src/runtime/mod.rs` - Runtime adapter (Phase B)
- 🆕 `src/cmd/block_run.rs` - Block execution (Phase C)
- 🆕 `src/cmd/block_init.rs` - Block scaffolding (Phase E)
- 🆕 `src/cmd/block_lint.rs` - Block validation (Phase E)
- 🆕 `src/cmd/block_sign.rs` - Block signing (Phase E)
- 🆕 `src/templates/` - Block templates (Phase E)
- 🆕 `src/analytics.rs` - DuckDB integration (Phase F)
- 🆕 `src/nameserver.rs` - DID integration (Phase H)
- 🆕 `tests/integration/` - Integration tests (Phase J)
- 🆕 `tests/fixtures/` - Golden test data (Phase J)

---

## Command Evolution

### Current Commands (Phase 1 & 2)

```bash
jig init
jig send "message"
jig read [--channel] [--limit]
jig tail [--channel]
jig receipt view --file receipt.json
jig receipt compare local.json server.json
```

### After Phase C (Block Execution)

```bash
# All above, plus:
jig block run test.wasm --receipt out.json
jig block run test.wasm --seed 12345 --fuel 1000000
jig block run test.wasm --cap net.fetch --cap crypto.sign
```

### After Phase E (Block Authoring)

```bash
# All above, plus:
jig block init my-block --template rust-wasi
jig block lint my-block/
jig block build my-block/
jig block sign my-block/
jig send --block my-block.jigb
```

### After Phase H (Nameserver)

```bash
# All above, plus:
jig id register --name alice
jig id prove --work-file receipt.json
jig id status
```

### Target State (All Phases)

```bash
# All above, plus:
jig analyze fuel-usage --last 100
jig analyze export --format parquet --out data.parquet
jig block from-stdin < input.txt
```

---

## Next Steps

1. **Review** this roadmap and the detailed plan
2. **Approve** scope, timeline, and design decisions
3. **Coordinate** with jig-runtime, jig-server, jig-core teams on Phase A
4. **Begin** Phase B implementation (runtime adapter)
5. **Start** Phase E in parallel (block authoring - no runtime dependency)

---

**Status:** 🟡 Awaiting approval
**Owner:** jig-cli team
**Stakeholders:** jig-runtime, jig-server, jig-core teams
**Timeline:** 5-7 days post-blockers
**Questions?** See [ALIGNMENT_SUMMARY.md](./ALIGNMENT_SUMMARY.md)
