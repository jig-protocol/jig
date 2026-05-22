# Runtime Integration Status — Phase 1.3

**Date**: 2025-11-05  
**Status**: `jig-runtime` baseline landed; v0.2 receipt mapping complete; capability alignment pending  
**Context**: [IMPLEMENTATION_PLAN_FINAL.md](./IMPLEMENTATION_PLAN_FINAL.md)

---

## Delivered by `jig-runtime` team

- Added the `repos/jig-runtime` crate implementing the shared Wasmtime runner with deterministic config, resource limits, and pricing hooks.
- `Runtime::execute` now yields `jig_runtime::Receipt` (v0.2): module hash, fuel usage, per-capability buckets, limits snapshots, pricing metadata, and structured outcomes.
- `RuntimeConfig` covers ResourceLimits, capability allowlists/quotas, fuel metering, engine knobs, and pricing; validated by `cargo nextest run -p jig-runtime` (92 tests, 3 ignored).
- Telemetry scaffolding (`telemetry.rs`) and capability registry/quota enforcement primitives (`capabilities.rs`, `fuel.rs`) are in place for future hostcall instrumentation.

## jig-server integration snapshot

- `src/runtime/mod.rs`: `BlockRuntime` now wraps `jig_runtime::Runtime`, applies limits/pricing from `ServerConfig`, and converts runtime receipts to `jig_core::BlockReceipt`.
- `handler.rs`: ingestion path executes blocks through the new runtime and persists receipts alongside bundles.
- v0.2 receipt fields (`counters`, `timings_ms`, `limits`, `renders_match`, outcome) are now populated directly from `jig_runtime::Receipt`; bytes_rx remains a placeholder until hostcall telemetry differentiates directions.
- Legacy shims (`capability::FuelTracker`, `CapabilityRegistry`) remain in the crate but are no longer wired into execution; the guard still contains placeholder drop logic.

## Validation to date

- `cargo nextest run -p jig-runtime` ✅ — full suite passes (see runtime crate for detailed breakdown).
- `cargo nextest run -p jig-server` ✅ — full suite passes; `server::tests::server_initializes` now tolerates sandboxed environments that deny socket binds.

## Outstanding work for jig-server Phase 1.3

1. Align capability enforcement with `jig-runtime`:
   - Decide whether to delegate to runtime-level allowlists/quotas or continue using the server-side registry.
   - Remove the legacy `capability::FuelTracker` once runtime telemetry fully replaces it.
2. Expand runtime validation coverage:
   - Execute real WASM flows (fuel exhaustion, pricing toggles, empty-code blocks) end-to-end via `BlockRuntime`.
   - Capture golden receipts to guard future regressions.
3. Prepare storage & API updates (Phase 2.2 dependency):
   - Introduce schema changes for `counters`/`timings` JSON, per-capability rows, and analytics sinks.
   - Ensure REST responses and federation payloads include the enriched receipt.

## References

- `repos/jig-server/src/runtime/mod.rs`
- `repos/jig-server/src/handler.rs`
- `repos/jig-runtime/src/api.rs`, `src/receipt.rs`, `src/config.rs`
- `executable-internet-master-plan/20251102_REVIEW.md`
- `repos/jig-server/IMPLEMENTATION_PLAN_FINAL.md`
