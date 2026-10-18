# L2 runtime inventory

Date: 2026-10-18. Lane L2 of the
[v0.2 close and M3 start plan](../superpowers/plans/2026-10-18-v0.2-close-and-m3-start.md).

This lists the runtime and capability code that no production path calls, and says for each item
what happens to it. "Callers" means callers outside the item's own module and its tests. They were
found by searching the workspace (`repos/`) at `main` `d16f26a`.

Verdicts:

- **Delete:** dead. L2 removes it in a deletion PR with no behaviour change.
- **Keep:** something on a production path calls it.
- **Other lane:** dead or questionable, but the files belong to another lane.
- **Ask DJ:** removing it changes behaviour, or a design may claim it.

## Hazards

| # | Hazard | What `main` does | PR |
| --- | --- | --- | --- |
| 1 | Engine identity in signed receipts | `RUNTIME_VERSION` is jig-runtime's crate version, "0.1.0" since 2024, and it is signed into every text-render receipt | #119: replaced by `EngineIdentity` (exact wasmtime version, config fingerprint, fuel schedule) |
| 1a | Engine features wider than the validator | wasmtime 49 enables most WebAssembly 3.0 proposals. The engine turned off only threads and SIMD | #125: the engine enables exactly WebAssembly 2.0 without SIMD |
| 2 | Pricing version is a free label | `pricing.schedule_version` is an operator setting, signed into priced receipts as given | #119: now the constant `FUEL_SCHEDULE_VERSION`; configs that set it are rejected |
| 3 | `fuel_total` sum | `engine.wasm` is dropped once any host bucket exists | #109: always recorded. The sum stays for v0.2, as `receipts.md` requires; v0.3 drops `fuel_total` (Q1, decided) |
| 4 | Post-hoc `capabilities_used` filter | `BlockRuntime::finalize_block_receipt` filters the receipt's capabilities to match the manifest, and codeless blocks get the manifest's capabilities copied in as "used" | Its only caller is `POST /blocks`, which #107 (L3) removes. L2 then deletes `BlockRuntime::execute` and the conversion, filter included |

## jig-core capability modules

| Item | Callers | Verdict |
| --- | --- | --- |
| `capability_dsl` (`build_capability`, `parse_scopes`, `capability!`, `capabilities!`) | `lint.rs` tests only | Delete |
| `lint` (`lint_block`, `allowlist_from_manifest`, `BlockLintResult`) | none | Delete |
| `check_manifest_capabilities`, `check_manifest_capabilities_with_registry`, `CapabilityReport` | `lint.rs` and one `lib.rs` test | Delete |
| `CapabilityDefinition.required_imports` (the `jig_host::*` mapping) | read only by `check_manifest_capabilities_with_registry`. No `jig_host` import is linked anywhere | Delete |
| `CapabilityRegistry`, `default_jig_capabilities` names, `attestation_requirements`, `fuel_cost_estimate` | `BlockManifest::validate`, through `BlockManifestBuilder::build` (jig-client `blocks.rs`, jig-server federation). It rejects unknown capability names, missing attestations, and fuel requests over 10× the estimate | **Keep.** It is live validation, not scaffolding. Lane C replaces it |
| `validate_capability_request`, `validate_all_capabilities` | the same manifest validation path | Keep |

## jig-runtime

| Item | Callers | Verdict |
| --- | --- | --- |
| `capabilities.rs` (`CapabilityRegistry`, `CapabilityHandle`, `CapabilityUsage`), `#![allow(dead_code)]` | none, never constructed | Delete, with `RuntimeError::InvalidCapabilityHandle` |
| `costs.rs` (`CostSchedule`, `InstructionCosts`, `CapabilityCosts`) and `cost-schedules/v0.1.0.toml` | `integration-tests/tests/runtime_workspace_integration.rs` builds one and checks its version. Nothing loads a schedule | Delete, with that test assertion |
| `FuelConfig.cost_schedule_path`, `FuelConfig.default_hostcall_costs` | none | Delete |
| `telemetry.rs` (`TelemetryHook`, `TelemetryRegistry`, `MemoryTelemetryCollector`) | none | Delete |
| deprecated `ExitStatus` in `lib.rs` | none | Delete |
| `EngineConfig.component_model`, `EngineConfig.wasi_preview2` | jig-runtime reads neither. jig-nameserver sets `wasi_preview2` | Delete `component_model`. `wasi_preview2` needs a one-line change in `jig-nameserver/src/runtime.rs` (L6) |
| `CapabilityConfig` (`allowed`, `quotas`, `scope_policies`, `deny_by_default`) | only the dead `capabilities.rs`. jig-nameserver's `NameserverRuntime` (dead, L6) constructs it | Delete after L6 removes `NameserverRuntime` |
| `ExecutionContext.capabilities` / `with_capability` | written by jig-server's `BlockRuntime` and tests. The runtime never reads it | Delete. jig-server's own call goes in the same PR |
| `ExecutionContext.env`, `args`, `rng_seed` / `with_env`, `with_rng_seed` | written by jig-cli `runtime.rs` (`rng_seed`) and one integration test. The runtime never reads them: WASI gets no env or args | Delete. The jig-cli line belongs to L3, so ask there first |
| capability meter (`fuel.rs`, `CapabilityMeterHandle`) | no production writer. No host import exists to charge it | Ask DJ: lane C may claim it for the effectful tier |
| Cargo feature `deterministic` | no `cfg` reads it | Delete |
| Cargo feature `component-model` | no `cfg` reads it. It only turns on wasmtime's component model | Delete. Lane A brings it back with the WIT ABI |
| Cargo feature `receipt-signing` (optional `ed25519-dalek`) | no `cfg` reads it. jig-nameserver enables it in `Cargo.toml` | Delete, with a one-line change to `jig-nameserver/Cargo.toml` (L6) |
| optional `tokio` dependency ("future async API") | no feature or code uses it | Delete |
| Cargo feature `tracing` | 40 `cfg`s in jig-runtime. CI never builds it | Ask DJ: build it in CI, or remove it (plan rule 3) |

## jig-server runtime

| Item | Callers | Verdict |
| --- | --- | --- |
| `BlockRuntime::execute`, `finalize_block_receipt`, `create_empty_block_receipt` | only `handler.rs` (`POST /blocks`) | Delete after #107 merges. `BlockRuntime::new` stays only as #107's boot check; replace it with `RuntimeConfig::validate` |
| `ExecutionConfig` | `v0_0_2.rs` uses it to configure the ingest executor | Keep |

## Not touched

- The four receipt formats in jig-pipeline (`0.2-synthetic`, `0.3-render`, `0.3-sealed`, and the v0.2 `BlockReceipt`) belong to lane A's design.
- Unused `jig-config` dependencies of jig-pipeline and jig-client: removed in #126.

## Other crates

| Item | Callers | Verdict |
| --- | --- | --- |
| `repos/hello-wasm` | only `integration-tests/user-flows/test_runner_bakeoff.sh`, which measures the archived podman/docker runners and skips wasmtime when the build fails. Not built in CI | Delete |
| `test_runner_bakeoff.sh` | manual only | Other lane: L3 (integration-tests) can delete it |
| jig-config `execution.rs` `import_allowlist` / `forbidden_imports` (`jig_host::*`, `env::get`) | nothing outside jig-config reads them. jig-core `wasm_validation` has its own list | Other lane: L3 |
| jig-nameserver `NameserverRuntime` (`runtime.rs`) | never constructed outside its tests | Other lane: L6 |

## Open questions for DJ

- **Q1. Fuel sum. Decided (C8 in lane C's design, #117).** Wasm fuel and host meters stay
  separate, and v0.3 has no `fuel_total`. #109 is the v0.2 stopgap: it keeps the measured wasm
  fuel in the sum that `receipts.md` still requires. `fuel_total` goes away with the v0.2
  `BlockReceipt`, and nothing new may depend on it.
- **Q2. Capability meter.** Keep `CapabilityMeterHandle` for lane C, or delete it now? Git history
  keeps it.
- **Q3. `tracing` feature.** Add a CI build, or remove it?
- **Q4. `CapabilityRegistry`.** It is live validation with made-up names (`net:http:fetch`,
  `ai:llm:inference`) and nothing behind them. Leave it to lane C, or narrow it to `core:compute`
  now? Narrowing changes behaviour.
