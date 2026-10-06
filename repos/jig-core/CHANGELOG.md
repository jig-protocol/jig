# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning where applicable.

## [Unreleased]

## [0.0.1] - 2025-11-05

### Added
- Determinism allowlist tests for `jig_host::http_fetch` via `BlockBundle::validate_code_with_allowlist`.
- Outcome gating test: failure outcomes cannot include affordances and must include a reason.
- Status bins normalization test: `CountersBuilder::add_status` uppercases status labels.
- Timings property test: `Timings::new(queue, init, exec)` sets `total = init + exec`.
- Hash algorithms negative test: empty `hash_algorithms` entries rejected.
- Canonical bytes stability test: `to_canonical_bytes` stable across map insertion orders for counters.
- Capability DSL macros (`capability!`, `capabilities!`) and lint helpers (`lint_block`, `allowlist_from_manifest`) for downstream CLI/server use.
- Determinism policy toggle via `Constraints.deterministic` (strict by default) and `verify_determinism_default` helper.

### Documentation
- Updated `repos/jig-docs/core/RECEIPT_V0_2.md` with `ReasonCode`, `status_by_capability`, canonical `capability|scope` keys, and expanded validation rules.
- Updated `repos/jig-core/README.md` with Determinism & Wasm Validation guidance and examples.
