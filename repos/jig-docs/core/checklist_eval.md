Findings vs Plan (strict)
[Step 1: Canonical Serialization & Signatures] — Complete
Canonical bytes:
BlockManifest::to_canonical_bytes()
and
BlockReceipt::to_canonical_bytes()
in
src/manifest.rs
and
src/receipt.rs
; canonicalizer in
src/serde_helpers.rs
.
Signing payload helper:
BlockReceipt::signing_payload()
strips
signature
and
metadata
in
src/receipt.rs
.
Schema/version metadata: RECEIPT_SCHEMA_VERSION defaulted;
HashAlgorithms
defaults (render_hash, block_id) in
src/receipt.rs
.
Tests:
signing_payload_excludes_signature_and_metadata()
,
canonical_json_sorts_keys_recursively()
,
hash_algorithms_default_values_present()
.
[Step 2: Determinism Verification API] — Partially Complete (core is functionally in place; two ergonomic nits)
API & policy:
verify_determinism()
,
DeterminismPolicy
,
HostImportAllowlist
, forbidden imports, float detection in
src/wasm_validation.rs
.
Wiring:
BlockBundle::validate_code()
builds strict policy, applies memory limit from
Constraints
, and validates in
src/bundle.rs
.
Import allowlist / forbidden: Default allowlist + explicit forbidden set;
check_imports()
helper available.
Timeout: Represented in
Constraints
and exposed in
Limits
; not enforceable statically here (runtime concern).
Tests: empty module accepted, float ops rejected, allowlisted imports OK, disallowed + forbidden imports rejected, memory/table bounds enforced, bundle validation consumes policy.
Gaps to consider:
No public non-test method to allow floats (only
allow_floats_for_tests()
under #[cfg(test)]).
No explicit unit test covering
validate_code_with_allowlist()
toggling a specific import via allowlist (policy hook).
[Step 3: Capability Scope Semantics] — Complete (tests could add more negatives)
Parser/normalization:
ScopeParser
with scheme/authority/segments, wildcard rules; canonical render in
src/capability_scope.rs
.
Coverage:
parse_scope()
,
covers_prefix()
, and usage key roundtrip tests present.
Note: Negative test vectors for invalid segments/wildcards would harden coverage.
[Step 4: Outcome & Metering Model] — In Progress (logic present; add a couple tests)
Model: OutcomeStatus,
Outcome
, ReasonCode,
Counters
(fuel + per-cap + status bins + bytes) in
src/receipt.rs
.
Validation: Failure requires reason; failure must not include affordances; counters.fuel_total == fuel_used; sum(fuel_by_capability) == fuel_total; status bins keys must be present in capabilities_used.
Recent tests: Added
status_by_capability_keys_must_be_in_capabilities_used()
,
fuel_by_capability_sum_must_equal_fuel_total()
; have
failure_requires_reason_code()
.
Gaps to consider:
Add explicit negative test for “failure + non-empty affordances” (validator already enforces).
Add test that status labels are uppercased in status_by_capability.
[Step 5: Timing Semantics Enforcement] — Complete
Validation: timings.total == init + exec in
src/receipt.rs
;
Timings::new()
sets total = init + exec.
Tests: Negative case for invalid totals; clock-source helper
.clock_source_monotonic()
and constant RECEIPT_METADATA_CLOCK_SOURCE re-exported.
Spec/docs alignment: Spec example fixed and note added;
README.md
timing guidance updated.
[Step 6: Golden Receipts & Regression Tests] — Complete
Fixtures:
tests/fixtures/receipt_ok.json
,
receipt_soft_fail.json
,
receipt_hard_fail.json
reflect invariant and v0.2 shape.
Property tests: CID and JSON order stability, Arbitrary implementations in
src/proptest_generators.rs
.
[Step 7: Documentation & Broadcast] — Not evaluated per request
You asked not to flag missing docs here; checklist focuses on non-doc items.
