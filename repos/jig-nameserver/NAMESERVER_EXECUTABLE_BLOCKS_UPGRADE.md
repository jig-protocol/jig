# jig-nameserver: Executable Blocks Integration Plan

**Purpose:** Upgrade jig-nameserver to support executable block validation, fuel metering, and receipt-based governance following the 20251102 review.

**Date:** 2025-11-04

## Context

The upstream repos (`jig-core`, `jig-runtime`, `jig-server`, `jig-config`) are receiving updates for:

- Executable Wasm blocks with deterministic execution
- Receipt v0.2 with fuel metering and per-capability counters
- Outcome-based pricing (ok/soft_fail/hard_fail + affordances)
- Canonical JSON serialization and receipt signatures

This document outlines how jig-nameserver must adapt to leverage these primitives for enhanced governance, reputation tracking, and bad behavior detection.

---

## 1. Receipt Storage & Verification

### Objective

Store and validate execution receipts (v0.2) to enable:

- Receipt-based useful work validation
- Cross-nameserver receipt verification
- Fuel anomaly detection for reputation scoring

### Tasks

#### 1.1 Extend Storage Schema

- [ ] Add `receipts` table with v0.2 fields:
  ```sql
  CREATE TABLE receipts (
    block_id TEXT PRIMARY KEY,
    host_did TEXT NOT NULL,
    executed_at INTEGER NOT NULL,
    render_hash TEXT NOT NULL,
    renders_match INTEGER NOT NULL,
    fuel_used INTEGER NOT NULL,
    memory_peak_mb INTEGER NOT NULL,
    counters_fuel_total INTEGER NOT NULL,
    counters_bytes_tx INTEGER NOT NULL,
    counters_bytes_rx INTEGER NOT NULL,
    counters_syscalls INTEGER NOT NULL,
    timings_total_ms INTEGER NOT NULL,
    outcome_status TEXT NOT NULL,  -- ok | soft_fail | hard_fail
    outcome_affordances TEXT,      -- JSON array
    outcome_reason TEXT,
    capabilities TEXT NOT NULL,    -- JSON array
    attestations TEXT,             -- JSON array
    signature TEXT NOT NULL
  );
  ```
- [ ] Add `receipt_capability_counters` table for fuel attribution:
  ```sql
  CREATE TABLE receipt_capability_counters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    block_id TEXT NOT NULL,
    executed_at INTEGER NOT NULL,
    capability TEXT NOT NULL,
    fuel_used INTEGER NOT NULL,
    FOREIGN KEY (block_id) REFERENCES receipts(block_id)
  );
  CREATE INDEX idx_rcc_block ON receipt_capability_counters(block_id);
  CREATE INDEX idx_rcc_capability ON receipt_capability_counters(capability);
  ```

#### 1.2 Receipt Validation API

- [ ] Add `POST /v1/receipts/submit` endpoint:
  - Validate receipt signature (Ed25519)
  - Verify render_hash matches expected (if known)
  - Store receipt + per-capability counters
  - Update host reputation based on outcome
- [ ] Add `GET /v1/receipts/:block_id` for receipt queries
- [ ] Add `GET /v1/receipts?host_did=X&outcome=Y` for filtering

#### 1.3 Receipt Cross-Validation

- [ ] Add useful work kind `ValidateReceipt` for cross-validation tasks:
  - Nameserver A submits receipt to Nameserver B for verification
  - Nameserver B re-executes block (or fetches receipts from other hosts)
  - Nameserver B returns attestation confirming/disputing receipt
- [ ] Store attestations in `receipts.attestations[]` field
- [ ] Log attestation discrepancies in transparency log

---

## 2. Host Transparency Entries

### Objective

Publish runtime configuration and policy hashes to transparency log for federated trust.

### Tasks

#### 2.1 Extend Transparency Log Event Types

- [ ] Add `TransparencyLogEventKind::HostRuntimePublished`:
  ```rust
  pub struct HostRuntimeEntry {
      pub host_did: String,
      pub runtime_hash: String,      // Wasmtime version + capability DSL version
      pub capabilities: Vec<String>,  // Supported capabilities
      pub affordances: Vec<String>,   // Supported affordances (email.delivered, etc.)
      pub policy_hash: String,        // BLAKE3 of current policy
      pub published_at: DateTime<Utc>,
  }
  ```
- [ ] Log runtime_hash changes when nameserver updates Wasmtime/DSL
- [ ] Log policy_hash changes when rulesets/tribunal policies update

#### 2.2 Federation Gossip for Runtime Configs

- [ ] Extend `PolicyHashExchange` to include `runtime_hash` and `affordances`
- [ ] Add endpoint `GET /v1/federation/runtime` to fetch current runtime config
- [ ] Verify federated peers publish transparency entries for runtime changes
- [ ] Flag peers with missing/stale runtime transparency entries

---

## 3. Attestation Registry

### Objective

Track useful-work validators and their attestations for reputation cross-referencing.

### Tasks

#### 3.1 Attestation Storage

- [ ] Add `attestations` table:
  ```sql
  CREATE TABLE attestations (
    id TEXT PRIMARY KEY,
    block_id TEXT NOT NULL,
    verifier_did TEXT NOT NULL,
    verdict TEXT NOT NULL,  -- confirmed | disputed | soft_fail
    fuel_delta INTEGER,     -- difference from original receipt
    evidence_cid TEXT,      -- optional IPFS/S3 pointer to evidence
    attested_at INTEGER NOT NULL,
    signature TEXT NOT NULL
  );
  CREATE INDEX idx_attestations_block ON attestations(block_id);
  CREATE INDEX idx_attestations_verifier ON attestations(verifier_did);
  ```
- [ ] Store attestations when received via useful work or gossip

#### 3.2 Reputation Integration

- [ ] Update reputation scoring to weight attestations:
  - `confirmed` attestations boost host reputation
  - `disputed` attestations trigger tribunal review or auto-penalty
  - Multiple `disputed` from different verifiers = high confidence fraud
- [ ] Log attestation-based reputation updates to transparency log

---

## 4. Capability/Affordance Alignment

### Objective

Align DNS capability advertisements with affordance declarations for pricing and verification.

### Tasks

#### 4.1 Extend Capabilities Config

- [ ] Add `affordances` field to `CapabilitiesConfig`:
  ```rust
  pub struct CapabilitiesConfig {
      pub version: String,
      pub domain: String,
      pub work_types: Vec<String>,
      pub affordances: Vec<String>,  // NEW: email.delivered, bridge.forwarded, etc.
      pub features: Vec<String>,
  }
  ```
- [ ] Update DNS TXT generation to include `jig-ns=affordances:email.delivered,bridge.forwarded`
- [ ] Update `.well-known/jig-ns/capabilities` plain text output

#### 4.2 Affordance-Based Reputation

- [ ] Track `outcome.affordances[]` from receipts in reputation updates
- [ ] Boost reputation for hosts that complete declared affordances (e.g., `email.delivered`)
- [ ] Penalize hosts that claim affordances but never complete them (phantom capability detection)

---

## 5. Governance Blocks (Tribunal Decisions as Blocks)

### Objective

Store tribunal decisions as content-addressable blocks with CIDs for federation and auditing.

### Tasks

#### 5.1 Tribunal Decision Block Format

- [ ] Define `TribunalDecisionBlock` with CID:
  ```rust
  pub struct TribunalDecisionBlock {
      pub block_id: String,        // CID of the decision
      pub case_id: Uuid,
      pub decision: String,        // "penalty" | "exoneration" | "escalate"
      pub evidence_cids: Vec<String>,
      pub decided_by: String,      // tribunal DID or multisig
      pub decided_at: DateTime<Utc>,
      pub signature: String,
  }
  ```
- [ ] Generate CIDs for tribunal decisions using BLAKE3 hash of canonical JSON
- [ ] Store tribunal blocks in content-addressable storage (filesystem or IPFS)

#### 5.2 Federation & Transparency

- [ ] Add endpoint `GET /v1/tribunal/blocks/:cid` to fetch decision blocks
- [ ] Log tribunal decision block_ids in transparency log (`TribunalDecisionGossip`)
- [ ] Gossip tribunal block CIDs to federated peers for cross-validation

---

## 6. Security Model Adaptations

### Objective

Use receipt determinism and fuel anomalies to detect bad behavior.

### Tasks

#### 6.1 Receipt-Based Bad Behavior Detection

- [ ] Implement `ReceiptAnomalyDetector`:
  - Flag `renders_match=false` as non-deterministic execution (HIGH severity)
  - Flag excessive `fuel_by_capability["net.fetch"]` as potential abuse
  - Flag `outcome=hard_fail` patterns (repeated failures suggest malicious blocks)
  - Flag fuel_used significantly above/below historical average for block type
- [ ] Auto-escalate anomalies to tribunal or apply immediate PoW increase

#### 6.2 Cross-Nameserver Verification

- [ ] Request receipt cross-validation from 2+ federated peers for suspicious hosts
- [ ] Compare `fuel_used`, `outcome`, and `render_hash` across peers
- [ ] If majority disagrees with host's receipt, mark host as unreliable
- [ ] Log discrepancies to transparency log

#### 6.3 Penalty Escalation

- [ ] Update penalty ledger to include `receipt_anomaly` as penalty reason
- [ ] Apply stepped penalties:
  - 1st non-deterministic render: +2 difficulty bits, warning logged
  - 2nd: +4 bits, tribunal case opened
  - 3rd: host suspended, all receipts invalidated
- [ ] Allow penalty appeals via tribunal with counter-evidence receipts

---

## 7. Useful Work Extensions

### Objective

Expand useful work types to include executable block validation tasks.

### Tasks

#### 7.1 New Useful Work Kinds

- [ ] Add `UsefulWorkKind::ProcessExecutableBlock`:
  - Requester submits block_id + expected_render_hash
  - Worker executes block and returns receipt
  - Nameserver verifies receipt and awards reputation
- [ ] Add `UsefulWorkKind::ValidateFuelCounts`:
  - Requester submits receipt to verify
  - Worker re-executes block and compares fuel_by_capability
  - Worker returns attestation with fuel_delta
- [ ] Add `UsefulWorkKind::CrossValidateReceipt`:
  - Requester submits receipt + host_did
  - Worker fetches receipts from multiple nameservers
  - Worker returns consensus verdict (confirmed/disputed)
- [ ] Add `UsefulWorkKind::ResolveReceiptDispute`:
  - Tribunal assigns dispute resolution as useful work
  - Worker provides detailed analysis of receipt discrepancies
  - Tribunal uses analysis for final decision

#### 7.2 Receipt-Based Useful Work API

- [ ] Extend `POST /v1/work/enqueue` to accept receipt payloads
- [ ] Extend `POST /v1/work/:id/result` to include attestation signatures
- [ ] Add reputation rewards for useful work completions with verified attestations

---

## 8. Runtime Deployment & Message Format Changes

### Objective

Prepare nameserver to consume and operate with jig-runtime primitives.

### Tasks

#### 8.1 Runtime Integration (via jig-runtime crate)

- [ ] Add `jig-runtime` dependency (once available from upstream):
  - Embed Wasmtime for on-demand block execution
  - Use capability DSL for secure host API
  - Generate v0.2 receipts for executed blocks
- [ ] Implement `NameserverHostAPI` with limited capabilities:
  - `storage.read:receipts:*` (read receipt storage)
  - `storage.write:attestations:*` (write attestation results)
  - `net.fetch:federation:*` (fetch receipts from peers)
  - No `net.fetch:*` wildcard to prevent abuse
- [ ] Configure fuel limits in `NameServerConfig`:
  ```toml
  [runtime]
  fuel_max = 5_000_000
  memory_max_mb = 32
  execution_timeout_ms = 250
  ```

#### 8.2 Message Format Updates

- [ ] Accept CID-based block_ids in all APIs (replace UUID where applicable)
- [ ] Use canonical JSON serialization for all transparency log entries
- [ ] Sign all outbound receipts/attestations with nameserver's Ed25519 key
- [ ] Verify signatures on all inbound receipts/attestations

---

## 9. Analytics & Observability

### Objective

Track receipt metrics for reputation tuning and tribunal evidence.

### Database Strategy by Tier

- **Tier 1 (Potato):** SQLite ONLY. No additional dependencies. Target: <60sec curl-to-hello-world.
- **Tier 2 (Prosumer):** Truth: SQLite or Postgres. Optional OLAP: DuckDB. Optional Parquet export for local analytics.
- **Tier 3 (Hyperscale):** Truth: Postgres or upgrade to CockroachDB. Hot State: Redis/ValkeyDB or upgrade to ScyllaDB. OLAP: ClickHouse for federated cross-nameserver analytics. Optional addons for storage (e.g., S3 for Parquet exports), vector (Pinecone), etc. Targeting large-scale enterprise use cases and/or consumer hubs.
- **Consistent across tiers**: OSS, open source (or at _minimum_ source-available, and even then only at T3), open data, open analytics, open governance.

### Tasks

#### 9.1 Tier 1 Analytics (Potato: SQLite Only)

- [ ] Keep raw receipts in SQLite
- [ ] Run queries directly on SQLite with indexes:
  ```sql
  SELECT host_did, AVG(fuel_used), AVG(timings_total_ms), COUNT(*)
  FROM receipts WHERE outcome_status='ok' GROUP BY host_did;
  ```
- [ ] Add SQLite indexes for common query patterns (host_did, executed_at, outcome_status)
- [ ] No export tools, no additional backends for T1

#### 9.2 Tier 2 Analytics (Prosumer: Postgres + DuckDB/Parquet)

- [ ] Add optional Postgres backend via config (alternative to SQLite)
- [ ] Add `jig-ns analyze receipts --since 2025-10-01 --format parquet` CLI command
- [ ] Export receipts to Parquet for offline DuckDB queries
- [ ] Keep this optional and feature-gated (not default)

#### 9.3 Tier 3 Analytics (Hyperscale: ClickHouse)

- [ ] Add optional ClickHouse sink for federated metrics (via config):
  ```toml
  [intel]
  backend = "clickhouse"  # or "postgres" (T2) or "sqlite" (T1, default)
  clickhouse_url = "http://clickhouse.example.com:8123"
  ```
- [ ] Stream receipts to ClickHouse for cross-nameserver analytics
- [ ] Build dashboards for fuel usage, outcome patterns, attestation rates

---

## 10. Testing Priorities

### Test Coverage

- [ ] Unit tests: receipt validation, fuel anomaly detection, attestation storage
- [ ] Integration tests:
  - Submit receipt → verify signature → store → query
  - Enqueue useful work (ValidateReceipt) → assign → complete with attestation
  - Cross-nameserver receipt validation (2+ nameservers)
  - Tribunal decision → block generation → CID fetch
- [ ] Property tests: receipt determinism, fuel counter consistency
- [ ] Chaos tests: Byzantine hosts submitting fraudulent receipts

---

## 11. Migration Path

### Phase A: Receipt Storage (P0, blocks useful work)

1. Add receipt tables to SQLite schema
2. Implement receipt submission endpoint
3. Basic signature verification
4. Test: store and query receipts

### Phase B: Useful Work Integration (P1, blocks cross-validation)

1. Add new useful work kinds (ProcessExecutableBlock, ValidateFuelCounts)
2. Receipt-based useful work assignment
3. Attestation storage and signature verification
4. Test: useful work lifecycle with attestations

### Phase C: Transparency & Federation (P1, blocks governance)

1. Log runtime_hash and policy_hash to transparency log
2. Gossip runtime configs to federated peers
3. Tribunal decision blocks with CIDs
4. Test: transparency verification, federation sync

### Phase D: Security & Detection (P2, enables adaptive governance)

1. Receipt anomaly detection rules
2. Cross-nameserver verification protocol
3. Penalty escalation for receipt fraud
4. Test: detect and penalize non-deterministic hosts

### Phase E: Runtime Embedding (P2, enables self-execution)

1. Integrate jig-runtime crate
2. NameserverHostAPI with limited capabilities
3. On-demand block execution for validation
4. Test: execute block, generate receipt, verify determinism

### Phase F: Analytics (P3, optional)

1. Local Parquet export + DuckDB queries
2. Optional ClickHouse sink for hyperscale
3. Dashboards for fuel metrics, outcome trends
4. Test: analytics pipeline, query performance

---

## 12. Dependencies & Blockers

### Upstream Blockers

- **jig-core**: Must ship `BlockManifest`, `Receipt` v0.2 types, Wasm validators, capability DSL (Phase A)
- **jig-runtime**: Must ship Wasmtime wrapper with fuel metering + capability-secured host API (Phase E)
- **jig-config**: Must ship execution limits config (`[runtime]` section) (Phase A)

### Internal Dependencies

- **Storage**: SQLite schema migrations for receipts, attestations
- **Federation**: Runtime config gossip protocol extensions
- **Transparency**: New event kinds for runtime/policy publishing

---

## 13. Open Questions

1. **Receipt storage retention:** How long do we keep receipts in SQLite? Archive to S3/IPFS after N days?
2. **Privacy:** Should receipts be public or only shared with federated peers? Redact capabilities/affordances?
3. **Dispute resolution:** Who pays gas for cross-validation? Loser of dispute? Penalty pool?
4. **Runtime embedding:** Should potato nameservers execute blocks, or delegate to federated peers with more resources?
5. **Attestation trust:** How many attestations required before updating reputation? Simple majority or weighted by attester reputation?

---

## 14. Success Criteria

- [ ] Nameserver can store, validate, and query execution receipts (v0.2)
- [ ] Useful work supports receipt validation and attestation generation
- [ ] Transparency log includes host runtime/policy entries with correct ordering
- [ ] Federation gossip exchanges runtime configs and validates consistency
- [ ] Tribunal decisions stored as content-addressable blocks with CID references
- [ ] Receipt anomaly detection identifies non-deterministic or abusive hosts
- [ ] Cross-nameserver verification protocol resolves receipt disputes
- [ ] Analytics pipeline exports receipts to Parquet/DuckDB (potato) or ClickHouse (hyperscale)
- [ ] All tests passing (27+ existing + new receipt/attestation tests)

---

## Next Steps

1. Review this plan with upstream team to confirm jig-core/jig-runtime APIs
2. Prioritize Phase A (Receipt Storage) and Phase B (Useful Work Integration)
3. Update PROGRESS.md with Phase A tasks and mark as "In Progress"
4. Begin schema migrations and receipt endpoint implementation
