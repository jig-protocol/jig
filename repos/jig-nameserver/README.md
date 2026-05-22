# Jig Nameserver

The Jig nameserver anchors decentralized identity, reputation, and tribunal governance for the executable internet. Every handle → DID mapping, proof-of-useful-work adjustment, and tribunal escalation flows through here—backed by the same ruleset metadata we expose via `.well-known/jig-ns`.

## Why It Exists

- **Identity Resolution:** Accept signed claims (Ed25519) and publish identity records for clients via `GET /v1/resolve`.
- **Adaptive Proof-of-Work:** Issue challenges with difficulty adjusted by penalty ledgers, reputation scores, and ruleset contracts.
- **Reputation Aggregation:** Ingest reputation observations (`POST /v1/reputation/observe`), aggregate them per ruleset, and store weighted scores.
- **Tribunal Automation:** Open cases, record decisions, and expose status streams so the graph can defend itself in near real-time.

## Configuration

Nameserver configuration is driven by the shared `jig-config` profile system:

1. We read `JIG_NS_CONFIG` first (explicit path).
2. Otherwise we look for `nameserver` sections in the global `jig-config.toml` (honoring profiles + overrides).
3. Environment variables always win last (`JIG_NS_DB_PATH`, `JIG_NS_POW_DIFFICULTY`, etc.).

Key sections in `jig-config.toml`:

```toml
[nameserver]
profile = "high-sec"

[nameserver.network]
bind = "0.0.0.0"
port = 8070

[nameserver.reputation]
default_ruleset = "high-sec"

[[nameserver.reputation.local_rulesets]]
key = "high-sec"
description = "Baseline high security contract"
authority = "did:jig:central"
weight = 1.0

[nameserver.reputation.local_rulesets.pow_policy]
min_bits = 14
max_bits = 28
multiplier = 1.0

[nameserver.reputation.translation_contracts]
# Translate partner QA scores into our high-sec range
from = "partner-qa"
to = "high-sec"
weight = 0.6
[nameserver.reputation.translation_contracts.transform]
type = "linear"
slope = 0.5
intercept = 0.0
```

For more examples, see [`examples/config`](examples/config/).

## Core Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/resolve?name=<handle>` | Lookup identity records.
| `POST /v1/challenge` | Request PoW challenge (`action = claim | alias`).
| `POST /v1/claim` | Submit signed identity claim with solved PoW.
| `POST /v1/alias` | Mint scoped aliases (optional anonymous subject).
| `POST /v1/reputation/observe` | Record reputation observations for ruleset aggregation.
| `GET /v1/reputation/:subject/:id` | Summary of aggregated reputation across rulesets.
| `GET /v1/reputation/:subject/:id/observations` | Raw observation listing (recent window).
| `GET /v1/tribunal/cases` | List tribunal cases (filter by status).
| `POST /v1/tribunal/cases` | Create a tribunal case.
| `GET /v1/tribunal/cases/:id` | Fetch case details + decisions.
| `POST /v1/tribunal/cases/:id/decision` | Append case decision (sustain, modify, escalate…).
| `POST /v1/work/enqueue` | Enqueue useful work assignment (admin-only).
| `POST /v1/work/assign` | Claim work assignments for a worker.
| `POST /v1/work/:id/result` | Submit work completion result.
| `GET /v1/transparency/entries` | List transparency log entries (filter by time/kind).
| `GET /v1/transparency/hashes` | List hourly hash checkpoints.
| `GET /v1/transparency/verify` | Verify chain integrity.
| `GET /v1/federation/peers` | List federation peers (active, unreachable, suspended).
| `POST /v1/federation/gossip` | Receive gossip message from peer.
| `GET /v1/federation/policy` | List policy hashes exchanged with peers.

Responses are JSON and mirror the `types` module (see `src/types.rs`).

## Reputation Flow

1. Observers (nameservers or automated agents) post observations:
   ```json
   {
     "subject": "user",
     "subject_id": "alice@example.com",
     "ruleset": "high-sec",
     "score": 0.82,
     "weight": 1.3,
     "observer": "did:jig:ns:alpha",
     "evidence": "block://bafyobs",
     "expires_at": "2025-11-02T18:34:12Z"
   }
   ```
2. We aggregate observations (weighted average, ruleset multiplier) and persist `ReputationScore`.
3. Challenge issuance (`/v1/challenge`) asks storage for the aggregated score and adjusts difficulty accordingly.
4. `GET /v1/reputation/:subject/:id` provides both aggregated and raw observations for transparent auditing.

## Tribunal Flow

1. Automated monitors or nameservers open cases:
   ```json
   {
     "subject": "user",
     "subject_id": "eve@example.net",
     "ruleset": "high-sec",
     "reason": "Automated escalation: repeated phishing blocks",
     "reporter": "did:jig:ns:alpha",
     "severity": "high",
     "metadata": {
       "observations": ["block://bafycaseobs1", "block://bafycaseobs2"],
       "escalated_by": "useful-work-monitor"
     }
   }
   ```
2. Decisions append to cases (`sustain`, `modify`, `overturn`, `dismiss`, `escalate`).
3. Case status transitions automatically (`resolved`, `dismissed`, `escalated`).
4. Future work: stream decisions into transparency logs and propagate reputation deltas.

## Useful Work System

The nameserver coordinates distributed "useful work" assignments that help offset computational costs of E2EE operations, block validation, and governance tasks. Work assignments are prioritized queues where workers claim tasks, execute them, and submit results.

### Work Types

- **`validate_block`** – Validate Wasm blocks (E2EE decryption, signature checks, fuel metering).
- **`verify_observation`** – Verify reputation observation evidence.
- **`audit_ruleset`** – Audit ruleset compliance for tribunal cases.
- **`custom`** – Extensible work type for future use.

### Configuration

```toml
[nameserver.useful_work]
assignment_ttl_secs = 600           # Assignments expire after 10 minutes
max_assignments_per_worker = 5     # Each worker can have max 5 inflight tasks
result_retention_secs = 86400      # Keep results for 24 hours
max_queue_depth = 1024             # Maximum queued + inflight assignments
```

Environment variables:
- `JIG_NS_WORK_TTL` – Assignment TTL in seconds (min 60)
- `JIG_NS_WORK_MAX_PER_WORKER` – Max assignments per worker
- `JIG_NS_WORK_RESULT_RETENTION` – Result retention in seconds
- `JIG_NS_WORK_QUEUE_DEPTH` – Max queue depth

### Workflow

1. **Enqueue work** (admin-only):
   ```bash
   curl -X POST http://localhost:8070/v1/work/enqueue \
     -H "X-Admin-Token: $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "kind": "validate_block",
       "subject": "block-abc123",
       "ruleset": "high-sec",
       "payload": {"block_cid": "bafyreiabc123..."},
       "priority": 10,
       "assignment_ttl_secs": 300
     }'
   ```

2. **Claim work** (worker):
   ```bash
   curl -X POST http://localhost:8070/v1/work/assign \
     -H "Content-Type: application/json" \
     -d '{
       "worker": "worker-001",
       "limit": 3
     }'
   ```

   Returns up to 3 assignments sorted by priority (highest first), then oldest first.

3. **Submit result**:
   ```bash
   curl -X POST http://localhost:8070/v1/work/$ASSIGNMENT_ID/result \
     -H "Content-Type: application/json" \
     -d '{
       "worker": "worker-001",
       "status": "completed",
       "output": {"validation": "passed", "fuel_used": 12500},
       "metadata": {"duration_ms": 450}
     }'
   ```

### Queue Management

- Assignments expire automatically after TTL; expired work transitions to `failed` status.
- Workers can claim up to `max_assignments_per_worker` concurrent tasks.
- Queue depth is capped at `max_queue_depth` (enqueue requests return `429` if full).
- Priority ordering ensures high-priority work (e.g., block validation) completes first.

### Integration with E2EE and Blocks

In the executable internet architecture, useful work assignments can:
- **Validate blocks** – Verify Wasm execution receipts, check signatures, enforce fuel limits.
- **Distribute E2EE costs** – Workers can help with encryption/decryption operations (future work with MPC/threshold crypto).
- **Generate evidence** – Blocks themselves can generate provenance for whether work was performed correctly or rulesets were violated.

This creates an economic feedback loop where useful work earns reputation, and reputation influences PoW difficulty and tribunal outcomes.

## Transparency Log

The nameserver maintains an append-only transparency log of all governance actions, providing cryptographic auditability and chain-of-custody for tribunal decisions, reputation updates, and useful work completion.

### Log Structure

- **Entries**: Individual events (tribunal_decision, reputation_update, useful_work_completed, penalty_applied, identity_claimed)
- **Hourly Hashes**: Merkle root computed every hour, chaining previous hash for tamper-evidence
- **Verification**: Public endpoints allow anyone to verify chain integrity

### Event Types

- `tribunal_decision` – Tribunal case decisions with outcomes
- `reputation_update` – Reputation score changes
- `useful_work_completed` – Validated useful work results
- `penalty_applied` – Penalty points applied to identities
- `identity_claimed` – New identity registrations

### Endpoints

```bash
# List recent log entries (filter by time range, event kind)
curl "http://localhost:8070/v1/transparency/entries?limit=50&event_kind=tribunal_decision"

# List hourly hash checkpoints
curl "http://localhost:8070/v1/transparency/hashes?limit=24"

# Verify chain integrity
curl "http://localhost:8070/v1/transparency/verify"
```

### Query Parameters

- `start` – RFC3339 timestamp (e.g., `2025-10-29T00:00:00Z`)
- `end` – RFC3339 timestamp
- `event_kind` – Filter by event type
- `limit` – Max results (default 100, max 1000)

### Hash Computation

The system automatically computes merkle roots every hour:

1. Collect all entries in the period (1-hour window)
2. Hash each entry (BLAKE3)
3. Build merkle tree by hashing pairs recursively
4. Chain previous merkle root
5. Store hash checkpoint with metadata

Verification checks that each hash's `previous_hash` matches the prior period's `merkle_root`, ensuring an unbroken chain.

### Integration

Transparency logging is automatic for:
- Tribunal decisions (`POST /v1/tribunal/cases/:id/decision`)
- Reputation updates (`POST /v1/reputation/observe`)
- Useful work completion (`POST /v1/work/:id/result`)
- Penalty applications (automatic via rate limiting)

This provides an immutable audit trail for all governance actions, supporting accountability and dispute resolution in decentralized systems.

## DNS Capability Advertisement

The nameserver publishes its capabilities via DNS TXT records and a well-known endpoint, enabling federated discovery and automatic capability negotiation.

### Configuration

```toml
[nameserver.capabilities]
version = "v1"
domain = "ns.example.com"  # Your nameserver domain
useful_work_types = ["validate_block", "verify_observation", "audit_ruleset"]
tribunal_enabled = true
transparency_enabled = true
federation_enabled = false
```

Environment variables:
- `JIG_NS_DOMAIN` – Nameserver domain for DNS records
- `JIG_NS_VERSION` – Protocol version (default: v1)

### DNS TXT Records

Generate DNS TXT records from your config:

```bash
cargo run --bin dns-txt
```

Output:
```
_jig-ns.example.com  IN  TXT  "jig-ns=version:v1"
_jig-ns.example.com  IN  TXT  "jig-ns=work:validate_block,verify_observation,audit_ruleset"
_jig-ns.example.com  IN  TXT  "jig-ns=tribunal:enabled"
_jig-ns.example.com  IN  TXT  "jig-ns=transparency:enabled"
```

Add these records to your DNS zone to advertise capabilities to the federation network.

### Well-Known Endpoint

The capabilities are also available as plain text at `/.well-known/jig-ns/capabilities`:

```bash
curl http://localhost:8070/.well-known/jig-ns/capabilities
```

Output:
```
# Jig Nameserver Capabilities
version: v1
domain: ns.example.com

# Useful Work Types
work: validate_block
work: verify_observation
work: audit_ruleset

# Features
tribunal: enabled
transparency: enabled
federation: disabled
```

### Discovery Flow

1. Client queries `_jig-ns.<domain>` TXT records
2. Parses `jig-ns=` prefixed key-value pairs
3. Determines compatible protocol version and features
4. Falls back to `/.well-known/jig-ns/capabilities` for HTTP-based discovery

This lightweight, TOML-first approach keeps dependencies minimal while enabling robust federation without JSON/YAML overhead.

## Federation Gossip Protocol

The nameserver implements a decentralized gossip protocol for coordinating policy, reputation, and tribunal decisions across a federation of nameservers.

### Configuration

```toml
[nameserver.federation]
enabled = true
seed_peers = [
  "https://ns-alpha.example.com",
  "https://ns-beta.example.org"
]
max_peers = 50
allow_domains = []  # Empty = allow all
deny_domains = []   # Block specific domains
cache_ttl_secs = 3600
gossip_interval_secs = 300  # 5 minutes
handshake_timeout_secs = 30
gossip_batch_size = 100
```

Environment variables:
- `JIG_NS_FEDERATION_ENABLED` – Enable/disable federation (true/false)
- `JIG_NS_SEED_PEERS` – Comma-separated list of seed peer URLs
- `JIG_NS_MAX_PEERS` – Maximum number of federation peers
- `JIG_NS_GOSSIP_INTERVAL` – Gossip interval in seconds
- `JIG_NS_HANDSHAKE_TIMEOUT` – Handshake timeout in seconds

### Gossip Protocol

The federation coordinator runs a background task that periodically:
1. **Discovers peers** from seed URLs
2. **Handshakes** with new peers to exchange capabilities
3. **Gossips** with active peers to propagate:
   - **Policy hashes** – Protocol versions and ruleset configurations
   - **Reputation summaries** – Aggregate scores per ruleset (no PII)
   - **Tribunal decisions** – Case outcomes and penalties

### Peer Discovery

```bash
# Peers are discovered from seed URLs via capabilities endpoint
curl https://ns.example.com/.well-known/jig-ns/capabilities
```

The coordinator:
- Fetches capabilities from seed peers
- Computes BLAKE3 hash for version verification
- Stores peer metadata (domain, endpoint, status, capabilities_hash)
- Tracks peer status (Active, Unreachable, Suspended)

### Gossip Messages

Four message types are exchanged:
- `policy_hash` – Protocol version + ruleset configuration hashes
- `reputation_summary` – Aggregate reputation scores per ruleset
- `tribunal_decision` – Tribunal case outcomes (with privacy-preserving subject hashes)
- `handshake` – Initial peer capability exchange

### Federation Endpoints

#### List Federation Peers

```bash
curl "http://localhost:8070/v1/federation/peers?limit=50"
```

Returns:
```json
{
  "peers": [
    {
      "id": "...",
      "domain": "ns.example.com",
      "endpoint": "https://ns.example.com",
      "status": "active",
      "capabilities_hash": "blake3_hash...",
      "discovered_at": "2025-10-29T00:00:00Z",
      "last_seen_at": "2025-10-29T12:34:56Z"
    }
  ],
  "count": 1
}
```

#### Receive Gossip Message

```bash
curl -X POST http://localhost:8070/v1/federation/gossip \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "id": "...",
      "kind": "policy_hash",
      "from_peer": "ns.example.com",
      "payload": { ... },
      "timestamp": "2025-10-29T12:34:56Z"
    }
  }'
```

#### List Policy Hashes

```bash
curl "http://localhost:8070/v1/federation/policy?limit=50"
```

Returns policy hashes exchanged with peers:
```json
{
  "policies": [
    {
      "domain": "ns.example.com",
      "policy_version": "v1",
      "policy_hash": "blake3_hash...",
      "rulesets": ["high-sec", "partner-qa"],
      "capabilities_url": "https://ns.example.com/.well-known/jig-ns/capabilities",
      "timestamp": "2025-10-29T12:34:56Z"
    }
  ],
  "count": 1
}
```

### Privacy & Security

- **No PII in gossip** – Reputation summaries aggregate scores without identifiable information
- **Subject hashing** – Tribunal decisions use BLAKE3 hashes of subject IDs
- **Capability verification** – Peers verify protocol compatibility via capabilities hashes
- **Status tracking** – Unreachable peers are marked and excluded from gossip rounds

### Integration with Transparency Log

Federation gossip messages are stored in the transparency log, providing an auditable record of all inter-nameserver coordination.

## Running Locally

```bash
# With default in-memory storage
cargo run -p jig-nameserver

# Using a specific config profile
JIG_CONFIG=./examples/config/profile_potato.toml cargo run -p jig-nameserver
```

## Tests

We use `cargo nextest` for speed and isolation:

```bash
cargo nextest run -p jig-nameserver
```

Integration tests under `src/server.rs` cover alias minting, reputation flow, and tribunal flow. Use `cargo test -p jig-nameserver server::tests::tribunal_case_flow` to focus on tribunal logic.

## Further Reading

- [`examples/requests/`](examples/requests/) – interactive payloads for reputation + tribunal APIs.
- [`src/config.rs`](src/config.rs) – loader that merges profiles + env.
- [`executable-internet-master-plan/implementation/repos/jig-nameserver.md`](../executable-internet-master-plan/implementation/repos/jig-nameserver.md) – roadmap/tasks.
- [`QUICK_NOTE_ON_REPUTATION_COMPATIBILITY.md`](QUICK_NOTE_ON_REPUTATION_COMPATIBILITY.md) – design principles for decentralized reputation.
