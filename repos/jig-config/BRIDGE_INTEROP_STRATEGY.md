# Bridge & Interoperability Configuration Strategy

**Purpose:** Define how jig-config enables bidirectional bridges between Jig's deterministic, metered Wasm block execution and wildly-ambiguous third-party systems (Slack, email, ActivityPub, ATProto, IRC, etc.) while maintaining security, fuel accounting, provenance, and determinism.

**Status:** Design Document - 2025-11-04
**Owner:** jig-config team

---

## The Core Challenge

Jig's architecture provides strong guarantees:
- **Deterministic execution**: Blocks produce identical outputs given identical inputs
- **Fuel accounting**: Every operation is metered and priced
- **Provenance**: Block IDs, receipts, and signatures ensure authorship
- **Security**: Capability-based access control with zero ambient authority
- **E2EE**: Optional end-to-end encryption for sensitive content
- **Reputation**: Identity-based reputation system gates access

**But third-party systems don't:**
- Email: Arbitrary attachments, headers, HTML, spam
- Slack: Rich messages, files, reactions, threads, custom emojis
- ActivityPub: Varied object types, federation quirks, moderation policies
- ATProto: Bluesky-specific schemas, lexicons, content filtering
- IRC: Plain text with no metadata, client-specific formatting

**The question:** How do we bridge these worlds without compromising Jig's guarantees?

---

## Architectural Pattern: The Bridge Sandwich

Every bridge follows a three-layer pattern:

```
┌─────────────────────────────────────────────┐
│ 1. INGEST LAYER (External → Jig)           │
│    - Validate schema                        │
│    - Sanitize content                       │
│    - Extract metadata                       │
│    - Map to capabilities                    │
└─────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────┐
│ 2. BLOCK LAYER (Jig's deterministic core)  │
│    - Wrap as block manifest                 │
│    - Allocate fuel budget                   │
│    - Generate receipt                       │
│    - Enforce capabilities                   │
└─────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────┐
│ 3. EXPORT LAYER (Jig → External)           │
│    - Render to target format                │
│    - Add provenance metadata                │
│    - Respect privacy constraints            │
│    - Track delivery status                  │
└─────────────────────────────────────────────┘
```

---

## Configuration Schema

### Generic Bridge Configuration

Every bridge type (email, Slack, ActivityPub, etc.) shares this base structure:

```toml
[bridges.<bridge_type>]
enabled = true                     # Master switch
bridge_version = "1.0"             # Bridge schema version

# Ingest Layer Configuration
[bridges.<bridge_type>.ingest]
schema_validation = "strict"       # strict | lenient | disabled
max_content_size_mb = 10           # Reject oversized payloads
allowed_mime_types = [...]         # Allowlist for attachments
sanitization_mode = "aggressive"   # aggressive | moderate | minimal
mark_legacy_source = true          # Tag non-native content

# Block Layer Configuration
[bridges.<bridge_type>.block]
fuel_budget_default = 100_000      # Fuel allocated for block wrapping
fuel_budget_max = 1_000_000        # Hard cap on fuel per bridge operation
default_capabilities = []          # Zero ambient authority
capability_mapping = { ... }       # External actions → Jig capabilities

# Export Layer Configuration
[bridges.<bridge_type>.export]
render_mode = "full"               # full | summary | minimal
include_provenance = true          # Append block CID + signature
include_receipt = false            # Embed receipt in export
privacy_mode = "anonymized"        # full | anonymized | minimal

# Rate Limiting & Reputation
[bridges.<bridge_type>.limits]
rate_limit_per_user = 100          # Operations per hour
rate_limit_global = 10_000         # Global operations per hour
min_reputation_tier = "null_sec"   # null_sec | low_sec | high_sec | verified
require_verified_for_export = false

# Monitoring & Observability
[bridges.<bridge_type>.monitoring]
log_all_ingress = true             # Log incoming content
log_all_egress = true              # Log outgoing renders
track_fuel_usage = true            # Track fuel per bridge operation
alert_on_anomalies = true          # Alert on suspicious patterns
```

---

## Bridge-Specific Examples

### 1. Email Bridge

```toml
[bridges.email]
enabled = true
bridge_version = "1.0"

# Ingest: Email → Jig Block
[bridges.email.ingest]
schema_validation = "strict"
max_content_size_mb = 25           # Standard email limit
allowed_mime_types = [
    "text/plain",
    "text/html",
    "application/pdf",
    "image/jpeg",
    "image/png",
]
sanitization_mode = "aggressive"   # Strip scripts, sanitize HTML
preserve_headers = [
    "from", "to", "subject", "date",
    "message-id", "in-reply-to",
    "dkim-signature", "spf-result",
]
mark_legacy_source = true

# DKIM/SPF validation
[bridges.email.ingest.validation]
enforce_dkim = true
enforce_spf = true
reject_unsigned = false            # Allow unsigned for internal use

# Block wrapping
[bridges.email.block]
fuel_budget_default = 500_000      # Email parsing can be expensive
fuel_budget_max = 5_000_000
default_capabilities = []          # No capabilities by default

# Map email actions to Jig capabilities
[bridges.email.block.capability_mapping]
"send_email" = ["net.smtp", "net.dns"]
"fetch_attachments" = ["net.http"]
"access_contacts" = ["storage.read"]

# Export: Jig Block → Email
[bridges.email.export]
render_mode = "full"
include_provenance = true
include_receipt = false
footer_template = """
---
Secured by Jig Block
Block ID: {{block_id}}
Signature: {{signature}}
"""

# Deliverability analytics
[bridges.email.export.deliverability]
track_opens = false                # Privacy-first default
track_bounces = true
track_replies = true
analytics_backend = "duckdb"       # duckdb | clickhouse

# Rate limiting
[bridges.email.limits]
relay_quota_per_day = 1000
rate_limit_per_user = 100
rate_limit_global = 10_000
min_reputation_tier = "low_sec"    # Require some reputation to prevent spam
require_verified_for_relay = true  # Require verified identity for outbound

# DNS discovery
[bridges.email.dns]
discovery_enabled = true
srv_record_prefix = "_jig._tcp"
txt_record_prefix = "_jig-version"
fallback_to_smtp = true
```

---

### 2. ActivityPub Bridge

```toml
[bridges.activitypub]
enabled = true
bridge_version = "1.0"

# Ingest: ActivityPub Object → Jig Block
[bridges.activitypub.ingest]
schema_validation = "lenient"      # ActivityPub has many variants
max_content_size_mb = 10
allowed_object_types = [
    "Note", "Article", "Image", "Video",
    "Create", "Update", "Delete", "Follow", "Like",
]
sanitization_mode = "moderate"
mark_legacy_source = true

# Federation rules
[bridges.activitypub.ingest.federation]
allowed_instances = []             # Empty = allow all
blocked_instances = [
    "spam.example.com",
    "known-bad-actor.social",
]
require_https = true
verify_signatures = true

# Block wrapping
[bridges.activitypub.block]
fuel_budget_default = 200_000
fuel_budget_max = 2_000_000
default_capabilities = []

[bridges.activitypub.block.capability_mapping]
"create_post" = ["storage.write"]
"fetch_remote" = ["net.http", "net.dns"]
"follow_user" = ["storage.read", "storage.write"]

# Export: Jig Block → ActivityPub Object
[bridges.activitypub.export]
render_mode = "summary"
include_provenance = true
include_receipt = false

# ActivityPub object template
[bridges.activitypub.export.template]
type = "Note"
context = "https://www.w3.org/ns/activitystreams"
attachment_template = ".jigb"      # Attach full block as artifact

# Identity mapping
[bridges.activitypub.identity]
did_to_actor_mapping = true
publish_did_in_profile = true
nameserver_discovery = true

# Rate limiting
[bridges.activitypub.limits]
rate_limit_per_user = 300
rate_limit_global = 50_000
min_reputation_tier = "null_sec"   # Open federation by default
```

---

### 3. Slack Bridge

```toml
[bridges.slack]
enabled = true
bridge_version = "1.0"

# Ingest: Slack Message → Jig Block
[bridges.slack.ingest]
schema_validation = "lenient"      # Slack message format varies
max_content_size_mb = 50           # Slack allows large files
allowed_content_types = [
    "text", "file", "image", "video",
    "reaction", "thread_reply",
]
sanitization_mode = "moderate"
preserve_metadata = [
    "user", "channel", "timestamp",
    "thread_ts", "reactions",
]
mark_legacy_source = true

# Block wrapping
[bridges.slack.block]
fuel_budget_default = 150_000
fuel_budget_max = 1_500_000
default_capabilities = []

[bridges.slack.block.capability_mapping]
"send_message" = ["net.http"]
"upload_file" = ["net.http", "storage.write"]
"read_channel" = ["storage.read"]

# Export: Jig Block → Slack Message
[bridges.slack.export]
render_mode = "full"
include_provenance = false         # Slack users don't care about block IDs
include_receipt = false
use_block_kit = true               # Use Slack Block Kit for rich formatting

# Threading
[bridges.slack.export.threading]
preserve_thread_structure = true
create_thread_per_channel = false

# Rate limiting (Slack has strict rate limits)
[bridges.slack.limits]
rate_limit_per_user = 60           # 1 message per second
rate_limit_global = 1_000
min_reputation_tier = "null_sec"

# OAuth configuration
[bridges.slack.oauth]
client_id = "${SLACK_CLIENT_ID}"
client_secret = "${SLACK_CLIENT_SECRET}"
scopes = [
    "chat:write",
    "channels:read",
    "files:read",
    "users:read",
]
```

---

### 4. AT Protocol (Bluesky) Bridge

```toml
[bridges.atproto]
enabled = true
bridge_version = "1.0"

# Ingest: AT Protocol Record → Jig Block
[bridges.atproto.ingest]
schema_validation = "strict"       # AT Protocol has strict lexicons
max_content_size_mb = 10
allowed_record_types = [
    "app.bsky.feed.post",
    "app.bsky.feed.like",
    "app.bsky.feed.repost",
    "app.bsky.graph.follow",
]
sanitization_mode = "moderate"
mark_legacy_source = true

# Lexicon validation
[bridges.atproto.ingest.lexicon]
validate_against_lexicon = true
allow_unknown_fields = false
enforce_schema_version = true

# Block wrapping
[bridges.atproto.block]
fuel_budget_default = 200_000
fuel_budget_max = 2_000_000
default_capabilities = []

[bridges.atproto.block.capability_mapping]
"create_post" = ["storage.write"]
"fetch_feed" = ["net.http", "net.dns"]
"follow_user" = ["storage.read", "storage.write"]

# Export: Jig Block → AT Protocol Record
[bridges.atproto.export]
render_mode = "summary"
include_provenance = true
include_receipt = false

# AT Protocol record template
[bridges.atproto.export.template]
lexicon = "app.bsky.feed.post"
include_did = true
embed_block_reference = true

# PDS (Personal Data Server) configuration
[bridges.atproto.pds]
endpoint = "https://bsky.social"
did_method = "plc"                 # plc | web
nameserver_mapping = true

# Rate limiting
[bridges.atproto.limits]
rate_limit_per_user = 300
rate_limit_global = 50_000
min_reputation_tier = "null_sec"
```

---

## Sanitization Strategy

Each bridge implements a sanitization pipeline to transform ambiguous external content into deterministic block manifests:

### 1. Schema Validation
- **Strict:** Reject any content that doesn't match expected schema
- **Lenient:** Accept content with extra fields, warn on missing fields
- **Disabled:** Accept any content (dangerous, use with caution)

### 2. Content Sanitization
- **Aggressive:** Strip all potentially dangerous content (scripts, iframes, forms)
- **Moderate:** Allow safe HTML subset, sanitize attributes
- **Minimal:** Only remove obviously malicious content

### 3. Deterministic Transformation
- Normalize timestamps to UTC
- Sort object keys alphabetically
- Canonicalize URLs (lowercase domains, remove tracking params)
- Strip non-deterministic metadata (request IDs, session tokens)
- Hash large binary content and store references

### 4. Capability Mapping
External actions are mapped to Jig capabilities with explicit grants:

```toml
[bridges.<type>.block.capability_mapping]
# External action = [required capabilities]
"send_email" = ["net.smtp", "net.dns"]
"upload_file" = ["storage.write", "net.http"]
"fetch_url" = ["net.http"]
"read_contacts" = ["storage.read"]
```

If a bridge operation requires capabilities not granted, it **fails with clear error**.

---

## Export Format Configuration

Jig blocks can be exported to multiple formats for interoperability:

```toml
[export.yaml]
enabled = true
canonical_format = false           # YAML is not canonical, use for interop only
include_comments = true
include_provenance = true
max_depth = 10                     # Prevent deep nesting

[export.json]
enabled = true
canonical_format = false           # JSON is not canonical (use JCS for that)
pretty_print = true
include_provenance = true
escape_unicode = false

[export.jcs]
enabled = true
canonical_format = true            # JCS is THE canonical JSON format
include_provenance = true
strict_ordering = true

[export.activitypub]
enabled = true
canonical_format = false
context_url = "https://www.w3.org/ns/activitystreams"
include_jig_extensions = true

[export.atproto]
enabled = true
canonical_format = false
lexicon_version = "app.bsky.feed.post"
include_jig_references = true
```

**Key Principle:** TOML is the **source of truth** for configuration. YAML/JSON/ActivityPub/etc. are **generated artifacts** for interoperability, not configuration inputs.

---

## Fuel Budgeting for Bridges

Bridge operations consume fuel from multiple sources:

1. **Ingest Fuel:** Parsing external content, schema validation, sanitization
2. **Block Wrapping Fuel:** Converting sanitized content into block manifest
3. **Export Fuel:** Rendering block to external format

```toml
[bridges.<type>.fuel]
# Fuel allocation per operation
ingest_fuel_default = 50_000
ingest_fuel_max = 500_000

block_wrapping_fuel_default = 100_000
block_wrapping_fuel_max = 1_000_000

export_fuel_default = 50_000
export_fuel_max = 500_000

# Total fuel per bridge operation
total_fuel_max = 2_000_000

# Fuel accounting mode
accounting_mode = "strict"         # strict | lenient | disabled
charge_user_for_bridge_fuel = false  # false = platform absorbs cost
```

---

## Security & Reputation Gating

Bridges can be gated by reputation tier to prevent abuse:

```toml
[bridges.<type>.security]
# Minimum reputation tier to use bridge
min_reputation_tier = "null_sec"   # null_sec | low_sec | high_sec | verified

# Reputation-based rate limits
[bridges.<type>.security.rate_limits_by_tier]
null_sec = 10                      # 10 ops/hour
low_sec = 100                      # 100 ops/hour
high_sec = 1000                    # 1000 ops/hour
verified = 10000                   # 10000 ops/hour

# Require identity verification for certain operations
require_verified_for_outbound = true
require_verified_for_relay = true
require_verified_for_federation = false

# Content filtering
enable_spam_filter = true
enable_content_filter = true
enable_rate_limit_backoff = true
```

---

## Monitoring & Observability

All bridge operations are logged and metered:

```toml
[bridges.<type>.monitoring]
# Logging
log_all_ingress = true             # Log all incoming content
log_all_egress = true              # Log all outgoing renders
log_fuel_usage = true              # Log fuel consumption per operation
log_errors = true                  # Log all errors
log_level = "info"                 # debug | info | warn | error

# Metrics
track_latency = true               # Track p50/p95/p99 latency
track_throughput = true            # Track ops/sec
track_error_rate = true            # Track error %
track_fuel_per_operation = true    # Track fuel usage distribution

# Alerts
alert_on_high_error_rate = true
alert_threshold_error_pct = 5.0
alert_on_fuel_exhaustion = true
alert_on_rate_limit_exceeded = true

# Analytics backend
analytics_backend = "duckdb"       # duckdb | clickhouse
```

---

## Implementation Phases

### Phase 6: Export & Interoperability (Current)
1. Design generic bridge configuration schema
2. Implement `BridgeConfig` base struct
3. Implement export format configuration (YAML, JSON, JCS)
4. Add sanitization rule configuration
5. Add fuel budgeting for bridge operations
6. Add tests for export formats

### Phase 7: Bridge-Specific Configuration
1. Implement `EmailBridgeConfig`
2. Implement `IrcBridgeConfig`
3. Implement `ActivityPubBridgeConfig`
4. Implement `ATProtoBridgeConfig`
5. Implement `SlackBridgeConfig`
6. Add integration tests for each bridge type

---

## Design Principles

1. **Zero Trust:** Bridges start with zero capabilities, must explicitly grant
2. **Sanitize Aggressively:** External content is untrusted until validated
3. **Fail Secure:** Invalid content is rejected, not coerced
4. **Audit Everything:** All bridge operations logged for compliance
5. **Reputation Gates:** High-risk operations require verified identity
6. **Fuel Accounting:** All bridge operations metered and priced
7. **Provenance Always:** Block IDs and signatures preserved across bridges
8. **Privacy First:** PII anonymization enforced for compliant bridges

---

**End of Bridge & Interoperability Strategy**
