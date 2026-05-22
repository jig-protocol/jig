//! Block execution receipts (protocol-level).
//!
//! ## Architecture: Why No Pricing Fields?
//!
//! `BlockReceipt` is intentionally **pricing-neutral** for these reasons:
//!
//! 1. **Protocol Stability**: Receipts are the wire format for federation and attestation.
//!    Different pricing models shouldn't break protocol compatibility.
//!
//! 2. **Policy Flexibility**: Servers apply their own pricing policies.
//!    The protocol doesn't dictate economic models.
//!
//! 3. **Layered Design**:
//!    - `jig-core::BlockReceipt` = Protocol-level (what gets signed/federated)
//!    - `jig-runtime::Receipt` = Execution-level (includes optional pricing)
//!    - Servers convert runtime receipts → BlockReceipts for protocol operations
//!    - Pricing stored in `metadata` field for flexibility
//!
//! 4. **Cross-Domain Federation**: Receipts can cross pricing boundaries without
//!    schema conflicts or forced conversions.
//!
//! See `jig-runtime/README.md` for the full architectural rationale.

use cid::Cid;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::BTreeMap;
use time::OffsetDateTime;

use crate::capability_scope::{
    CAPABILITY_SCOPE_SEPARATOR, CapabilityScopePattern, CapabilityUsageKey,
};
use crate::error::{JigError, Result};
use crate::manifest::BlockManifest;
use crate::serde_helpers::{deserialize_cid, serialize_cid, to_canonical_json_bytes};

/// Current receipt schema version stamped on serialized receipts.
pub const RECEIPT_SCHEMA_VERSION: &str = "0.2";

const DEFAULT_RENDER_HASH_ALG: &str = "sha256";
const DEFAULT_BLOCK_ID_HASH_ALG: &str = "blake3-256";
pub const RECEIPT_METADATA_CLOCK_SOURCE: &str = "timing.clock_source";

fn default_receipt_schema_version() -> String {
    RECEIPT_SCHEMA_VERSION.to_string()
}

/// Outcome status for block execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeStatus {
    #[default]
    Ok,
    SoftFail,
    HardFail,
}

/// Execution outcome with optional affordances.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Outcome {
    pub status: OutcomeStatus,
    #[serde(default)]
    pub affordances: Vec<String>,
    #[serde(default)]
    pub reason: Option<ReasonCode>,
}

/// Enumerated machine-readable reason codes for non-OK outcomes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    NetTimeout,
    Upstream5xx,
    CapabilityDenied,
    ManifestInvalid,
    NonDeterminismDetected,
    RenderMismatch,
    RuntimeTimeout,
    RuntimeTrap,
    FuelExhausted,
    MemoryLimitExceeded,
    TableLimitExceeded,
    HostPanic,
    Unknown,
}

/// Execution counters for metering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Counters {
    pub fuel_total: u64,
    #[serde(default)]
    pub fuel_by_capability: BTreeMap<String, u64>,
    #[serde(default)]
    pub status_by_capability: BTreeMap<String, BTreeMap<String, u64>>,
    #[serde(default)]
    pub bytes_tx: u64,
    #[serde(default)]
    pub bytes_rx: u64,
    #[serde(default)]
    pub syscalls: u64,
}

impl Counters {
    pub fn builder() -> CountersBuilder {
        CountersBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct CountersBuilder {
    fuel_total: u64,
    fuel_by_capability: BTreeMap<String, u64>,
    status_by_capability: BTreeMap<String, BTreeMap<String, u64>>,
    bytes_tx: u64,
    bytes_rx: u64,
    syscalls: u64,
}

impl CountersBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fuel_total(mut self, total: u64) -> Self {
        self.fuel_total = total;
        self
    }

    pub fn add_fuel(mut self, usage: &CapabilityUsageKey, amount: u64) -> Self {
        let entry = self
            .fuel_by_capability
            .entry(usage.to_canonical_string())
            .or_insert(0);
        *entry = entry.saturating_add(amount);
        self
    }

    pub fn add_status(mut self, usage: &CapabilityUsageKey, status: &str) -> Self {
        let cap_key = usage.to_canonical_string();
        let bins = self.status_by_capability.entry(cap_key).or_default();
        let entry = bins.entry(status.to_ascii_uppercase()).or_insert(0);
        *entry = entry.saturating_add(1);
        self
    }

    pub fn bytes_tx(mut self, bytes: u64) -> Self {
        self.bytes_tx = bytes;
        self
    }

    pub fn bytes_rx(mut self, bytes: u64) -> Self {
        self.bytes_rx = bytes;
        self
    }

    pub fn syscalls(mut self, count: u64) -> Self {
        self.syscalls = count;
        self
    }

    pub fn build(self) -> Counters {
        Counters {
            fuel_total: self.fuel_total,
            fuel_by_capability: self.fuel_by_capability,
            status_by_capability: self.status_by_capability,
            bytes_tx: self.bytes_tx,
            bytes_rx: self.bytes_rx,
            syscalls: self.syscalls,
        }
    }
}

/// Execution timings in milliseconds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Timings {
    #[serde(default)]
    pub queue_wait: u32,
    #[serde(default)]
    pub init: u32,
    pub exec: u32,
    pub total: u32,
}

impl Timings {
    /// Construct timings from queue wait, init, exec using a monotonic clock source.
    pub fn new(queue_wait: u32, init: u32, exec: u32) -> Self {
        Self {
            queue_wait,
            init,
            exec,
            total: init.saturating_add(exec),
        }
    }
}

/// Execution limits snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Limits {
    pub fuel_max: u64,
    pub memory_max_mb: u32,
    pub execution_timeout_ms: u32,
}

/// Hash algorithm metadata for key receipt fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashAlgorithms {
    pub block_id: String,
    pub render_hash: String,
}

impl Default for HashAlgorithms {
    fn default() -> Self {
        Self {
            block_id: DEFAULT_BLOCK_ID_HASH_ALG.to_string(),
            render_hash: DEFAULT_RENDER_HASH_ALG.to_string(),
        }
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockReceipt {
    #[serde(default = "default_receipt_schema_version")]
    pub receipt_schema_version: String,
    #[serde(serialize_with = "serialize_cid", deserialize_with = "deserialize_cid")]
    pub block_id: Cid,
    pub host: String,
    pub executed_at: OffsetDateTime,

    // v0.1 fields
    pub render_hash: String,
    pub fuel_used: u64,
    #[serde(default)]
    pub memory_peak_mb: Option<u32>,

    // v0.2 fields (optional for backwards compat)
    #[serde(default)]
    pub renders_match: Option<bool>,
    #[serde(default)]
    pub counters: Option<Counters>,
    #[serde(default)]
    pub timings_ms: Option<Timings>,
    #[serde(default)]
    pub limits: Option<Limits>,
    #[serde(default)]
    pub outcome: Option<Outcome>,

    #[serde(default)]
    pub hash_algorithms: HashAlgorithms,

    // Capabilities and attestations
    #[serde(default, rename = "capabilities")]
    pub capabilities_used: Vec<String>,
    #[serde(default)]
    pub attestations: Vec<String>,

    // Signature and metadata
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl BlockReceipt {
    pub fn builder(block_id: Cid) -> BlockReceiptBuilder {
        BlockReceiptBuilder::new(block_id)
    }

    /// Serialise the receipt to canonical JSON bytes (stable field order).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        to_canonical_json_bytes(self)
    }

    /// Produce the canonical byte payload that must be signed by hosts.
    ///
    /// Excludes the `signature` and `metadata` fields while keeping all
    /// execution-critical data (`limits`, `timings`, counters, etc.).
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)
            .map_err(|e| JigError::Serialization(format!("receipt to value: {e}")))?;
        if let serde_json::Value::Object(ref mut map) = value {
            map.remove("signature");
            map.remove("metadata");
        }
        to_canonical_json_bytes(&value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.render_hash.is_empty() {
            return Err(JigError::Validation("render_hash cannot be empty".into()));
        }
        if self.receipt_schema_version.is_empty() {
            return Err(JigError::Validation(
                "receipt_schema_version cannot be empty".into(),
            ));
        }
        if self.hash_algorithms.block_id.is_empty() || self.hash_algorithms.render_hash.is_empty() {
            return Err(JigError::Validation(
                "hash_algorithms entries cannot be empty".into(),
            ));
        }

        // v0.2 validation
        if let Some(counters) = &self.counters {
            // Ensure counters.fuel_total matches fuel_used
            if counters.fuel_total != self.fuel_used {
                return Err(JigError::Validation(format!(
                    "counters.fuel_total ({}) must match fuel_used ({})",
                    counters.fuel_total, self.fuel_used
                )));
            }
        }

        if let Some(timings) = &self.timings_ms {
            let expected_total = timings.init.saturating_add(timings.exec);
            if timings.total != expected_total {
                return Err(JigError::Validation(format!(
                    "timings.total ({}) must equal init ({}) + exec ({})",
                    timings.total, timings.init, timings.exec
                )));
            }
        }

        if let Some(outcome) = &self.outcome {
            match outcome.status {
                OutcomeStatus::Ok => {
                    // Ok status may omit reason, but should not include failure reasons
                }
                OutcomeStatus::SoftFail | OutcomeStatus::HardFail => {
                    if !outcome.affordances.is_empty() {
                        return Err(JigError::Validation(
                            "affordances may only be emitted for OutcomeStatus::Ok".into(),
                        ));
                    }
                    if outcome.reason.is_none() {
                        return Err(JigError::Validation(
                            "failure outcomes must include a reason code".into(),
                        ));
                    }
                }
            }
        }

        if let Some(counters) = &self.counters {
            for usage_key in counters.status_by_capability.keys() {
                if !self.capabilities_used.iter().any(|key| key == usage_key) {
                    return Err(JigError::Validation(format!(
                        "status_by_capability contains entry '{usage_key}' not present in capabilities_used"
                    )));
                }
            }

            let sum: u64 = counters.fuel_by_capability.values().copied().sum();
            if sum != counters.fuel_total {
                return Err(JigError::Validation(format!(
                    "counters.fuel_total ({}) must equal sum of fuel_by_capability ({sum})",
                    counters.fuel_total
                )));
            }
        }

        Ok(())
    }

    /// Validate receipt against manifest capabilities.
    ///
    /// Ensures that capabilities_used ⊆ manifest.capabilities
    pub fn validate_against_manifest(&self, manifest: &BlockManifest) -> Result<()> {
        self.validate()?;

        for used_cap in &self.capabilities_used {
            if used_cap.contains(CAPABILITY_SCOPE_SEPARATOR) {
                let usage = CapabilityUsageKey::parse(used_cap)?;
                let capability = manifest
                    .capabilities
                    .iter()
                    .find(|c| c.name == usage.capability)
                    .ok_or_else(|| {
                        JigError::Validation(format!(
                            "receipt uses undeclared capability: {}",
                            usage.capability
                        ))
                    })?;

                let usage_scope = usage.scope.as_ref().ok_or_else(|| {
                    JigError::Validation(format!(
                        "capability '{}' requires scope entry in receipt",
                        capability.name
                    ))
                })?;

                if capability.scope.is_empty() {
                    return Err(JigError::Validation(format!(
                        "capability '{}' has no declared scopes, but receipt recorded scope {}",
                        capability.name, usage_scope
                    )));
                }

                let mut covered = false;
                for scope in &capability.scope {
                    if scope.covers(usage_scope) {
                        covered = true;
                        break;
                    }
                }

                if !covered {
                    return Err(JigError::Validation(format!(
                        "scope {} not covered by manifest capability {}",
                        usage_scope, capability.name
                    )));
                }
            } else {
                let capability = manifest
                    .capabilities
                    .iter()
                    .find(|c| c.name == *used_cap)
                    .ok_or_else(|| {
                        JigError::Validation(format!(
                            "receipt uses undeclared capability: {used_cap}"
                        ))
                    })?;

                if !capability.scope.is_empty() {
                    return Err(JigError::Validation(format!(
                        "capability '{}' requires scoped usage (missing '{}<scope>')",
                        capability.name, CAPABILITY_SCOPE_SEPARATOR
                    )));
                }
            }
        }

        Ok(())
    }
}

pub struct BlockReceiptBuilder {
    block_id: Cid,
    receipt_schema_version: String,
    host: Option<String>,
    executed_at: Option<OffsetDateTime>,

    // v0.1 fields
    render_hash: Option<String>,
    fuel_used: Option<u64>,
    memory_peak_mb: Option<u32>,

    // v0.2 fields
    renders_match: Option<bool>,
    counters: Option<Counters>,
    timings_ms: Option<Timings>,
    limits: Option<Limits>,
    outcome: Option<Outcome>,
    hash_algorithms: HashAlgorithms,

    capabilities_used: Vec<String>,
    attestations: Vec<String>,
    signature: Option<String>,
    metadata: BTreeMap<String, serde_json::Value>,
}

impl BlockReceiptBuilder {
    pub fn new(block_id: Cid) -> Self {
        Self {
            block_id,
            receipt_schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
            host: None,
            executed_at: None,
            render_hash: None,
            fuel_used: None,
            memory_peak_mb: None,
            renders_match: None,
            counters: None,
            timings_ms: None,
            limits: None,
            outcome: None,
            hash_algorithms: HashAlgorithms::default(),
            capabilities_used: Vec::new(),
            attestations: Vec::new(),
            signature: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn render_hash(mut self, hash: impl Into<String>) -> Self {
        self.render_hash = Some(hash.into());
        self
    }

    pub fn fuel_used(mut self, fuel: u64) -> Self {
        self.fuel_used = Some(fuel);
        self
    }

    pub fn memory_peak_mb(mut self, mem: u32) -> Self {
        self.memory_peak_mb = Some(mem);
        self
    }

    pub fn capability(mut self, capability: impl Into<String>) -> Self {
        self.capabilities_used.push(capability.into());
        self
    }

    pub fn capability_with_scope(
        mut self,
        capability: impl Into<String>,
        scope: &CapabilityScopePattern,
    ) -> Self {
        let capability = capability.into();
        let usage =
            CapabilityUsageKey::with_scope(capability.clone(), scope.clone()).to_canonical_string();
        self.capabilities_used.push(usage);
        self
    }

    pub fn receipt_schema_version(mut self, version: impl Into<String>) -> Self {
        self.receipt_schema_version = version.into();
        self
    }

    pub fn hash_algorithms(mut self, hash_algorithms: HashAlgorithms) -> Self {
        self.hash_algorithms = hash_algorithms;
        self
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    pub fn executed_at(mut self, ts: OffsetDateTime) -> Self {
        self.executed_at = Some(ts);
        self
    }

    pub fn signature(mut self, signature: impl Into<String>) -> Self {
        self.signature = Some(signature.into());
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    pub fn clock_source_monotonic(self) -> Self {
        self.metadata(
            RECEIPT_METADATA_CLOCK_SOURCE,
            serde_json::json!("monotonic"),
        )
    }

    // v0.2 builder methods
    pub fn renders_match(mut self, matches: bool) -> Self {
        self.renders_match = Some(matches);
        self
    }

    pub fn counters(mut self, counters: Counters) -> Self {
        self.counters = Some(counters);
        self
    }

    pub fn timings(mut self, timings: Timings) -> Self {
        self.timings_ms = Some(timings);
        self
    }

    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = Some(limits);
        self
    }

    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    pub fn attestation(mut self, attestation: impl Into<String>) -> Self {
        self.attestations.push(attestation.into());
        self
    }

    pub fn build(self) -> Result<BlockReceipt> {
        let receipt = BlockReceipt {
            receipt_schema_version: self.receipt_schema_version,
            block_id: self.block_id,
            host: self
                .host
                .ok_or_else(|| JigError::Validation("receipt host required".into()))?,
            executed_at: self.executed_at.unwrap_or_else(OffsetDateTime::now_utc),
            render_hash: self
                .render_hash
                .ok_or_else(|| JigError::Validation("receipt render_hash required".into()))?,
            fuel_used: self
                .fuel_used
                .ok_or_else(|| JigError::Validation("receipt fuel_used required".into()))?,
            memory_peak_mb: self.memory_peak_mb,
            renders_match: self.renders_match,
            counters: self.counters,
            timings_ms: self.timings_ms,
            limits: self.limits,
            outcome: self.outcome,
            hash_algorithms: self.hash_algorithms,
            capabilities_used: self.capabilities_used,
            attestations: self.attestations,
            signature: self.signature,
            metadata: self.metadata,
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::BlockBundle;
    use crate::capability_scope::{CapabilityScopePattern, CapabilityUsageKey};
    use crate::manifest::{Author, BlockManifest, Capability};
    use semver::Version;
    use serde_json::json;
    use time::OffsetDateTime;

    fn sample_block_id() -> Cid {
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap();

        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &[],
            resources: vec![],
        };
        bundle.block_cid().unwrap()
    }

    fn sample_receipt_with_metadata(
        block_id: Cid,
        metadata_entries: &[(&str, &str)],
    ) -> BlockReceipt {
        let executed_at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let mut builder = BlockReceipt::builder(block_id)
            .host("did:jig:server:test")
            .executed_at(executed_at)
            .render_hash("sha256:deadbeef")
            .fuel_used(1234);

        for (key, value) in metadata_entries {
            builder = builder.metadata(*key, json!(*value));
        }

        builder.build().unwrap()
    }

    #[test]
    fn signing_payload_excludes_signature_and_metadata() {
        let block_id = sample_block_id();
        let executed_at = OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap();

        let receipt = BlockReceipt::builder(block_id)
            .host("did:jig:server:test")
            .executed_at(executed_at)
            .render_hash("sha256:cafebabe")
            .fuel_used(42)
            .metadata("transport", json!("irc"))
            .metadata("trace", json!("abcd"))
            .signature("sig:deadbeef")
            .build()
            .unwrap();

        let payload = receipt.signing_payload().unwrap();
        let payload_str = String::from_utf8(payload).unwrap();
        assert!(payload_str.contains("\"receipt_schema_version\":\"0.2\""));
        assert!(payload_str.contains("\"hash_algorithms\""));
        assert!(!payload_str.contains("\"signature\""));
        assert!(!payload_str.contains("\"metadata\""));
        // Limits should not be stripped if present (ensure core fields remain)
        assert!(payload_str.contains("\"render_hash\""));
    }

    #[test]
    fn canonical_bytes_are_stable_regardless_of_metadata_order() {
        let block_id = sample_block_id();
        let receipt_a = sample_receipt_with_metadata(block_id, &[("alpha", "1"), ("beta", "2")]);
        let receipt_b = sample_receipt_with_metadata(block_id, &[("beta", "2"), ("alpha", "1")]);

        let bytes_a = receipt_a.to_canonical_bytes().unwrap();
        let bytes_b = receipt_b.to_canonical_bytes().unwrap();
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn hash_algorithms_default_values_present() {
        let block_id = sample_block_id();
        let receipt = BlockReceipt::builder(block_id)
            .host("did:jig:server:test")
            .render_hash("sha256:abcd")
            .fuel_used(1)
            .build()
            .unwrap();

        assert_eq!(receipt.hash_algorithms.block_id, DEFAULT_BLOCK_ID_HASH_ALG);
        assert_eq!(receipt.hash_algorithms.render_hash, DEFAULT_RENDER_HASH_ALG);
    }

    #[test]
    fn manifest_scope_covers_receipt_usage() {
        let scope = CapabilityScopePattern::parse("https://api.example.com/orders/*").unwrap();

        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .capability(Capability {
                name: "net:http:fetch".into(),
                scope: vec![scope.clone()],
                fuel: None,
                attestations: vec![],
                metadata: BTreeMap::new(),
            })
            .build()
            .unwrap();

        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &[],
            resources: vec![],
        };
        let block_id = bundle.block_cid().unwrap();

        let request_scope =
            CapabilityScopePattern::parse("https://api.example.com/orders/123").unwrap();

        let receipt = BlockReceipt::builder(block_id)
            .host("did:jig:server:test")
            .render_hash("sha256:abcd")
            .fuel_used(10)
            .capability_with_scope("net:http:fetch", &request_scope)
            .build()
            .unwrap();

        assert!(receipt.validate_against_manifest(&manifest).is_ok());
    }

    #[test]
    fn failure_requires_reason_code() {
        let block_id = sample_block_id();
        let receipt = BlockReceipt::builder(block_id)
            .host("did:jig:server:test")
            .render_hash("sha256:abcd")
            .fuel_used(10)
            .outcome(Outcome {
                status: OutcomeStatus::HardFail,
                affordances: vec![],
                reason: None,
            })
            .build();

        assert!(receipt.is_err());

        let receipt_ok = BlockReceipt::builder(sample_block_id())
            .host("did:jig:server:test")
            .render_hash("sha256:abcd")
            .fuel_used(10)
            .outcome(Outcome {
                status: OutcomeStatus::HardFail,
                affordances: vec![],
                reason: Some(ReasonCode::CapabilityDenied),
            })
            .build()
            .unwrap();
        assert_eq!(
            receipt_ok.outcome.as_ref().unwrap().reason.clone().unwrap(),
            ReasonCode::CapabilityDenied
        );
    }

    #[test]
    fn status_by_capability_keys_must_be_in_capabilities_used() {
        let block_id = sample_block_id();
        let usage = CapabilityUsageKey::without_scope("core:compute");

        let counters = CountersBuilder::new()
            .fuel_total(1)
            .add_status(&usage, "ok")
            .build();

        // Note: we intentionally do NOT add the capability to capabilities_used
        let result = BlockReceipt::builder(block_id)
            .host("did:jig:server:test")
            .render_hash("sha256:abcd")
            .fuel_used(1)
            .counters(counters)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn fuel_by_capability_sum_must_equal_fuel_total() {
        let block_id = sample_block_id();
        let usage = CapabilityUsageKey::without_scope("core:compute");

        // fuel_total is 10 but sum of per-capability fuel is 7
        let counters = CountersBuilder::new()
            .fuel_total(10)
            .add_fuel(&usage, 7)
            .build();

        let result = BlockReceipt::builder(block_id)
            .host("did:jig:server:test")
            .render_hash("sha256:abcd")
            .fuel_used(10)
            .counters(counters)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn timings_total_must_equal_init_plus_exec() {
        let block_id = sample_block_id();
        let invalid_timings = Timings {
            queue_wait: 1,
            init: 2,
            exec: 3,
            total: 10, // incorrect on purpose
        };

        let receipt = BlockReceipt::builder(block_id)
            .host("did:jig:server:test")
            .render_hash("sha256:abcd")
            .fuel_used(1)
            .timings(invalid_timings)
            .build();

        assert!(receipt.is_err());
    }

    #[test]
    fn clock_source_metadata_helper_sets_key() {
        let block_id = sample_block_id();
        let receipt = BlockReceipt::builder(block_id)
            .host("did:jig:server:test")
            .render_hash("sha256:abcd")
            .fuel_used(1)
            .clock_source_monotonic()
            .build()
            .unwrap();

        assert_eq!(
            receipt
                .metadata
                .get(RECEIPT_METADATA_CLOCK_SOURCE)
                .and_then(|v| v.as_str()),
            Some("monotonic")
        );
    }

    #[test]
    fn failure_outcome_with_affordances_is_rejected() {
        let block_id = sample_block_id();
        let result = BlockReceipt::builder(block_id)
            .host("did:jig:server:test")
            .render_hash("sha256:abcd")
            .fuel_used(10)
            .outcome(Outcome {
                status: OutcomeStatus::HardFail,
                affordances: vec!["email.delivered".into()],
                reason: Some(ReasonCode::CapabilityDenied),
            })
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn counters_add_status_uppercases_status_key() {
        let block_id = sample_block_id();
        let usage = CapabilityUsageKey::without_scope("core:compute");

        let counters = CountersBuilder::new()
            .fuel_total(1)
            .add_fuel(&usage, 1)
            .add_status(&usage, "ok")
            .build();

        let receipt = BlockReceipt::builder(block_id)
            .host("did:jig:server:test")
            .render_hash("sha256:abcd")
            .fuel_used(1)
            .counters(counters)
            .capability("core:compute")
            .build()
            .unwrap();

        let counters = receipt.counters.as_ref().unwrap();
        let bins = counters
            .status_by_capability
            .get("core:compute")
            .expect("bins for capability");
        assert!(bins.contains_key("OK"));
    }

    #[test]
    fn timings_new_sets_total_to_init_plus_exec_saturating() {
        let cases: &[(u32, u32, u32)] = &[
            (0, 0, 0),
            (0, 3, 7),
            (5, 12, 34),
            (42, u32::MAX, 1),
            (1, u32::MAX - 10, 20),
        ];
        for &(queue, init, exec) in cases {
            let t = Timings::new(queue, init, exec);
            assert_eq!(t.total, init.saturating_add(exec));
            assert_eq!(t.queue_wait, queue);
            assert_eq!(t.init, init);
            assert_eq!(t.exec, exec);
        }
    }

    #[test]
    fn empty_hash_algorithms_fields_are_rejected() {
        let block_id = sample_block_id();
        let result = BlockReceipt::builder(block_id)
            .host("did:jig:server:test")
            .render_hash("sha256:abcd")
            .fuel_used(1)
            .hash_algorithms(HashAlgorithms {
                block_id: "".into(),
                render_hash: "".into(),
            })
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn canonical_bytes_stable_for_counter_maps_insertion_order() {
        let block_id_a = sample_block_id();
        let block_id_b = sample_block_id();

        let mut counters_a = CountersBuilder::new()
            .fuel_total(100)
            .bytes_tx(1)
            .bytes_rx(2);
        counters_a = counters_a.add_fuel(&CapabilityUsageKey::without_scope("a"), 60);
        counters_a = counters_a.add_fuel(&CapabilityUsageKey::without_scope("b"), 40);
        counters_a = counters_a
            .add_status(&CapabilityUsageKey::without_scope("a"), "ok")
            .add_status(&CapabilityUsageKey::without_scope("b"), "fail");
        let counters_a = counters_a.build();

        let mut counters_b = CountersBuilder::new()
            .fuel_total(100)
            .bytes_tx(1)
            .bytes_rx(2);
        counters_b = counters_b.add_fuel(&CapabilityUsageKey::without_scope("b"), 40);
        counters_b = counters_b.add_fuel(&CapabilityUsageKey::without_scope("a"), 60);
        counters_b = counters_b
            .add_status(&CapabilityUsageKey::without_scope("b"), "fail")
            .add_status(&CapabilityUsageKey::without_scope("a"), "ok");
        let counters_b = counters_b.build();

        let executed_at = OffsetDateTime::from_unix_timestamp(1_700_000_200).unwrap();

        let receipt_a = BlockReceipt::builder(block_id_a)
            .host("did:jig:server:test")
            .executed_at(executed_at)
            .render_hash("sha256:abcd")
            .fuel_used(100)
            .counters(counters_a)
            .capability("a")
            .capability("b")
            .build()
            .unwrap();

        let receipt_b = BlockReceipt::builder(block_id_b)
            .host("did:jig:server:test")
            .executed_at(executed_at)
            .render_hash("sha256:abcd")
            .fuel_used(100)
            .counters(counters_b)
            .capability("a")
            .capability("b")
            .build()
            .unwrap();

        let bytes_a = receipt_a.to_canonical_bytes().unwrap();
        let bytes_b = receipt_b.to_canonical_bytes().unwrap();
        assert_eq!(bytes_a, bytes_b);
    }
}
