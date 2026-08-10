use std::collections::BTreeMap;

use cid::Cid;
use jig_core::receipt::{
    BlockReceipt, Counters as CoreCounters, HashAlgorithms, Limits as CoreLimits,
    Outcome as CoreOutcome, OutcomeStatus, Timings as CoreTimings,
};
use multihash_codetable::{Code, MultihashDigest};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::api::Outcome;
use crate::error::{Result, RuntimeError};

const RAW_CODEC: u64 = 0x55;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ExecutionOutcome {
    #[default]
    Success,
    LimitsExceeded,
    ExecutionFailed,
    ValidationFailed,
}

/// Module hash metadata stored alongside the protocol receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleHash {
    pub algorithm: String,
    pub value: String,
}

impl ModuleHash {
    pub fn new(value: impl Into<String>, algorithm: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            algorithm: algorithm.into(),
        }
    }
}

/// Host-side error details that are not part of the canonical receipt payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptError {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Pricing information retained by the runtime (not part of the signed payload).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceiptPricing {
    pub cost_per_fuel_unit: f64,
    pub total_cost: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    pub schedule_version: String,
}

/// Detailed record of a capability call. Stored in runtime metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCall {
    pub capability: String,
    pub operation: String,
    pub fuel_used: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_transferred: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Canonical runtime receipt. Contains a protocol-aligned `BlockReceipt`
/// plus host metadata used for pricing, debugging, or analytics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub block: BlockReceipt,
    pub module_hash: Option<ModuleHash>,
    pub duration_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pricing: Option<ReceiptPricing>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_calls: Vec<CapabilityCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ReceiptError>,
    pub outcome: ExecutionOutcome,
}

impl Receipt {
    pub fn builder() -> ReceiptBuilder {
        ReceiptBuilder::new()
    }

    /// Serialize the protocol section (BlockReceipt) into canonical JSON bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.block.to_canonical_bytes().map_err(RuntimeError::from)
    }

    /// Produce the payload that must be signed by hosts.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        self.block.signing_payload().map_err(RuntimeError::from)
    }

    /// Convenience getter for outcome status.
    pub fn outcome_status(&self) -> OutcomeStatus {
        self.block
            .outcome
            .as_ref()
            .map(|o| o.status.clone())
            .unwrap_or_default()
    }

    /// Convenience getter for fuel used.
    pub fn fuel_used(&self) -> u64 {
        self.block.fuel_used
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(RuntimeError::from)
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(RuntimeError::from)
    }
}

/// Builder used by the runtime to assemble canonical receipts
/// while preserving host metadata.
#[derive(Debug, Default)]
pub struct ReceiptBuilder {
    block_id: Option<Cid>,
    receipt_schema_version: Option<String>,
    host: Option<String>,
    executed_at: Option<OffsetDateTime>,
    render_hash: Option<String>,
    renders_match: Option<bool>,
    fuel_used: Option<u64>,
    memory_peak_mb: Option<u32>,
    counters: Option<CoreCounters>,
    timings: Option<CoreTimings>,
    limits: Option<CoreLimits>,
    outcome: Option<CoreOutcome>,
    hash_algorithms: Option<HashAlgorithms>,
    capabilities_used: Vec<String>,
    attestations: Vec<String>,
    metadata: BTreeMap<String, serde_json::Value>,
    module_hash: Option<ModuleHash>,
    duration_ns: Option<u64>,
    pricing: Option<ReceiptPricing>,
    capability_calls: Vec<CapabilityCall>,
    error: Option<ReceiptError>,
    legacy_outcome: ExecutionOutcome,
}

impl ReceiptBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn block_id(mut self, block_id: Cid) -> Self {
        self.block_id = Some(block_id);
        self
    }

    pub fn block_id_from_str(mut self, block_id: &str) -> Result<Self> {
        let cid: Cid = block_id
            .parse()
            .map_err(|e| RuntimeError::ValidationError(format!("invalid block id: {e}")))?;
        self.block_id = Some(cid);
        Ok(self)
    }

    pub fn block_id_from_wasm(mut self, wasm_bytes: &[u8]) -> Self {
        let module_hash = blake3::hash(wasm_bytes);
        let mh = Code::Blake3_256.digest(module_hash.as_bytes());
        let cid = Cid::new_v1(RAW_CODEC, mh);
        self.block_id = Some(cid);
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

    pub fn render_hash(mut self, hash: impl Into<String>) -> Self {
        self.render_hash = Some(hash.into());
        self
    }

    pub fn renders_match(mut self, renders_match: bool) -> Self {
        self.renders_match = Some(renders_match);
        self
    }

    pub fn fuel_used(mut self, fuel: u64) -> Self {
        self.fuel_used = Some(fuel);
        self
    }

    pub fn memory_peak_mb(mut self, peak: u32) -> Self {
        self.memory_peak_mb = Some(peak);
        self
    }

    pub fn counters(mut self, counters: CoreCounters) -> Self {
        self.counters = Some(counters);
        self
    }

    pub fn timings(mut self, timings: CoreTimings) -> Self {
        self.timings = Some(timings);
        self
    }

    pub fn limits(mut self, limits: CoreLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    pub fn outcome(mut self, outcome: CoreOutcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    pub fn legacy_outcome(mut self, outcome: ExecutionOutcome) -> Self {
        self.legacy_outcome = outcome;
        self
    }

    pub fn hash_algorithms(mut self, hash_algorithms: HashAlgorithms) -> Self {
        self.hash_algorithms = Some(hash_algorithms);
        self
    }

    pub fn capability(mut self, capability: impl Into<String>) -> Self {
        self.capabilities_used.push(capability.into());
        self
    }

    pub fn attestation(mut self, attestation: impl Into<String>) -> Self {
        self.attestations.push(attestation.into());
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    pub fn module_hash(mut self, module_hash: ModuleHash) -> Self {
        self.module_hash = Some(module_hash);
        self
    }

    pub fn execution_duration_ns(mut self, duration: u64) -> Self {
        self.duration_ns = Some(duration);
        self
    }

    pub fn duration_ns(mut self, duration: u64) -> Self {
        self.duration_ns = Some(duration);
        self
    }

    pub fn pricing(mut self, pricing: ReceiptPricing) -> Self {
        self.pricing = Some(pricing);
        self
    }

    pub fn capability_call(mut self, call: CapabilityCall) -> Self {
        self.capability_calls.push(call);
        self
    }

    pub fn error(mut self, code: impl Into<String>, message: Option<String>) -> Self {
        self.error = Some(ReceiptError {
            code: code.into(),
            message,
        });
        self
    }

    pub fn build(self) -> Result<Receipt> {
        let block_id = self
            .block_id
            .ok_or_else(|| RuntimeError::ValidationError("block_id required for receipt".into()))?;

        let host = self
            .host
            .ok_or_else(|| RuntimeError::ValidationError("host required for receipt".into()))?;

        let render_hash = self.render_hash.ok_or_else(|| {
            RuntimeError::ValidationError("render_hash required for receipt".into())
        })?;

        let fuel_used = self.fuel_used.ok_or_else(|| {
            RuntimeError::ValidationError("fuel_used required for receipt".into())
        })?;

        let mut builder = BlockReceipt::builder(block_id)
            .host(host)
            .render_hash(render_hash)
            .fuel_used(fuel_used);

        if let Some(version) = self.receipt_schema_version {
            builder = builder.receipt_schema_version(version);
        }

        if let Some(executed_at) = self.executed_at {
            builder = builder.executed_at(executed_at);
        }

        if let Some(memory_peak_mb) = self.memory_peak_mb {
            builder = builder.memory_peak_mb(memory_peak_mb);
        }

        if let Some(renders_match) = self.renders_match {
            builder = builder.renders_match(renders_match);
        }

        if let Some(counters) = self.counters {
            builder = builder.counters(counters);
        }

        if let Some(timings) = self.timings {
            builder = builder.timings(timings);
        }

        if let Some(limits) = self.limits {
            builder = builder.limits(limits);
        }

        if let Some(outcome) = self.outcome {
            builder = builder.outcome(outcome);
        }

        if let Some(hash_algorithms) = self.hash_algorithms {
            builder = builder.hash_algorithms(hash_algorithms);
        }

        for capability in self.capabilities_used {
            builder = builder.capability(capability);
        }

        for attestation in self.attestations {
            builder = builder.attestation(attestation);
        }

        for (key, value) in self.metadata {
            builder = builder.metadata(key, value);
        }

        let block = builder.build().map_err(RuntimeError::from)?;

        Ok(Receipt {
            block,
            module_hash: self.module_hash,
            duration_ns: self.duration_ns.unwrap_or_default(),
            pricing: self.pricing,
            capability_calls: self.capability_calls,
            error: self.error,
            outcome: self.legacy_outcome,
        })
    }
}

impl From<&Outcome> for CoreOutcome {
    fn from(outcome: &Outcome) -> Self {
        match outcome {
            Outcome::Success => CoreOutcome {
                status: OutcomeStatus::Ok,
                affordances: vec![],
                reason: None,
            },
            Outcome::SoftFailure { reason } => CoreOutcome {
                status: OutcomeStatus::SoftFail,
                affordances: vec![],
                reason: Some(reason.clone()),
            },
            Outcome::HardFailure { reason } => CoreOutcome {
                status: OutcomeStatus::HardFail,
                affordances: vec![],
                reason: Some(reason.clone()),
            },
        }
    }
}

#[cfg(test)]
mod cid_stability_tests {
    use super::*;

    /// The runtime derives a block's content address independently of
    /// `jig-core`, so it needs its own golden. A change here re-addresses every
    /// receipt the runtime has ever emitted: treat a diff as a protocol break,
    /// not as a stale expectation.
    #[test]
    fn block_id_from_wasm_is_stable() {
        let wasm = b"\0asm\x01\0\0\0";
        let builder = ReceiptBuilder::new().block_id_from_wasm(wasm);
        let cid = builder.block_id.expect("block id");

        assert_eq!(
            cid.to_string(),
            "bafkr4ifdheemyqqvtlplr7imjw225dc5r5ihwagwfjdj3alaglfc4am76e"
        );
        assert_eq!(cid.version(), cid::Version::V1);
        assert_eq!(cid.codec(), RAW_CODEC);
        // blake3 multihash code, 32-byte digest.
        assert_eq!(cid.hash().code(), 0x1e);
        assert_eq!(cid.hash().size(), 32);
        // The multihash commits to blake3(module_hash), where the module hash
        // is itself blake3 over the wasm bytes.
        let module_hash = blake3::hash(wasm.as_slice());
        assert_eq!(
            cid.hash().digest(),
            blake3::hash(module_hash.as_bytes()).as_bytes()
        );
    }

    #[test]
    fn block_id_from_str_round_trips() {
        let golden = "bafkreigh2akiscaildcw453u6enm6kdwy5cae2f5z5ky3g4zz6p3r6jwhu";
        let builder = ReceiptBuilder::new()
            .block_id_from_str(golden)
            .expect("parse");
        assert_eq!(builder.block_id.expect("block id").to_string(), golden);
    }
}
