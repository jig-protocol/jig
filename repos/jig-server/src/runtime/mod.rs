//! Block execution runtime components.
//!
//! ## Architecture: Receipt Conversion Layer
//!
//! This module bridges `jig-runtime` (execution layer) and `jig-core` (protocol layer):
//!
//! ### Execution Flow:
//! 1. Server configures `ExecutionConfig` with pricing policy (enabled, cost_per_fuel)
//! 2. `BlockRuntime` wraps `jig_runtime::Runtime` with server-specific settings
//! 3. Execution returns `jig_runtime::Receipt` with pricing fields
//! 4. `convert_receipt()` transforms to `jig_core::BlockReceipt` for storage/wire protocol
//!
//! ### Pricing Strategy:
//! - **Source**: `jig_runtime::Receipt.pricing` (ReceiptPricing struct)
//! - **Storage**: Converted to `BlockReceipt.metadata` JSON fields:
//!   - `pricing.cost_per_fuel_unit`
//!   - `pricing.total_cost`
//!   - `pricing.currency`
//!   - `pricing.schedule_version`
//! - **Why metadata?**: Keeps jig-core protocol-neutral, allows pricing evolution
//!
//! ### Long-Term Design:
//! - Database stores `BlockReceipt` (with pricing in metadata)
//! - Billing/analytics queries metadata fields directly
//! - Federation sends `BlockReceipt` (pricing preserved but not enforced)
//! - Different servers can apply different pricing to same execution
//!
//! See `jig-runtime/README.md` and `jig-core/src/receipt.rs` for full rationale.

use cid::Cid;
use jig_core::capability_scope::{CAPABILITY_SCOPE_SEPARATOR, CapabilityUsageKey};
use jig_core::{
    BlockBundle, BlockManifest, BlockReceipt, BlockReceiptBuilder, Counters, Limits, Timings,
};
use jig_runtime::{
    BlockPackage, ExecutionContext, Receipt as JigReceipt, Runtime, RuntimeConfig,
    config::ResourceLimits,
};
use time::OffsetDateTime;

use crate::error::{Result, ServerError};

pub mod outcome;

pub use outcome::{Outcome, OutcomeStatus};

/// Execution tuning knobs loaded from configuration.
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    pub fuel_max: u64,
    pub memory_max_mb: u32,
    pub timeout_ms: u64,
    pub host_id: String,
    pub pricing_enabled: bool,
    pub cost_per_fuel: Option<f64>,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            fuel_max: 5_000_000,
            memory_max_mb: 64,
            timeout_ms: 250,
            host_id: "did:jig:server:local".into(),
            pricing_enabled: false,
            cost_per_fuel: None,
        }
    }
}

/// Wrapper for jig-runtime that integrates with jig-server.
pub struct BlockRuntime {
    runtime: Runtime,
    config: ExecutionConfig,
}

impl BlockRuntime {
    pub fn new(config: ExecutionConfig) -> Result<Self> {
        let mut runtime_config = RuntimeConfig {
            limits: ResourceLimits {
                fuel_max: config.fuel_max,
                memory_max_mb: config.memory_max_mb,
                execution_timeout_ms: config.timeout_ms,
                max_instances: 1, // one instance per execution
                // `..Default::default()` for the rest — notably
                // `max_concurrent_instances`, the engine-wide concurrency
                // ceiling. Spelling every field out here is what let a
                // single-instance cap reach the live server unnoticed; taking
                // the runtime's default means a new limit lands here too.
                ..Default::default()
            },
            ..Default::default()
        };

        // Configure pricing
        if config.pricing_enabled {
            runtime_config.pricing.enabled = true;
            if let Some(cost) = config.cost_per_fuel {
                runtime_config.pricing.cost_per_fuel_unit = cost;
            }
        }

        let runtime = Runtime::with_config(runtime_config)
            .map_err(|e| ServerError::Runtime(format!("failed to create jig-runtime: {e}")))?;

        Ok(Self { runtime, config })
    }

    /// Execute the supplied block bundle using jig-runtime.
    ///
    /// This delegates to jig-runtime for deterministic WASM execution with fuel metering,
    /// pricing calculations, and outcome tracking.
    pub fn execute(
        &self,
        cid: &Cid,
        manifest: &BlockManifest,
        bundle: &BlockBundle<'_>,
    ) -> Result<BlockReceipt> {
        if bundle.code_bytes.is_empty() {
            return self.create_empty_block_receipt(cid, manifest, bundle);
        }

        // Create execution context
        let block_package =
            BlockPackage::from_wasm(bundle.code_bytes.to_vec()).with_id(cid.to_string());

        let mut context = ExecutionContext::default().with_block(block_package);

        // Add capabilities from manifest (allowlist)
        for cap in &manifest.capabilities {
            context = context.with_capability(cap.name.clone());
        }

        // Execute WASM code via jig-runtime
        let jig_receipt = self
            .runtime
            .execute(bundle.code_bytes, context)
            .map_err(|e| ServerError::Runtime(format!("block execution failed: {e}")))?;

        // Start from runtime BlockReceipt and augment host-side fields
        self.finalize_block_receipt(&jig_receipt, manifest, bundle)
    }

    /// Create a minimal receipt for blocks without code.
    fn create_empty_block_receipt(
        &self,
        cid: &Cid,
        manifest: &BlockManifest,
        bundle: &BlockBundle<'_>,
    ) -> Result<BlockReceipt> {
        let render_hash = manifest
            .render
            .as_ref()
            .map(|r| r.expected_hash.clone())
            .unwrap_or_else(|| bundle.root_hash_hex());

        let counters = Counters::builder().fuel_total(0).build();
        let limits = Limits {
            fuel_max: self.config.fuel_max,
            memory_max_mb: self.config.memory_max_mb,
            execution_timeout_ms: self.config.timeout_ms.min(u64::from(u32::MAX)) as u32,
        };
        let timings = Timings {
            queue_wait: 0,
            init: 0,
            exec: 0,
            total: 0,
        };

        let mut builder = BlockReceiptBuilder::new(*cid)
            .host(self.config.host_id.clone())
            .executed_at(OffsetDateTime::now_utc())
            .render_hash(render_hash)
            .fuel_used(0)
            .counters(counters)
            .timings(timings)
            .limits(limits);

        // Include declared capabilities from manifest for validation alignment
        for cap in &manifest.capabilities {
            builder = builder.capability(cap.name.clone());
        }

        builder
            .outcome(jig_core::Outcome {
                status: jig_core::OutcomeStatus::Ok,
                affordances: vec![],
                reason: None,
            })
            .build()
            .map_err(ServerError::from)
    }

    /// Start from jig-runtime Receipt.block and augment host metadata and v0.2 fields.
    fn finalize_block_receipt(
        &self,
        jig_receipt: &JigReceipt,
        manifest: &BlockManifest,
        bundle: &BlockBundle<'_>,
    ) -> Result<BlockReceipt> {
        let base = &jig_receipt.block;

        let mut builder = BlockReceiptBuilder::new(base.block_id)
            .host(base.host.clone())
            .executed_at(base.executed_at)
            .render_hash(base.render_hash.clone())
            .fuel_used(base.fuel_used);

        if let Some(mem) = base.memory_peak_mb {
            builder = builder.memory_peak_mb(mem);
        }

        // Prepare counters/limits/outcome/hash_algorithms (counters may be filtered below)
        let mut counters_opt = base.counters.clone();
        if let Some(ref limits) = base.limits {
            builder = builder.limits(limits.clone());
        }
        if let Some(ref outcome) = base.outcome {
            builder = builder.outcome(outcome.clone());
        }
        builder = builder.hash_algorithms(base.hash_algorithms.clone());

        // Filter capabilities_used to only those declared in the manifest to satisfy
        // validate_against_manifest and avoid engine-internal entries (e.g., "engine.wasm").
        let kept_caps: Vec<String> = base
            .capabilities_used
            .iter()
            .filter(|cap| {
                if cap.contains(CAPABILITY_SCOPE_SEPARATOR) {
                    if let Ok(usage) = CapabilityUsageKey::parse(cap) {
                        manifest
                            .capabilities
                            .iter()
                            .any(|c| c.name == usage.capability)
                    } else {
                        false
                    }
                } else {
                    manifest
                        .capabilities
                        .iter()
                        .any(|c| c.name == **cap && c.scope.is_empty())
                }
            })
            .cloned()
            .collect();

        // Filter status_by_capability bins to only include kept capabilities
        if let Some(ref mut counters) = counters_opt {
            counters.status_by_capability = counters
                .status_by_capability
                .clone()
                .into_iter()
                .filter(|(k, _)| kept_caps.iter().any(|c| c == k))
                .collect();
        }

        // Apply counters after filtering
        if let Some(ref counters) = counters_opt {
            builder = builder.counters(counters.clone());
        }

        // Capabilities and attestations
        for cap in &kept_caps {
            builder = builder.capability(cap.clone());
        }
        for att in &base.attestations {
            builder = builder.attestation(att.clone());
        }

        // Copy metadata and add pricing if present
        for (k, v) in &base.metadata {
            builder = builder.metadata(k.clone(), v.clone());
        }
        if let Some(ref pricing) = jig_receipt.pricing {
            builder = builder
                .metadata(
                    "pricing.cost_per_fuel_unit",
                    serde_json::json!(pricing.cost_per_fuel_unit),
                )
                .metadata("pricing.total_cost", serde_json::json!(pricing.total_cost))
                .metadata("pricing.currency", serde_json::json!(pricing.currency))
                .metadata(
                    "pricing.schedule_version",
                    serde_json::json!(pricing.schedule_version),
                );
        }

        // Compute timings from duration_ns (exec == total; init/queue_wait = 0 for now)
        let exec_ms = (jig_receipt.duration_ns / 1_000_000).min(u32::MAX as u64) as u32;
        let timings = Timings {
            queue_wait: 0,
            init: 0,
            exec: exec_ms,
            total: exec_ms,
        };
        builder = builder.timings(timings);

        // Compute renders_match using module_hash vs manifest.render.expected_hash
        let module_hash = jig_receipt.module_hash.as_ref().map(|m| m.value.clone());
        let expected_render_hash = manifest
            .render
            .as_ref()
            .map(|r| r.expected_hash.clone())
            .unwrap_or_else(|| bundle.root_hash_hex());
        if let Some(actual) = module_hash.as_ref() {
            builder = builder.renders_match(actual == &expected_render_hash);
        }

        let receipt = builder.build().map_err(ServerError::from)?;
        // Validate against manifest for capability usage correctness
        receipt
            .validate_against_manifest(manifest)
            .map_err(ServerError::from)?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::hash;
    use jig_core::manifest::{Author, Capability, RenderDescriptor};
    use semver::Version;

    const SIMPLE_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, // WASM magic
        0x01, 0x00, 0x00, 0x00, // WASM version
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // Type section: [] -> []
        0x03, 0x02, 0x01, 0x00, // Function section
        0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, // Export "main"
        0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // Code section: empty function body
    ];

    const LOOP_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, // WASM magic
        0x01, 0x00, 0x00, 0x00, // WASM version
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // Type: () -> ()
        0x03, 0x02, 0x01, 0x00, // Function section
        0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, // Export "main"
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b, // Code: loop + br
    ];

    fn manifest_with_expected_hash(code_bytes: &[u8]) -> BlockManifest {
        let module_hash = hash(code_bytes).to_hex().to_string();
        BlockManifest::builder()
            .version(Version::new(1, 0, 0))
            .author(Author {
                did: "did:test:author".into(),
                ..Default::default()
            })
            .capability(Capability {
                name: "core:compute".to_string(),
                ..Default::default()
            })
            .render(RenderDescriptor {
                entry: "index.html".to_string(),
                expected_hash: module_hash,
                output_type: "application/wasm".to_string(),
            })
            .build()
            .expect("manifest with expected hash")
    }

    #[test]
    fn augments_pricing_and_timings() {
        let code_bytes = SIMPLE_WASM.to_vec();
        let manifest = manifest_with_expected_hash(&code_bytes);
        let manifest_bytes = manifest
            .to_canonical_bytes()
            .expect("canonical manifest bytes");
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &code_bytes,
            resources: Vec::new(),
        };
        let cid = bundle.block_cid().expect("cid");

        let mut cfg = ExecutionConfig::default();
        cfg.pricing_enabled = true;
        cfg.cost_per_fuel = Some(0.0001);
        let runtime = BlockRuntime::new(cfg).expect("runtime");
        let receipt = runtime.execute(&cid, &manifest, &bundle).expect("receipt");

        assert_eq!(receipt.block_id, cid);
        assert_eq!(receipt.renders_match, Some(true));

        let timings = receipt.timings_ms.expect("timings");
        assert!(timings.total >= timings.exec);

        // Pricing metadata present
        assert!(receipt.metadata.get("pricing.cost_per_fuel_unit").is_some());

        let counters = receipt.counters.expect("counters");
        assert_eq!(counters.fuel_total, receipt.fuel_used);
    }

    #[test]
    fn executes_simple_wasm_and_populates_receipt() {
        let code_bytes = SIMPLE_WASM.to_vec();
        let manifest = manifest_with_expected_hash(&code_bytes);
        let manifest_bytes = manifest
            .to_canonical_bytes()
            .expect("canonical manifest bytes");

        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &code_bytes,
            resources: Vec::new(),
        };
        let cid = bundle.block_cid().expect("cid");

        let runtime = BlockRuntime::new(ExecutionConfig::default()).expect("runtime");
        let receipt = runtime.execute(&cid, &manifest, &bundle).expect("receipt");

        assert_eq!(receipt.block_id, cid);
        let outcome = receipt.outcome.expect("outcome");
        assert_eq!(outcome.status, jig_core::OutcomeStatus::Ok);
        assert_eq!(receipt.renders_match, Some(true));

        let counters = receipt.counters.expect("counters");
        assert_eq!(counters.fuel_total, receipt.fuel_used);
        assert_eq!(counters.bytes_tx, 0);
        assert_eq!(counters.bytes_rx, 0);

        let timings = receipt.timings_ms.expect("timings");
        assert!(timings.exec <= timings.total);
    }

    #[test]
    fn fuel_exhaustion_sets_hard_fail_outcome() {
        let code_bytes = LOOP_WASM.to_vec();
        let manifest = manifest_with_expected_hash(&code_bytes);
        let manifest_bytes = manifest
            .to_canonical_bytes()
            .expect("canonical manifest bytes");

        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &code_bytes,
            resources: Vec::new(),
        };
        let cid = bundle.block_cid().expect("cid");

        let mut config = ExecutionConfig::default();
        config.fuel_max = 100;
        let runtime = BlockRuntime::new(config).expect("runtime");

        let receipt = runtime.execute(&cid, &manifest, &bundle).expect("receipt");

        let outcome = receipt.outcome.expect("outcome");
        assert_eq!(outcome.status, jig_core::OutcomeStatus::HardFail);
        assert!(outcome.reason.is_some());

        let counters = receipt.counters.expect("counters");
        assert_eq!(counters.fuel_total, receipt.fuel_used);
        assert!(receipt.fuel_used <= 100);
    }
}
