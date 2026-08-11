//! Embedded WASM runtime for nameserver block execution
//!
//! Provides on-demand execution of Jig blocks with capability sandboxing,
//! fuel metering, and receipt signing/verification.

use crate::config::RuntimeConfig;
use crate::error::{NameServerError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use jig_core::BlockReceipt;
use jig_runtime::Receipt;
use jig_runtime::api::{BlockPackage, ExecutionContext, Limits, Runtime as JigRuntime};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Nameserver runtime wrapper with restricted capabilities
pub struct NameserverRuntime {
    runtime: JigRuntime,
    config: RuntimeConfig,
    signing_key: Option<SigningKey>,
}

impl NameserverRuntime {
    /// Create a new nameserver runtime with restricted capabilities
    pub fn new(config: RuntimeConfig) -> Result<Self> {
        if !config.enabled {
            return Err(NameServerError::Other(anyhow::anyhow!(
                "Runtime execution is disabled in config"
            )));
        }

        debug!("Initializing nameserver runtime with restricted capabilities");

        // Convert our config to jig-runtime config
        let runtime_config = jig_runtime::config::RuntimeConfig {
            limits: jig_runtime::config::ResourceLimits {
                fuel_max: config.fuel_max,
                memory_max_mb: config.memory_max_mb,
                execution_timeout_ms: config.execution_timeout_ms,
                max_instances: 1, // Single instance per execution
            },
            capabilities: jig_runtime::config::CapabilityConfig {
                allowed: config.allowed_capabilities.clone(),
                ..Default::default()
            },
            engine: jig_runtime::config::EngineConfig {
                deterministic: config.deterministic,
                wasi_preview2: config.wasi_preview2,
                ..Default::default()
            },
            ..Default::default()
        };

        let runtime = JigRuntime::with_config(runtime_config).map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to create runtime: {e}"))
        })?;

        info!(
            fuel_max = config.fuel_max,
            memory_max_mb = config.memory_max_mb,
            capabilities = ?config.allowed_capabilities,
            "Nameserver runtime initialized"
        );

        Ok(Self {
            runtime,
            config,
            signing_key: None,
        })
    }

    /// Set the signing key for outbound receipts
    pub fn with_signing_key(mut self, key: SigningKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Execute a block and return a signed receipt
    ///
    /// # Arguments
    /// * `block_id` - CID of the block (string format)
    /// * `wasm_bytes` - Compiled WASM module bytes
    /// * `author_did` - Optional DID of the block author
    ///
    /// # Returns
    /// Signed receipt with execution metrics and outcome
    pub fn execute_block(
        &self,
        block_id: impl Into<String>,
        wasm_bytes: Vec<u8>,
        author_did: Option<String>,
    ) -> Result<BlockReceipt> {
        let block_id = block_id.into();
        debug!(block_id = %block_id, wasm_size = wasm_bytes.len(), "Executing block");

        // Validate WASM module first
        self.runtime
            .validate_module(&wasm_bytes)
            .map_err(|e| NameServerError::BadRequest(format!("WASM validation failed: {e}")))?;

        // Create block package
        let block = BlockPackage::from_wasm(wasm_bytes.clone())
            .with_id(block_id.clone())
            .with_author(author_did.unwrap_or_else(|| "unknown".into()));

        // Create execution context with restricted capabilities
        let limits = Limits::new(
            self.config.fuel_max,
            self.config.memory_max_mb,
            Duration::from_millis(self.config.execution_timeout_ms),
        );

        let context = ExecutionContext::default()
            .with_block(block)
            .with_limits(limits)
            .with_capabilities(self.config.allowed_capabilities.clone());

        // Execute the block
        let receipt = self
            .runtime
            .execute(&wasm_bytes, context)
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("Block execution failed: {e}")))?;

        // Convert jig_runtime::Receipt to jig_core::BlockReceipt
        let block_receipt = self.convert_receipt(receipt)?;

        // Sign the receipt if we have a signing key
        if let Some(ref key) = self.signing_key {
            self.sign_receipt(block_receipt, key)
        } else {
            warn!("No signing key configured, receipt will be unsigned");
            Ok(block_receipt)
        }
    }

    /// Convert jig_runtime Receipt to jig_core BlockReceipt
    fn convert_receipt(&self, receipt: Receipt) -> Result<BlockReceipt> {
        // The Receipt already contains a BlockReceipt in the `block` field
        // We just extract it and return it
        Ok(receipt.block)
    }

    /// Sign a receipt with Ed25519
    fn sign_receipt(&self, mut receipt: BlockReceipt, key: &SigningKey) -> Result<BlockReceipt> {
        debug!("Signing receipt with Ed25519");

        // Serialize the receipt (excluding signature field)
        let receipt_json = serde_json::to_vec(&receipt).map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to serialize receipt: {e}"))
        })?;

        // Sign the serialized receipt
        let signature = key.sign(&receipt_json);
        let signature_bytes = signature.to_bytes();

        // Store signature in receipt
        receipt.signature = Some(hex::encode(signature_bytes));

        debug!(signature = ?receipt.signature, "Receipt signed");
        Ok(receipt)
    }

    /// Verify a receipt signature
    pub fn verify_receipt_signature(
        receipt: &BlockReceipt,
        public_key: &VerifyingKey,
    ) -> Result<()> {
        let signature_hex = receipt
            .signature
            .as_ref()
            .ok_or_else(|| NameServerError::BadRequest("Receipt has no signature".into()))?;

        // Decode signature
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| NameServerError::BadRequest(format!("Invalid signature hex: {e}")))?;

        let signature = Signature::from_bytes(
            signature_bytes
                .as_slice()
                .try_into()
                .map_err(|_| NameServerError::BadRequest("Invalid signature length".into()))?,
        );

        // Create a copy of the receipt without the signature for verification
        let mut receipt_for_verification = receipt.clone();
        receipt_for_verification.signature = None;

        let receipt_json = serde_json::to_vec(&receipt_for_verification).map_err(|e| {
            NameServerError::Other(anyhow::anyhow!(
                "Failed to serialize receipt for verification: {e}"
            ))
        })?;

        // Verify signature
        public_key.verify(&receipt_json, &signature).map_err(|e| {
            NameServerError::Unauthorized(format!("Signature verification failed: {e}"))
        })?;

        debug!("Receipt signature verified successfully");
        Ok(())
    }

    /// Get runtime configuration
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Check if a capability is allowed
    pub fn is_capability_allowed(&self, capability: &str) -> bool {
        self.config.allowed_capabilities.iter().any(|allowed| {
            // Support wildcard matching (e.g., "storage.read:receipts:*")
            if allowed.ends_with('*') {
                let prefix = &allowed[..allowed.len() - 1];
                capability.starts_with(prefix)
            } else {
                capability == allowed
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_disabled() {
        let config = RuntimeConfig {
            enabled: false,
            ..Default::default()
        };

        let result = NameserverRuntime::new(config);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Runtime execution is disabled"));
        }
    }

    #[test]
    fn test_capability_matching() {
        let config = RuntimeConfig {
            enabled: true,
            allowed_capabilities: vec![
                "storage.read:receipts:*".into(),
                "net.fetch:federation:example.com".into(),
            ],
            ..Default::default()
        };

        let runtime = NameserverRuntime::new(config).expect("Failed to create runtime");

        // Wildcard matching
        assert!(runtime.is_capability_allowed("storage.read:receipts:abc123"));
        assert!(runtime.is_capability_allowed("storage.read:receipts:"));
        assert!(!runtime.is_capability_allowed("storage.write:receipts:abc123"));

        // Exact matching
        assert!(runtime.is_capability_allowed("net.fetch:federation:example.com"));
        assert!(!runtime.is_capability_allowed("net.fetch:federation:evil.com"));
    }

    #[test]
    fn test_signing_key_setup() {
        let config = RuntimeConfig {
            enabled: true,
            ..Default::default()
        };

        let runtime = NameserverRuntime::new(config).expect("Failed to create runtime");

        // Generate a key using from_bytes (ed25519-dalek 2.x API)
        use ed25519_dalek::SigningKey;
        use rand::Rng; // rand 0.10 renamed the `RngCore` trait to `Rng`
        let mut rng = rand::rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);

        let runtime = runtime.with_signing_key(signing_key);
        assert!(runtime.signing_key.is_some());
    }

    #[test]
    fn test_signature_verification_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand::Rng; // rand 0.10 renamed the `RngCore` trait to `Rng`

        // Generate key pair
        let mut rng = rand::rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        // Create a mock receipt
        let receipt = BlockReceipt {
            block_id: cid::Cid::default(),
            host: "test-host".into(),
            executed_at: time::OffsetDateTime::now_utc(),
            render_hash: "test-hash".into(),
            fuel_used: 1000,
            memory_peak_mb: Some(32),
            renders_match: None,
            counters: None,
            timings_ms: None,
            limits: None,
            outcome: None,
            capabilities_used: vec![],
            attestations: vec![],
            signature: None,
            metadata: std::collections::BTreeMap::new(),
            hash_algorithms: jig_core::HashAlgorithms::default(),
            receipt_schema_version: "0.2".into(),
        };

        let config = RuntimeConfig {
            enabled: true,
            ..Default::default()
        };
        let runtime = NameserverRuntime::new(config).expect("Failed to create runtime");

        // Sign the receipt
        let signed_receipt = runtime
            .sign_receipt(receipt, &signing_key)
            .expect("Failed to sign receipt");

        assert!(signed_receipt.signature.is_some());

        // Verify the signature
        let result = NameserverRuntime::verify_receipt_signature(&signed_receipt, &verifying_key);
        assert!(result.is_ok(), "Signature verification should succeed");

        // Verify with wrong key should fail
        let mut wrong_seed = [0u8; 32];
        rng.fill_bytes(&mut wrong_seed);
        let wrong_key = SigningKey::from_bytes(&wrong_seed);
        let wrong_verifying_key = wrong_key.verifying_key();
        let result =
            NameserverRuntime::verify_receipt_signature(&signed_receipt, &wrong_verifying_key);
        assert!(
            result.is_err(),
            "Signature verification with wrong key should fail"
        );
    }
}
