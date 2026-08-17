use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::error::{JigError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BlockSignature {
    /// Pure ed25519 signature (primarily for testing / small deployments).
    Ed25519 {
        public_key: String,
        signature: String,
    },

    /// Sigstore bundle encoded as base64 DSSE (expected default for production).
    Sigstore { bundle: String },
}

impl BlockSignature {
    pub fn ed25519(public_key: &[u8], signature: &[u8]) -> Self {
        Self::Ed25519 {
            public_key: STANDARD.encode(public_key),
            signature: STANDARD.encode(signature),
        }
    }

    pub fn sigstore(bundle_bytes: &[u8]) -> Self {
        Self::Sigstore {
            bundle: STANDARD.encode(bundle_bytes),
        }
    }

    pub fn verify(&self, data: &[u8]) -> Result<()> {
        match self {
            BlockSignature::Ed25519 {
                public_key,
                signature,
            } => verify_ed25519(public_key, signature, data),
            BlockSignature::Sigstore { bundle } => verify_sigstore(bundle, data),
        }
    }
}

#[cfg(feature = "ed25519")]
fn verify_ed25519(public_key_b64: &str, signature_b64: &str, data: &[u8]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let public_key = STANDARD
        .decode(public_key_b64)
        .map_err(|e| JigError::Signing(format!("invalid base64 public key: {e}")))?;
    let signature = STANDARD
        .decode(signature_b64)
        .map_err(|e| JigError::Signing(format!("invalid base64 signature: {e}")))?;

    let verifying_key = VerifyingKey::from_bytes(
        public_key
            .as_slice()
            .try_into()
            .map_err(|_| JigError::Signing("public key must be 32 bytes for ed25519".into()))?,
    )
    .map_err(|e| JigError::Signing(format!("invalid ed25519 public key: {e}")))?;

    let sig = Signature::from_slice(&signature)
        .map_err(|e| JigError::Signing(format!("invalid signature: {e}")))?;
    verifying_key
        .verify(data, &sig)
        .map_err(|e| JigError::Signing(format!("ed25519 verification failed: {e}")))
}

#[cfg(not(feature = "ed25519"))]
fn verify_ed25519(_public_key_b64: &str, _signature_b64: &str, _data: &[u8]) -> Result<()> {
    Err(JigError::Signing(
        "ed25519 support not compiled in (enable `ed25519` feature)".into(),
    ))
}

/// Sigstore verification is not implemented. Always an error.
///
/// There used to be a `sigstore`-feature arm here that decoded the bundle,
/// checked it parsed, and returned `Ok(())` with a TODO about wiring up rekor,
/// fulcio and TUF. Nothing enabled the feature, so every build already took the
/// error path — but had anyone switched it on they would have got a function that
/// *looked* like signature verification and in fact accepted any well-formed
/// bundle. A verifier that returns `Ok` without verifying is worse than one that
/// refuses.
///
/// The `sigstore` dependency is dropped with it (YAGNI): it was the sole source of
/// `ring` 0.16 plus `openidconnect` 2.5.1, `picky` 7.0.0-rc.4, `tough` 0.12.5 and
/// `x509-parser` 0.14.0 — none compiled into anything shipped, all scanned by
/// `cargo deny`. Re-add it, deliberately and with real verification, when keyless
/// signing is actually being built.
///
/// The [`BlockSignature::Sigstore`] variant stays: it is part of the wire format,
/// and a block arriving with one must be rejected clearly rather than not parse.
fn verify_sigstore(_bundle_b64: &str, _data: &[u8]) -> Result<()> {
    Err(JigError::Signing(
        "sigstore verification is not implemented in this build".into(),
    ))
}
