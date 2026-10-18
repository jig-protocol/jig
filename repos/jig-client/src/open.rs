//! Opening a delivered block: decode it, compute its CID, and verify its
//! author's signature.
//!
//! A server relays blocks; it does not vouch for them. The README's claim that
//! "a relaying server cannot forge or silently rewrite what it passes on" is
//! true only for a client that checks — so every block a client shows goes
//! through [`open`] first. A block whose signature fails is refused outright;
//! one that arrives with no signature at all is opened but marked, so a caller
//! can say so rather than present it as authenticated.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jig_core::{BlockBundle, BlockManifest};

use crate::DeliveredBlock;

/// Whether the author's signature was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authenticity {
    /// Signed by the key of the DID the manifest names.
    Verified,
    /// The delivery carried no signature (a server older than v0.2's
    /// delivery format, or a legacy block). Nothing vouches for the author.
    Unsigned,
}

/// A delivered block, decoded and checked.
#[derive(Debug, Clone)]
pub struct OpenedBlock {
    pub cid: String,
    pub manifest: BlockManifest,
    /// The author's DID in canonical form, from the key the signature
    /// verified against — or the manifest's claim when unsigned.
    pub sender: String,
    pub authenticity: Authenticity,
}

impl OpenedBlock {
    pub fn meta_str(&self, key: &str) -> Option<&str> {
        self.manifest.metadata.get(key).and_then(|v| v.as_str())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpenError {
    #[error("malformed block: {0}")]
    Malformed(String),
    /// The signature does not verify against the claimed author's key. The
    /// block was altered after signing, or never signed by that author.
    #[error("forged block: the signature is not {claimed}'s")]
    Forged { claimed: String },
}

pub fn open(d: &DeliveredBlock) -> Result<OpenedBlock, OpenError> {
    let raw = STANDARD
        .decode(&d.bundle_b64)
        .map_err(|e| OpenError::Malformed(format!("bundle_b64: {e}")))?;
    let (manifest_bytes, code_bytes): (Vec<u8>, Vec<u8>) = serde_json::from_slice(&raw)
        .map_err(|e| OpenError::Malformed(format!("bundle tuple: {e}")))?;
    let manifest: BlockManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| OpenError::Malformed(format!("manifest: {e}")))?;
    let cid = BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    }
    .block_cid()
    .map_err(|e| OpenError::Malformed(format!("cid: {e}")))?
    .to_string();
    let claimed = manifest
        .authors
        .first()
        .map(|a| a.did.clone())
        .ok_or_else(|| OpenError::Malformed("no author".to_string()))?;

    let Some(sig_b64) = d.sig_b64.as_deref() else {
        return Ok(OpenedBlock {
            cid,
            sender: claimed.to_did_jig_string(),
            manifest,
            authenticity: Authenticity::Unsigned,
        });
    };
    let forged = || OpenError::Forged {
        claimed: claimed.to_did_jig_string(),
    };
    let key = claimed.as_bytes().map_err(|_| forged())?;
    let verifying = VerifyingKey::from_bytes(&key).map_err(|_| forged())?;
    let sig = STANDARD
        .decode(sig_b64)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or_else(forged)?;
    // The same canonical bytes ingest verified, rebuilt rather than trusted
    // as delivered.
    let canonical = serde_json::to_vec(&(&manifest_bytes, &code_bytes))
        .map_err(|e| OpenError::Malformed(e.to_string()))?;
    verifying.verify(&canonical, &sig).map_err(|_| forged())?;
    Ok(OpenedBlock {
        cid,
        sender: jig_core::Did::from_ed25519_pubkey(&key).to_did_jig_string(),
        manifest,
        authenticity: Authenticity::Verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use crate::blocks::build_text_render;
    use jig_core::HlcTimestamp;

    fn identity() -> Identity {
        let dir = tempfile::tempdir().unwrap();
        Identity::generate_for_tests(&dir.keep())
    }

    fn delivered(id: &Identity, body: &str) -> DeliveredBlock {
        let hlc = HlcTimestamp::now_wall(id.did().clone());
        let block = build_text_render(id, "#hello", body, hlc);
        DeliveredBlock {
            bundle_b64: STANDARD.encode(block.canonical_bytes()),
            sig_b64: Some(STANDARD.encode(&block.sender_sig)),
            receipts: vec![],
            delivery_cid: format!("delivery:{}", block.cid()),
        }
    }

    #[test]
    fn a_signed_block_opens_as_verified_with_the_cid_the_server_uses() {
        let id = identity();
        let d = delivered(&id, "hi");
        let opened = open(&d).unwrap();
        assert_eq!(opened.authenticity, Authenticity::Verified);
        assert_eq!(opened.sender, id.did_string());
        assert_eq!(format!("delivery:{}", opened.cid), d.delivery_cid);
    }

    #[test]
    fn a_rewritten_block_is_refused() {
        let id = identity();
        let honest = delivered(&id, "pay alice");
        let rewritten = delivered(&id, "pay mallory");
        // A server swaps the content but keeps the original signature.
        let tampered = DeliveredBlock {
            sig_b64: honest.sig_b64.clone(),
            ..rewritten
        };
        assert_eq!(
            open(&tampered).unwrap_err(),
            OpenError::Forged {
                claimed: id.did_string()
            }
        );
    }

    #[test]
    fn a_block_signed_by_someone_else_is_refused() {
        let alice = identity();
        let mallory = identity();
        let mut d = delivered(&alice, "hi");
        d.sig_b64 = delivered(&mallory, "hi").sig_b64;
        assert!(matches!(open(&d), Err(OpenError::Forged { .. })));
    }

    #[test]
    fn an_unsigned_delivery_opens_but_says_so() {
        let id = identity();
        let mut d = delivered(&id, "hi");
        d.sig_b64 = None;
        assert_eq!(open(&d).unwrap().authenticity, Authenticity::Unsigned);
    }
}
