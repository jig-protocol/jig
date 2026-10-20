//! Server receipts: writing v0.3 receipts, and reading every format a store may hold.
//!
//! A receipt this server writes is a v0.3 receipt ([`jig_core::block_receipt`]): deterministic
//! CBOR in a `COSE_Sign1` envelope signed by the server, of one of three kinds:
//!
//! - `exec`, for a block the server ran (`text-render`), built by
//!   [`crate::executor::ExecRun::receipt`];
//! - `sealed`, for encrypted content, which carries no content-derived value (PV-02);
//! - `accepted`, for a block stored without executing.
//!
//! Stores written before v0.3 hold JSON receipts (`{"canonical_hex", "sig_hex"}` around a JSON
//! payload whose `v` is `0.3-render`, `0.3-sealed` or `0.2-synthetic`), and so do peers that have
//! not upgraded. [`read`] accepts both, and checks the signature of each.

use cid::Cid;
use ed25519_dalek::SigningKey;
use jig_core::block_receipt::{Body, Receipt, ReceiptError, Role, SignedReceipt};
use jig_core::did::Did;

/// A receipt as read back: v0.3, or a legacy JSON receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadReceipt {
    V03(SignedReceipt),
    Legacy(LegacyReceipt),
}

/// What a legacy JSON receipt states, once its signature has checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyReceipt {
    /// The payload's `v`, e.g. `0.3-render`.
    pub version: String,
    pub block_cid: String,
    pub server_did: String,
    /// `render.hash`, for a render receipt.
    pub render_hash: Option<String>,
}

/// Why receipt bytes could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error(transparent)]
    V03(#[from] ReceiptError),
    #[error("not a v0.3 or legacy receipt: {0}")]
    Malformed(String),
    #[error("the legacy receipt's signature does not verify against its server_did")]
    BadSignature,
}

/// Read receipt bytes in either format, checking the signature.
pub fn read(bytes: &[u8]) -> Result<ReadReceipt, ReadError> {
    // A legacy receipt is a JSON object, so it starts with `{`. A COSE_Sign1 envelope is a CBOR
    // array or the tagged array (tag 18), neither of which does.
    if bytes.first() == Some(&b'{') {
        return read_legacy(bytes).map(ReadReceipt::Legacy);
    }
    Ok(ReadReceipt::V03(SignedReceipt::open(bytes)?))
}

fn read_legacy(bytes: &[u8]) -> Result<LegacyReceipt, ReadError> {
    let malformed = |what: &str| ReadError::Malformed(what.to_string());
    let wrapped: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| ReadError::Malformed(e.to_string()))?;
    let canonical = hex::decode(
        wrapped["canonical_hex"]
            .as_str()
            .ok_or_else(|| malformed("canonical_hex is missing"))?,
    )
    .map_err(|_| malformed("canonical_hex is not hex"))?;
    let sig = hex::decode(
        wrapped["sig_hex"]
            .as_str()
            .ok_or_else(|| malformed("sig_hex is missing"))?,
    )
    .map_err(|_| malformed("sig_hex is not hex"))?;
    let payload: serde_json::Value =
        serde_json::from_slice(&canonical).map_err(|e| ReadError::Malformed(e.to_string()))?;
    let field = |name: &str| {
        payload[name]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| ReadError::Malformed(format!("`{name}` is missing")))
    };
    let server_did = field("server_did")?;

    let key = Did::from(server_did.as_str())
        .as_bytes()
        .ok()
        .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
        .ok_or(ReadError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_slice(&sig).map_err(|_| ReadError::BadSignature)?;
    key.verify_strict(&canonical, &sig)
        .map_err(|_| ReadError::BadSignature)?;

    Ok(LegacyReceipt {
        version: field("v")?,
        block_cid: field("block_cid")?,
        server_did,
        render_hash: payload["render"]["hash"].as_str().map(str::to_string),
    })
}

/// The server's signed `sealed` receipt for encrypted content.
pub fn sealed(block_cid: &str, server_key: &SigningKey) -> Result<Vec<u8>, ReceiptError> {
    server_receipt(block_cid, server_key, Body::Sealed)
}

/// The server's signed `accepted` receipt for a block stored without executing.
pub fn accepted(block_cid: &str, server_key: &SigningKey) -> Result<Vec<u8>, ReceiptError> {
    server_receipt(block_cid, server_key, Body::Accepted)
}

/// Sign `receipt` with the server's key. Its `executor` must be that key's DID.
pub fn sign(receipt: Receipt, server_key: &SigningKey) -> Result<Vec<u8>, ReceiptError> {
    Ok(SignedReceipt::sign(receipt, server_key)?.envelope)
}

/// A block CID as ingest writes it, in the canonical binary form a receipt carries.
pub fn block_cid(block_cid: &str) -> Result<Cid, ReceiptError> {
    let cid: Cid = block_cid
        .parse()
        .map_err(|_| ReceiptError::Shape("the block CID does not parse"))?;
    jig_core::canonical_cid::check(&cid)?;
    Ok(cid)
}

/// The DID string a receipt's `executor` names for `server_key`.
pub fn executor(server_key: &SigningKey) -> String {
    Did::from_ed25519_pubkey(&server_key.verifying_key().to_bytes()).to_did_jig_string()
}

/// Now, in the milliseconds a receipt's `produced_at` uses.
pub fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

fn server_receipt(
    block: &str,
    server_key: &SigningKey,
    body: Body,
) -> Result<Vec<u8>, ReceiptError> {
    sign(
        Receipt {
            block_cid: block_cid(block)?,
            executor: executor(server_key),
            role: Role::Server,
            produced_at: now_ms(),
            body,
        },
        server_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    fn cid() -> String {
        jig_core::canonical_cid::of(b"a block").to_string()
    }

    #[test]
    fn a_sealed_receipt_round_trips_and_carries_no_content_derived_field() {
        let bytes = sealed(&cid(), &key()).unwrap();
        let ReadReceipt::V03(read) = read(&bytes).unwrap() else {
            panic!("a new receipt reads as v0.3");
        };
        assert_eq!(read.receipt.body, Body::Sealed);
        assert_eq!(read.receipt.executor, executor(&key()));
        assert_eq!(read.receipt.block_cid.to_string(), cid());
    }

    #[test]
    fn an_accepted_receipt_round_trips() {
        let ReadReceipt::V03(read) = read(&accepted(&cid(), &key()).unwrap()).unwrap() else {
            panic!("a new receipt reads as v0.3");
        };
        assert_eq!(read.receipt.body, Body::Accepted);
    }

    #[test]
    fn a_tampered_v03_receipt_is_refused() {
        let mut bytes = sealed(&cid(), &key()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(read(&bytes).is_err());
    }

    fn legacy(payload: serde_json::Value, key: &SigningKey) -> Vec<u8> {
        let canonical = serde_json::to_vec(&payload).unwrap();
        let sig = key.sign(&canonical);
        serde_json::to_vec(&serde_json::json!({
            "canonical_hex": hex::encode(&canonical),
            "sig_hex": hex::encode(sig.to_bytes()),
        }))
        .unwrap()
    }

    #[test]
    fn an_old_render_receipt_still_reads() {
        let bytes = legacy(
            serde_json::json!({
                "v": "0.3-render",
                "block_cid": cid(),
                "server_did": executor(&key()),
                "synthetic": false,
                "render": {"hash": "abc", "module": "text-block@0.1.0/blake3:00", "length_bytes": 3},
                "produced_at": 1,
            }),
            &key(),
        );
        assert_eq!(
            read(&bytes).unwrap(),
            ReadReceipt::Legacy(LegacyReceipt {
                version: "0.3-render".into(),
                block_cid: cid(),
                server_did: executor(&key()),
                render_hash: Some("abc".into()),
            })
        );
    }

    #[test]
    fn an_old_receipt_signed_by_another_key_is_refused() {
        let bytes = legacy(
            serde_json::json!({
                "v": "0.2-synthetic",
                "block_cid": cid(),
                "server_did": executor(&key()),
                "produced_at": 1,
            }),
            &SigningKey::from_bytes(&[4; 32]),
        );
        assert!(matches!(read(&bytes), Err(ReadError::BadSignature)));
    }

    #[test]
    fn a_non_canonical_block_cid_is_refused() {
        assert!(sealed("not a cid", &key()).is_err());
    }
}
