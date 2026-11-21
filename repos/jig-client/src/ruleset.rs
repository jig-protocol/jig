//! The ruleset a server declares (JEP-0009 rule 4), fetched and held to its
//! declaration.
//!
//! The welcome signs `{id, version, hash, url}`. The document at `url` is
//! the server's word only until it is checked: [`check_fetched`] accepts it
//! when its canonical CID is the signed `hash` and it opens, under one of its
//! own authors' keys, to the declared `id` and `version`. Wherever it was
//! fetched from, a document that passes is the one the server signed for.

use jig_core::ruleset::{SignedRuleset, hash_of};
use jig_pipeline::handshake::RulesetRef;

/// The most bytes a ruleset document may be. The reference rulesets are a
/// few KiB; this leaves room and bounds what a hostile server can send.
pub const MAX_RULESET_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RulesetMismatch {
    #[error("the document fetched is {actual}, not the {declared} the server declared")]
    Hash { declared: String, actual: String },
    #[error("the document fetched does not open as a signed ruleset: {0}")]
    Unsigned(String),
    #[error("the document is {actual}, but the server declared {declared}")]
    Names { declared: String, actual: String },
}

/// Where to fetch `declared` from: its `url` as given when absolute, or
/// against `base_http` (the server's `http(s)://host:port`) when it is a
/// path on that server, as a server's own [`RulesetRef::url`] is by default.
pub fn resolve_url(base_http: &str, declared: &RulesetRef) -> String {
    if declared.url.starts_with('/') {
        format!("{}{}", base_http.trim_end_matches('/'), declared.url)
    } else {
        declared.url.clone()
    }
}

/// `bytes` as the ruleset `declared` names, or why not.
pub fn check_fetched(
    declared: &RulesetRef,
    bytes: &[u8],
) -> Result<SignedRuleset, RulesetMismatch> {
    let actual = hash_of(bytes).to_string();
    if actual != declared.hash {
        return Err(RulesetMismatch::Hash {
            declared: declared.hash.clone(),
            actual,
        });
    }
    let signed =
        SignedRuleset::open(bytes).map_err(|e| RulesetMismatch::Unsigned(e.to_string()))?;
    let document = signed.document();
    if document.id != declared.id || document.version != declared.version {
        return Err(RulesetMismatch::Names {
            declared: format!("{} v{}", declared.id, declared.version),
            actual: format!("{} v{}", document.id, document.version),
        });
    }
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `jig-reference` (R2.1), signed by a fresh key that is its one author.
    fn signed() -> SignedRuleset {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../jig-spec/jep/vectors/0009/rulesets/jig-reference.json"
        );
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let payload = jig_core::ruleset::payload_from_json(&json).unwrap();
        let mut doc = jig_core::ruleset::RulesetDocument::from_payload(&payload).unwrap();
        let key = jig_core::crypto::ed25519::generate_signing_key();
        doc.authors = vec![
            jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string(),
        ];
        SignedRuleset::sign(doc, &key).unwrap()
    }

    /// What a server declares for `bytes`, under `id` and `version`.
    fn declared_for(bytes: &[u8], id: &str, version: u64) -> RulesetRef {
        let hash = hash_of(bytes).to_string();
        RulesetRef {
            id: id.into(),
            version,
            url: format!("/api/v1/ruleset/{hash}"),
            hash,
        }
    }

    #[test]
    fn a_path_resolves_against_the_server_and_a_url_stands() {
        let mut declared = declared_for(b"x", "jig-reference", 1);
        assert_eq!(
            resolve_url("https://jig.example:8443/", &declared),
            format!("https://jig.example:8443/api/v1/ruleset/{}", declared.hash)
        );
        declared.url = "https://mirror.example/r.cose".into();
        assert_eq!(
            resolve_url("https://jig.example:8443", &declared),
            "https://mirror.example/r.cose"
        );
    }

    #[test]
    fn the_declared_document_is_accepted() {
        let signed = signed();
        let doc = signed.document();
        let declared = declared_for(signed.envelope(), &doc.id, doc.version);
        let checked = check_fetched(&declared, signed.envelope()).unwrap();
        assert_eq!(checked.document(), doc);
    }

    /// The hash binds the bytes; the names are checked as well, so a server
    /// cannot declare `jig-reference` v1 over a document that says otherwise.
    #[test]
    fn a_document_under_another_name_or_version_is_refused() {
        let signed = signed();
        let doc = signed.document();
        for declared in [
            declared_for(signed.envelope(), "high-sec", doc.version),
            declared_for(signed.envelope(), &doc.id, doc.version + 1),
        ] {
            let err = check_fetched(&declared, signed.envelope()).unwrap_err();
            assert!(matches!(err, RulesetMismatch::Names { .. }), "{err}");
        }
    }

    #[test]
    fn a_document_that_is_not_the_declared_hash_is_refused() {
        let declared = declared_for(b"the declared envelope", "jig-reference", 1);
        let err = check_fetched(&declared, b"another envelope").unwrap_err();
        assert!(matches!(err, RulesetMismatch::Hash { .. }), "{err}");
    }

    #[test]
    fn bytes_with_the_declared_hash_that_do_not_open_are_refused() {
        let bytes = b"not a COSE_Sign1";
        let declared = declared_for(bytes, "jig-reference", 1);
        let err = check_fetched(&declared, bytes).unwrap_err();
        assert!(matches!(err, RulesetMismatch::Unsigned(_)), "{err}");
    }
}
