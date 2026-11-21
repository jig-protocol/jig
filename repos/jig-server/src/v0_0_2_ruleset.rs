//! The ruleset this server declares (JEP-0009 rule 4): read from `[ruleset]`
//! at boot, named in every welcome to a hello that asks and beside the
//! server's manifest, and served at `GET /api/v1/ruleset/{hash}`.
//!
//! Declaring is all this module does. Nothing here applies the ruleset to
//! anyone: that needs a subject's `ack` (rule 5, R2.3) and standing computed
//! under it (R2.4).

use std::sync::Arc;

use anyhow::Context as _;
use axum::{
    Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use jig_config::v0_0_2_server::{PoolsSection, RulesetSection};
use jig_core::ruleset::SignedRuleset;
use jig_pipeline::handshake::RulesetRef;

use crate::v0_0_2::AppState;

/// The route the document is served at.
pub const ROUTE: &str = "/api/v1/ruleset/{hash}";

/// The media type of a COSE_Sign1 envelope (RFC 9052).
pub const CONTENT_TYPE: &str = "application/cose; cose-type=\"cose-sign1\"";

/// The path this server serves the document with `hash` at.
pub fn path_for(hash: &str) -> String {
    ROUTE.replace("{hash}", hash)
}

/// A ruleset this server declares: the signed document, and what the
/// welcome and the manifest log name.
#[derive(Debug, Clone)]
pub struct Declared {
    pub signed: SignedRuleset,
    pub reference: RulesetRef,
}

/// The ruleset `[ruleset]` names, or `None` when it names none. A section
/// that is invalid, a file that cannot be read, or a document that does not
/// open is a boot error: a server that declared a ruleset it could not show
/// would sign a claim no client can check. So is a ruleset whose pool shares
/// `pools` does not enforce ([`check_enforced`]).
pub fn load(section: &RulesetSection, pools: &PoolsSection) -> anyhow::Result<Option<Declared>> {
    section.validate().map_err(anyhow::Error::msg)?;
    let Some(path) = &section.path else {
        return Ok(None);
    };
    let path = shellexpand::tilde(path).into_owned();
    let envelope =
        std::fs::read(&path).with_context(|| format!("[ruleset] reading path {path:?}"))?;
    let signed = SignedRuleset::open(&envelope)
        .with_context(|| format!("[ruleset] path {path:?} is not a signed ruleset"))?;
    check_enforced(&signed, pools).map_err(anyhow::Error::msg)?;
    let declared = declared(signed, section.url.as_deref());
    tracing::info!(
        id = %declared.reference.id,
        version = declared.reference.version,
        hash = %declared.reference.hash,
        url = %declared.reference.url,
        "declaring a ruleset"
    );
    Ok(Some(declared))
}

/// Refuse to declare a ruleset whose pool shares this server does not
/// enforce: declaring is signing a claim (JEP-0009 rule 4), and a server
/// that enforces other shares signs evidence against itself. The pools are
/// the one part of a ruleset enforced today; standing and the rest have no
/// enforcement until R2.4, so they are not checked here.
pub fn check_enforced(signed: &SignedRuleset, pools: &PoolsSection) -> Result<(), String> {
    let declared = &signed.document().parameters.pools;
    let id = &signed.document().id;
    if pools.writes_per_second == 0 {
        return Err(format!(
            "[ruleset] {id} declares pool shares, but [auth.pools] writes_per_second = 0 turns the \
             pools off: set it, or declare no ruleset"
        ));
    }
    let mut mismatches = Vec::new();
    if declared.stranger_share != pools.stranger_share_pct {
        mismatches.push(format!(
            "stranger_share {} vs stranger_share_pct {}",
            declared.stranger_share, pools.stranger_share_pct
        ));
    }
    if declared.invited_share != pools.invited_share_pct {
        mismatches.push(format!(
            "invited_share {} vs invited_share_pct {}",
            declared.invited_share, pools.invited_share_pct
        ));
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "[ruleset] {id} declares pool shares [auth.pools] does not enforce ({}): make them \
             agree, or declare no ruleset",
            mismatches.join("; ")
        ))
    }
}

/// What `signed` is declared as, served at `url` or, unset, at this server's
/// own [`ROUTE`].
pub fn declared(signed: SignedRuleset, url: Option<&str>) -> Declared {
    let hash = signed.hash().to_string();
    let reference = RulesetRef {
        id: signed.document().id.clone(),
        version: signed.document().version,
        url: url.map_or_else(|| path_for(&hash), str::to_string),
        hash,
    };
    Declared { signed, reference }
}

pub fn build_ruleset_router(state: Arc<AppState>) -> Router {
    Router::new().route(ROUTE, get(serve)).with_state(state)
}

/// The declared document, as its signed envelope, when `hash` is its hash.
/// Anything else is 404: this server serves the one ruleset it declares.
async fn serve(State(state): State<Arc<AppState>>, Path(hash): Path<String>) -> Response {
    match state.ruleset.as_deref() {
        Some(declared) if declared.reference.hash == hash => (
            [(header::CONTENT_TYPE, CONTENT_TYPE)],
            declared.signed.envelope().to_vec(),
        )
            .into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use jig_core::ruleset::RulesetDocument;

    /// `jig-reference` (JEP-0009 R2.1), re-signed by a fresh key that is
    /// its one author.
    pub(crate) fn signed_ruleset() -> SignedRuleset {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../jig-spec/jep/vectors/0009/rulesets/jig-reference.json"
        );
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let payload = jig_core::ruleset::payload_from_json(&json).unwrap();
        let mut doc = RulesetDocument::from_payload(&payload).unwrap();
        let key = jig_core::crypto::ed25519::generate_signing_key();
        doc.authors = vec![
            jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string(),
        ];
        SignedRuleset::sign(doc, &key).unwrap()
    }

    fn write(dir: &tempfile::TempDir, bytes: &[u8]) -> String {
        let path = dir.path().join("ruleset.cose");
        std::fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// A test server that declares `signed`, read from `[ruleset]` as at
    /// boot. The directory holds the file and must outlive the server.
    pub(crate) fn declaring_state(signed: &SignedRuleset) -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.ruleset.path = Some(write(&dir, signed.envelope()));
        config.auth.pools = enforced();
        (dir, AppState::for_test_with_config(config).unwrap())
    }

    async fn get(state: AppState, path: &str) -> (StatusCode, String, Vec<u8>) {
        use tower::ServiceExt as _;
        let app = build_ruleset_router(Arc::new(state));
        let req = axum::http::Request::builder()
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, content_type, body.to_vec())
    }

    /// The declared URL serves the signed envelope, whose CID is the
    /// declared hash and which opens to the declared document.
    #[tokio::test]
    async fn the_declared_url_serves_the_document_the_hash_names() {
        let signed = signed_ruleset();
        let (_dir, state) = declaring_state(&signed);
        let declared = state.ruleset.clone().unwrap().reference.clone();
        let (status, content_type, body) = get(state, &declared.url).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, CONTENT_TYPE);
        assert_eq!(jig_core::ruleset::hash_of(&body).to_string(), declared.hash);
        let opened = SignedRuleset::open(&body).unwrap();
        assert_eq!(opened.document(), signed.document());
    }

    /// One ruleset is served, under its own hash: any other hash, or a
    /// server that declares none, is 404.
    #[tokio::test]
    async fn another_hash_or_no_ruleset_is_not_found() {
        let signed = signed_ruleset();
        let other = signed_ruleset().hash().to_string();
        let (_dir, state) = declaring_state(&signed);
        assert_eq!(get(state, &path_for(&other)).await.0, StatusCode::NOT_FOUND);
        let none = AppState::for_test().unwrap();
        let hash = signed.hash().to_string();
        assert_eq!(get(none, &path_for(&hash)).await.0, StatusCode::NOT_FOUND);
    }

    /// `[auth.pools]` as `jig-reference` declares them.
    fn enforced() -> PoolsSection {
        let signed = signed_ruleset();
        let declared = &signed.document().parameters.pools;
        PoolsSection {
            stranger_share_pct: declared.stranger_share,
            invited_share_pct: declared.invited_share,
            ..PoolsSection::default()
        }
    }

    /// The shares a ruleset declares are the ones `[auth.pools]` enforces,
    /// or the server does not boot; the message names both values.
    #[test]
    fn pool_shares_the_server_does_not_enforce_refuse_boot() {
        let signed = signed_ruleset();
        assert_eq!(check_enforced(&signed, &enforced()), Ok(()));
        let declared = signed.document().parameters.pools.stranger_share;
        let other = PoolsSection {
            stranger_share_pct: declared + 1,
            ..enforced()
        };
        let err = check_enforced(&signed, &other).unwrap_err();
        assert!(
            err.contains(&format!(
                "stranger_share {declared} vs stranger_share_pct {}",
                declared + 1
            )),
            "{err}"
        );
        let invited = PoolsSection {
            invited_share_pct: 0,
            ..enforced()
        };
        assert!(
            check_enforced(&signed, &invited)
                .unwrap_err()
                .contains("invited_share")
        );
        let off = PoolsSection {
            writes_per_second: 0,
            ..enforced()
        };
        assert!(
            check_enforced(&signed, &off)
                .unwrap_err()
                .contains("turns the pools off")
        );

        let dir = tempfile::tempdir().unwrap();
        let section = RulesetSection {
            path: Some(write(&dir, signed.envelope())),
            url: None,
        };
        assert!(load(&section, &other).is_err(), "and boot refuses it");
    }

    #[test]
    fn no_section_declares_none() {
        assert!(
            load(&RulesetSection::default(), &enforced())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_signed_document_is_declared_by_its_hash_at_this_server() {
        let signed = signed_ruleset();
        let dir = tempfile::tempdir().unwrap();
        let section = RulesetSection {
            path: Some(write(&dir, signed.envelope())),
            url: None,
        };
        let declared = load(&section, &enforced()).unwrap().unwrap();
        let hash = signed.hash().to_string();
        assert_eq!(declared.reference.hash, hash);
        assert_eq!(declared.reference.id, signed.document().id);
        assert_eq!(declared.reference.version, signed.document().version);
        assert_eq!(declared.reference.url, format!("/api/v1/ruleset/{hash}"));
        assert!(jig_core::canonical_cid::is_canonical_text(&hash));
    }

    #[test]
    fn a_configured_url_is_declared_as_given() {
        let signed = signed_ruleset();
        let dir = tempfile::tempdir().unwrap();
        let section = RulesetSection {
            path: Some(write(&dir, signed.envelope())),
            url: Some("https://mirror.example/r.cose".into()),
        };
        let declared = load(&section, &enforced()).unwrap().unwrap();
        assert_eq!(declared.reference.url, "https://mirror.example/r.cose");
    }

    #[test]
    fn a_missing_or_unsigned_file_refuses_boot() {
        let dir = tempfile::tempdir().unwrap();
        let missing = RulesetSection {
            path: Some(dir.path().join("absent").to_string_lossy().into_owned()),
            url: None,
        };
        assert!(load(&missing, &enforced()).is_err());
        let mut bytes = signed_ruleset().envelope().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = RulesetSection {
            path: Some(write(&dir, &bytes)),
            url: None,
        };
        let err = load(&tampered, &enforced()).unwrap_err();
        assert!(
            format!("{err:#}").contains("not a signed ruleset"),
            "{err:#}"
        );
    }

    #[test]
    fn a_url_without_a_path_or_not_https_refuses_boot() {
        let no_path = RulesetSection {
            path: None,
            url: Some("https://mirror.example/r.cose".into()),
        };
        assert!(load(&no_path, &enforced()).is_err());
        let dir = tempfile::tempdir().unwrap();
        let plain = RulesetSection {
            path: Some(write(&dir, signed_ruleset().envelope())),
            url: Some("http://mirror.example/r.cose".into()),
        };
        assert!(load(&plain, &enforced()).is_err());
    }
}
