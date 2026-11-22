//! Holding a server's welcome to its manifest log (JEP-0002 rule 12; design
//! D11 item 13).
//!
//! A welcome cites the `server-manifest` block it stands on, by CID and the
//! `seq` of its `ingest` record. [`check_cited`] takes that block and record
//! as the server serves them and checks, without trusting the server:
//!
//! - the block is the one cited (its bundle hashes to the CID), a
//!   `server-manifest`, written and signed by the welcome's DID;
//! - the record is the welcome DID's, for that block, at that `seq`;
//! - the document decodes, and says what the welcome says: the welcome's
//!   version is one it lists, and its suites and capabilities are the same.
//!
//! - the ruleset the block declares beside the document
//!   ([`jig_pipeline::server_manifest::RULESET_METADATA_KEY`], JEP-0009
//!   rule 4) is the one the welcome
//!   names, and a welcome that does not name one cites a block that declares
//!   none.
//!
//! The first two failing mean the server did not prove what it cited
//! ([`ManifestCheck::Unproven`]). The last failing is a contradiction the
//! server signed twice ([`ManifestCheck::Contradicts`]): a welcome and a
//! log entry that disagree, the one a server tailoring its answer per client
//! would produce.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use jig_core::{BlockKind, BlockManifest};
pub use jig_pipeline::handshake::{ManifestRef, VerifiedWelcome};
use jig_pipeline::ingest_record::IngestRecord;
use jig_pipeline::server_manifest::{METADATA_KEY, ServerManifest, declared_ruleset};

pub use jig_pipeline::server_manifest::LOG_SLUG;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestCheck {
    #[error("the server did not prove the manifest its welcome cites: {0}")]
    Unproven(String),
    #[error("the server's welcome contradicts the manifest it cites: {0}")]
    Contradicts(String),
    /// A client that asked for the server's ruleset was answered by a
    /// welcome that does not grant it, while the manifest the welcome cites
    /// declares one ([`check_cited_asked`]). Only the client knows it asked,
    /// so this is a refusal, not evidence anyone else can check.
    #[error("the server's welcome withholds the ruleset its manifest declares: {0}")]
    Withheld(String),
}

/// Check `cited`, the block and record `welcome` cites, as served. Returns
/// the document on success.
///
/// It checks only what the welcome signs, so it holds for evidence: a
/// welcome that does not grant the ruleset capability makes no claim about
/// the ruleset, whatever the manifest declares. A client that asked uses
/// [`check_cited_asked`].
pub fn check_cited(
    welcome: &VerifiedWelcome,
    cited: &ManifestRef,
    bundle_b64: &str,
    sig_b64: &str,
    record: &IngestRecord,
) -> Result<ServerManifest, ManifestCheck> {
    check_cited_as(welcome, cited, bundle_b64, sig_b64, record, false)
}

/// [`check_cited`] for a client whose hello asked for the ruleset: a welcome
/// that does not grant it, citing a manifest that declares one, is refused
/// as [`ManifestCheck::Withheld`].
pub fn check_cited_asked(
    welcome: &VerifiedWelcome,
    cited: &ManifestRef,
    bundle_b64: &str,
    sig_b64: &str,
    record: &IngestRecord,
) -> Result<ServerManifest, ManifestCheck> {
    check_cited_as(welcome, cited, bundle_b64, sig_b64, record, true)
}

fn check_cited_as(
    welcome: &VerifiedWelcome,
    cited: &ManifestRef,
    bundle_b64: &str,
    sig_b64: &str,
    record: &IngestRecord,
    asked_ruleset: bool,
) -> Result<ServerManifest, ManifestCheck> {
    let unproven = |reason: &str| ManifestCheck::Unproven(reason.to_string());
    let manifest = served_block(&cited.cid, bundle_b64, sig_b64).map_err(|r| unproven(&r))?;
    if manifest.kind != Some(BlockKind::ServerManifest) {
        return Err(unproven("the cited block is not a server-manifest"));
    }
    if manifest.metadata.get("channel").and_then(|v| v.as_str()) != Some(LOG_SLUG) {
        return Err(unproven("the cited block is not in the manifest log"));
    }
    let author = manifest.authors.first().map(|a| a.did.to_did_jig_string());
    if !author
        .as_deref()
        .is_some_and(|a| jig_pipeline::handshake::same_did(a, &welcome.server_did))
    {
        return Err(unproven(
            "the cited manifest is not written by the welcome's DID",
        ));
    }
    record
        .verify(&welcome.server_did)
        .map_err(|e| unproven(&format!("its record does not verify: {e}")))?;
    if record.block_cid != cited.cid || record.seq != cited.seq {
        return Err(unproven(
            "the record served is not the one for the cited block and seq",
        ));
    }

    // Signed by the server from here on: a disagreement is a contradiction.
    let contradicts = |reason: String| ManifestCheck::Contradicts(reason);
    let bytes = manifest
        .metadata
        .get(METADATA_KEY)
        .and_then(|v| v.as_str())
        .and_then(|b64| STANDARD.decode(b64).ok())
        .ok_or_else(|| contradicts("the manifest it signed carries no document".to_string()))?;
    let doc = ServerManifest::decode(&bytes)
        .map_err(|e| contradicts(format!("the manifest it signed does not decode: {e}")))?;
    if !doc.versions.contains(&u64::from(welcome.version)) {
        return Err(contradicts(format!(
            "the welcome speaks version {}, the manifest lists {:?}",
            welcome.version, doc.versions
        )));
    }
    let mut claimed = doc.clone();
    claimed.suites = dedup(&welcome.suites);
    claimed.capabilities = welcome.capabilities.clone();
    claimed.capabilities.block_kinds = dedup(&welcome.capabilities.block_kinds);
    let canonical = |m: &ServerManifest| m.encode().map_err(|e| contradicts(e.to_string()));
    if canonical(&claimed)? != canonical(&doc)? {
        return Err(contradicts(format!(
            "the welcome advertises suites {:?} and capabilities {:?}, the manifest suites {:?} \
             and capabilities {:?}",
            claimed.suites, claimed.capabilities, doc.suites, doc.capabilities
        )));
    }
    let declared = declared_ruleset(&manifest.metadata).map_err(|e| {
        contradicts(format!(
            "the manifest it signed declares no valid ruleset: {e}"
        ))
    })?;
    // A welcome that grants the capability signs the ruleset, or its
    // absence (`Capabilities::ruleset`): that claim must be the manifest's.
    // One that does not grant it claims nothing about the ruleset (a server
    // answers a hello that did not ask that way), so only a client that
    // asked can hold its silence against the manifest.
    if !welcome.capabilities.ruleset {
        if asked_ruleset && let Some(declared) = &declared {
            return Err(ManifestCheck::Withheld(format!(
                "this client asked for the ruleset; the welcome does not grant it, and the \
                 manifest declares {}",
                ruleset_name(Some(declared))
            )));
        }
        return Ok(doc);
    }
    let named = welcome.ruleset.as_deref();
    if named != declared.as_ref() {
        return Err(contradicts(format!(
            "the welcome names ruleset {}, the manifest declares {}",
            ruleset_name(named),
            ruleset_name(declared.as_ref())
        )));
    }
    Ok(doc)
}

fn ruleset_name(ruleset: Option<&jig_pipeline::handshake::RulesetRef>) -> String {
    ruleset.map_or_else(
        || "none".to_string(),
        |r| format!("{} v{} ({})", r.id, r.version, r.hash),
    )
}

/// One entry of a server's manifest log as served (`jig trust show`): its
/// CID and document, once it is a `server-manifest` that `server_did` wrote
/// and signed. `Ok(None)` for the log's other blocks (its channel-create).
pub fn read_entry(
    server_did: &str,
    bundle_b64: &str,
    sig_b64: &str,
) -> Result<Option<(String, ServerManifest)>, String> {
    let (cid, manifest) = served(bundle_b64, sig_b64)?;
    let author = manifest.authors.first().map(|a| a.did.to_did_jig_string());
    if !author
        .as_deref()
        .is_some_and(|a| jig_pipeline::handshake::same_did(a, server_did))
    {
        return Err(format!("block {cid} is not written by {server_did}"));
    }
    if manifest.kind != Some(BlockKind::ServerManifest) {
        return Ok(None);
    }
    let bytes = manifest
        .metadata
        .get(METADATA_KEY)
        .and_then(|v| v.as_str())
        .and_then(|b64| STANDARD.decode(b64).ok())
        .ok_or_else(|| format!("block {cid} carries no document"))?;
    let doc = ServerManifest::decode(&bytes).map_err(|e| format!("block {cid}: {e}"))?;
    Ok(Some((cid, doc)))
}

/// The manifest of the block `cid` as served, once its bundle hashes to
/// `cid` and its first author's key signed it.
fn served_block(cid: &str, bundle_b64: &str, sig_b64: &str) -> Result<BlockManifest, String> {
    let (actual, manifest) = served(bundle_b64, sig_b64)?;
    if actual != cid {
        return Err("the block served is not the one cited".to_string());
    }
    Ok(manifest)
}

/// A served block's CID and manifest, once its first author's key signed it.
fn served(bundle_b64: &str, sig_b64: &str) -> Result<(String, BlockManifest), String> {
    let bundle_bytes = STANDARD
        .decode(bundle_b64)
        .map_err(|_| "the bundle is not base64".to_string())?;
    let sig = STANDARD
        .decode(sig_b64)
        .map_err(|_| "the signature is not base64".to_string())?;
    let (manifest_bytes, code_bytes): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&bundle_bytes).map_err(|_| "the bundle is malformed".to_string())?;
    let actual = jig_core::BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    }
    .block_cid()
    .map_err(|_| "its CID cannot be derived".to_string())?
    .to_string();
    let manifest: BlockManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| "the manifest is malformed".to_string())?;
    let author = manifest
        .authors
        .first()
        .ok_or_else(|| "it names no author".to_string())?;
    let key = author
        .did
        .as_bytes()
        .ok()
        .and_then(|k| VerifyingKey::from_bytes(&k).ok())
        .ok_or_else(|| "its author is not a did:jig key".to_string())?;
    let signature = Signature::from_slice(&sig).map_err(|_| "bad signature".to_string())?;
    let signed = serde_json::to_vec(&(&manifest_bytes, &code_bytes))
        .map_err(|_| "the bundle cannot be re-encoded".to_string())?;
    key.verify(&signed, &signature)
        .map_err(|_| "its author did not sign it".to_string())?;
    Ok((actual, manifest))
}

fn dedup(items: &[String]) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    items.iter().filter(|i| seen.insert(*i)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use jig_pipeline::handshake::{Capabilities, Reputation, RulesetRef};
    use jig_pipeline::ingest_record::{GENESIS_PREV, RecordSigner, label_cid};
    use jig_pipeline::server_manifest::PeerPolicy;

    struct Server {
        key: ed25519_dalek::SigningKey,
        identity: Identity,
    }

    impl Server {
        fn new() -> Self {
            let key = jig_core::crypto::ed25519::generate_signing_key();
            Self {
                identity: Identity::from_signing_key(key.clone()),
                key,
            }
        }

        fn did(&self) -> String {
            self.identity.did_string()
        }

        /// A `server-manifest` block for `doc`, as served, and the record
        /// for it at `seq`.
        fn publish(
            &self,
            doc: &ServerManifest,
            seq: u64,
        ) -> (ManifestRef, String, String, IngestRecord) {
            self.publish_in(LOG_SLUG, doc, seq)
        }

        /// [`Self::publish`], with the block naming `channel`.
        fn publish_in(
            &self,
            channel: &str,
            doc: &ServerManifest,
            seq: u64,
        ) -> (ManifestRef, String, String, IngestRecord) {
            self.publish_block(
                serde_json::json!({
                    "channel": channel,
                    METADATA_KEY: STANDARD.encode(doc.encode().unwrap()),
                }),
                seq,
            )
        }

        /// [`Self::publish`], with the block declaring `ruleset` beside the
        /// document.
        fn publish_declaring(
            &self,
            doc: &ServerManifest,
            ruleset: &RulesetRef,
            seq: u64,
        ) -> (ManifestRef, String, String, IngestRecord) {
            self.publish_block(
                serde_json::json!({
                    "channel": LOG_SLUG,
                    METADATA_KEY: STANDARD.encode(doc.encode().unwrap()),
                    jig_pipeline::server_manifest::RULESET_METADATA_KEY: ruleset,
                }),
                seq,
            )
        }

        fn publish_block(
            &self,
            metadata: serde_json::Value,
            seq: u64,
        ) -> (ManifestRef, String, String, IngestRecord) {
            let block = crate::blocks::build_with_metadata(
                &self.identity,
                BlockKind::ServerManifest,
                jig_core::HlcTimestamp::now_wall(self.identity.did().clone()),
                metadata,
            );
            let cid = block.cid();
            let record = RecordSigner {
                channel_id: label_cid("bafyLog"),
                key: &self.key,
                ingest_wall_ms: 1,
                ingest_logical: 0,
            }
            .sign(seq, &cid, GENESIS_PREV)
            .unwrap();
            (
                ManifestRef { cid, seq },
                STANDARD.encode(block.canonical_bytes()),
                STANDARD.encode(&block.sender_sig),
                record,
            )
        }

        fn welcome(&self, suites: &[&str], kinds: &[&str]) -> VerifiedWelcome {
            VerifiedWelcome {
                server_did: self.did(),
                version: 1,
                suites: suites.iter().map(|s| s.to_string()).collect(),
                capabilities: Capabilities {
                    block_kinds: kinds.iter().map(|s| s.to_string()).collect(),
                    execution: true,
                    federation: true,
                    max_future_skew_ms: 300_000,
                    tiers: false,
                    ruleset: false,
                },
                reputation: Reputation::none(),
                nonce: String::new(),
                server_nonce: String::new(),
                tls_exporter: Vec::new(),
                manifest: None,
                admit: None,
                ruleset: None,
                moved_from: None,
                evidence: String::new(),
            }
        }
    }

    fn doc() -> ServerManifest {
        ServerManifest {
            versions: vec![1],
            suites: vec!["none".into(), "mls".into()],
            capabilities: Capabilities {
                block_kinds: vec!["text-render".into(), "member-add".into()],
                execution: true,
                federation: true,
                max_future_skew_ms: 300_000,
                tiers: false,
                ruleset: false,
            },
            peer_policy: PeerPolicy::default(),
        }
    }

    fn ruleset(version: u64) -> RulesetRef {
        let hash = jig_core::canonical_cid::of(&version.to_le_bytes()).to_string();
        RulesetRef {
            id: "jig-reference".into(),
            version,
            url: format!("/api/v1/ruleset/{hash}"),
            hash,
        }
    }

    /// A welcome to a hello that asked, naming `named`.
    fn declaring(mut welcome: VerifiedWelcome, named: Option<RulesetRef>) -> VerifiedWelcome {
        welcome.capabilities.ruleset = true;
        welcome.ruleset = named.map(Box::new);
        welcome
    }

    /// JEP-0009 rule 4: the welcome and the manifest name one ruleset, and a
    /// server that declares none says so in both.
    #[test]
    fn the_welcome_and_the_manifest_declare_the_same_ruleset() {
        let server = Server::new();
        let base = server.welcome(&["none", "mls"], &["text-render", "member-add"]);

        let (cited, bundle, sig, record) = server.publish_declaring(&doc(), &ruleset(1), 1);
        let welcome = declaring(base.clone(), Some(ruleset(1)));
        check_cited(&welcome, &cited, &bundle, &sig, &record).unwrap();

        let (cited, bundle, sig, record) = server.publish(&doc(), 1);
        check_cited(
            &declaring(base.clone(), None),
            &cited,
            &bundle,
            &sig,
            &record,
        )
        .unwrap();
    }

    /// Any disagreement is one the server signed twice: another ruleset,
    /// one named and none declared, or one declared and none named (the
    /// welcome hiding it from a client that asked).
    #[test]
    fn a_welcome_that_names_another_ruleset_than_its_manifest_contradicts_it() {
        let server = Server::new();
        let base = server.welcome(&["none", "mls"], &["text-render", "member-add"]);
        let (declared, d_bundle, d_sig, d_record) =
            server.publish_declaring(&doc(), &ruleset(1), 1);
        let (none, n_bundle, n_sig, n_record) = server.publish(&doc(), 1);
        let contradicts = |r: Result<ServerManifest, ManifestCheck>| {
            assert!(matches!(r, Err(ManifestCheck::Contradicts(_))), "{r:?}")
        };

        let other = declaring(base.clone(), Some(ruleset(2)));
        contradicts(check_cited(&other, &declared, &d_bundle, &d_sig, &d_record));
        let named = declaring(base.clone(), Some(ruleset(1)));
        contradicts(check_cited(&named, &none, &n_bundle, &n_sig, &n_record));
        let hidden = declaring(base.clone(), None);
        contradicts(check_cited(
            &hidden, &declared, &d_bundle, &d_sig, &d_record,
        ));
    }

    /// A welcome that does not grant the capability says nothing about the
    /// ruleset, so it is no evidence against a manifest that declares one:
    /// a server answers a hello that did not ask that way. A client that
    /// asked refuses it, without evidence.
    #[test]
    fn a_welcome_without_the_capability_is_refused_only_by_a_client_that_asked() {
        let server = Server::new();
        let base = server.welcome(&["none", "mls"], &["text-render", "member-add"]);
        let (cited, bundle, sig, record) = server.publish_declaring(&doc(), &ruleset(1), 1);
        check_cited(&base, &cited, &bundle, &sig, &record).unwrap();
        let asked = check_cited_asked(&base, &cited, &bundle, &sig, &record);
        assert!(
            matches!(asked, Err(ManifestCheck::Withheld(_))),
            "{asked:?}"
        );
        // Nothing declared: nothing withheld.
        let (cited, bundle, sig, record) = server.publish(&doc(), 1);
        check_cited_asked(&base, &cited, &bundle, &sig, &record).unwrap();
    }

    #[test]
    fn a_welcome_that_says_what_its_manifest_says_holds() {
        let server = Server::new();
        let (cited, bundle, sig, record) = server.publish(&doc(), 1);
        // Order and repeats in the welcome are not differences.
        let welcome = server.welcome(&["none", "mls", "none"], &["member-add", "text-render"]);
        let got = check_cited(&welcome, &cited, &bundle, &sig, &record).unwrap();
        assert_eq!(got.encode(), doc().encode());
    }

    #[test]
    fn a_welcome_that_tells_another_story_is_a_contradiction() {
        let server = Server::new();
        let (cited, bundle, sig, record) = server.publish(&doc(), 1);
        for welcome in [
            server.welcome(&["none"], &["text-render", "member-add"]),
            server.welcome(&["none", "mls"], &["text-render"]),
        ] {
            assert!(matches!(
                check_cited(&welcome, &cited, &bundle, &sig, &record),
                Err(ManifestCheck::Contradicts(_))
            ));
        }
        let mut other_version = server.welcome(&["none", "mls"], &["text-render", "member-add"]);
        other_version.version = 2;
        assert!(matches!(
            check_cited(&other_version, &cited, &bundle, &sig, &record),
            Err(ManifestCheck::Contradicts(_))
        ));
    }

    #[test]
    fn a_manifest_the_server_does_not_prove_is_refused_not_a_contradiction() {
        let server = Server::new();
        let welcome = server.welcome(&["none", "mls"], &["text-render", "member-add"]);
        let (cited, bundle, sig, record) = server.publish(&doc(), 1);
        let unproven = |r: Result<ServerManifest, ManifestCheck>| {
            assert!(matches!(r, Err(ManifestCheck::Unproven(_))), "{r:?}");
        };
        // Another block than the one cited.
        let (other, other_bundle, other_sig, _) = server.publish(&doc(), 2);
        unproven(check_cited(
            &welcome,
            &cited,
            &other_bundle,
            &other_sig,
            &record,
        ));
        // The record for another seq.
        unproven(check_cited(
            &welcome,
            &ManifestRef {
                seq: 7,
                ..cited.clone()
            },
            &bundle,
            &sig,
            &record,
        ));
        let _ = other;
        // Written by someone else.
        let stranger = Server::new();
        let (s_cited, s_bundle, s_sig, s_record) = stranger.publish(&doc(), 1);
        unproven(check_cited(
            &welcome, &s_cited, &s_bundle, &s_sig, &s_record,
        ));
        // A signature that is not the author's.
        unproven(check_cited(&welcome, &cited, &bundle, &other_sig, &record));
        // A server-manifest the server wrote into another channel.
        let (o_cited, o_bundle, o_sig, o_record) = server.publish_in("#ops", &doc(), 1);
        unproven(check_cited(
            &welcome, &o_cited, &o_bundle, &o_sig, &o_record,
        ));
    }

    /// A welcome `server` signs that cites `cited`, and what it advertises.
    fn signed_welcome(server: &Server, cited: Option<ManifestRef>) -> (String, ServerManifest) {
        use jig_pipeline::handshake::{HelloView, ServerOffer, implemented_suite_names, negotiate};
        let mut statement = negotiate(
            &HelloView {
                versions: vec![1],
                suites: implemented_suite_names(),
                capabilities: Default::default(),
                nonce: jig_pipeline::handshake::fresh_nonce(),
                peer_did: None,
            },
            &ServerOffer::default(),
        )
        .unwrap();
        let said = ServerManifest {
            versions: vec![1],
            suites: statement.suites.clone(),
            capabilities: statement.capabilities.clone(),
            peer_policy: PeerPolicy::default(),
        };
        statement.manifest = cited;
        let text =
            serde_json::to_string(&jig_pipeline::handshake::seal(&server.key, statement)).unwrap();
        (text, said)
    }

    #[test]
    fn a_contradicted_manifest_is_proven_from_the_bundle_alone() {
        use crate::evidence::{BUNDLE_FORMAT, Bundle, BundleError, Proof, verify};
        let server = Server::new();
        let bundle =
            |welcome: String, published: &(ManifestRef, String, String, IngestRecord)| Bundle {
                format: BUNDLE_FORMAT.into(),
                class: 3,
                code: "manifest-contradiction".into(),
                reason: String::new(),
                server: "https://host:7117".into(),
                server_did: server.did(),
                observed_at_ms: 1,
                welcome: None,
                items: vec![],
                proof: Some(Proof::ManifestContradiction {
                    welcome,
                    block: published.1.clone(),
                    sig: published.2.clone(),
                    record: published.3.clone(),
                }),
            };
        let (_, said) = signed_welcome(&server, None);
        let mut other = said.clone();
        other.suites.push("rot13".into());

        // Logged one thing, welcomed with another.
        let logged = server.publish(&other, 1);
        let (welcome, _) = signed_welcome(&server, Some(logged.0.clone()));
        let proven = verify(&bundle(welcome, &logged)).unwrap().proven.unwrap();
        assert!(proven.contains("rot13"), "{proven}");

        // What it logged is what it said: nothing proven.
        let honest = server.publish(&said, 2);
        let (welcome, _) = signed_welcome(&server, Some(honest.0.clone()));
        let refused = |b: Bundle| assert!(matches!(verify(&b), Err(BundleError::Proof(_))));
        refused(bundle(welcome, &honest));
        // A welcome citing no manifest, or citing another than the one kept.
        refused(bundle(signed_welcome(&server, None).0, &logged));
        refused(bundle(
            signed_welcome(&server, Some(honest.0.clone())).0,
            &logged,
        ));
        // Another server's welcome, or a manifest another server wrote.
        let stranger = Server::new();
        refused(bundle(
            signed_welcome(&stranger, Some(logged.0.clone())).0,
            &logged,
        ));
        let theirs = stranger.publish(&other, 1);
        refused(bundle(
            signed_welcome(&server, Some(theirs.0.clone())).0,
            &theirs,
        ));
    }
}
