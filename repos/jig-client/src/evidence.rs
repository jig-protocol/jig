//! Evidence a client keeps against the parties that signed it (design D11
//! item 9). Held by the submitter, never handed to a third party, so a
//! compromised server or nameserver cannot make it disappear.
//!
//! Two kinds are kept:
//!
//! - **Bundles against a server** ([`Bundle`], format [`BUNDLE_FORMAT`]): a
//!   class 3 contradiction, one file per contradiction under
//!   `~/.jig/evidence/<server>/`. A bundle holds the items exactly as the
//!   server signed them, so anyone can check it ([`verify`]) without trusting
//!   whoever presents it. It holds no decrypted content and is not signed by
//!   the user (PV-03).
//! - **What name resolution acted on** ([`crate::naming::NameEvidence`]):
//!   every attestation and link exactly as served, one file per resolution
//!   under `~/.jig/evidence/names/`, in [`INTERIM_FORMAT`] until name bundles
//!   join [`BUNDLE_FORMAT`].
//!
//! Only a bundle with a [`Proof`] that [`verify`] accepts may make a refusal
//! sticky (JEP-0002 rule 16): a proof is built from server-signed items alone,
//! so a network attacker, who can drop, delay or replay frames but cannot
//! sign, cannot produce one.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jig_pipeline::handshake::{HandshakeResult, same_did, verify_offline};
use serde::{Deserialize, Serialize};

use crate::chain::ChainProof;

/// The format of a bundle against a server.
pub const BUNDLE_FORMAT: &str = "jig-evidence-v1";

/// One class 3 contradiction, as kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    /// [`BUNDLE_FORMAT`].
    pub format: String,
    /// The failure class (design D11 item 1): 3.
    pub class: u8,
    /// What was contradicted, as a stable name ([`Contradiction::code`]).
    ///
    /// [`Contradiction::code`]: crate::connection::Contradiction::code
    pub code: String,
    pub reason: String,
    /// The server, as configured.
    pub server: String,
    /// The DID this client pinned for it, which signed everything below.
    pub server_did: String,
    /// This client's clock when it saw the contradiction. Not signed.
    pub observed_at_ms: u64,
    /// The welcome of the connection it came on, verbatim; `None` over REST.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome: Option<String>,
    /// Every frame involved, verbatim as received.
    #[serde(default)]
    pub items: Vec<String>,
    /// The server-signed items that show the contradiction on their own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

/// Server-signed items that contradict each other, whoever presents them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Proof {
    /// Two `ingest` records that cannot both hold, or a bad record 0.
    Chain(Box<ChainProof>),
    /// A welcome that advertised `suite`, and a signed refusal that does not
    /// list it. Neither is dated, so this shows the server signed both, not
    /// which came first: the client that kept them saw the order.
    Downgrade {
        pinned_welcome: String,
        refusal: String,
        suite: String,
    },
}

/// What [`verify`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// What the proof shows, when the bundle has one and it holds. Without
    /// it, the bundle records what this client saw but proves nothing.
    pub proven: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("not a {BUNDLE_FORMAT} bundle (format `{0}`)")]
    Format(String),
    #[error("the bundle's welcome does not verify as {server_did}'s: {reason}")]
    Welcome { server_did: String, reason: String },
    #[error("the bundle's proof does not hold: {0}")]
    Proof(String),
    #[error("{0}")]
    Io(String),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
}

/// Check `bundle` using nothing but what is in it: its welcome must be the
/// pinned DID's, and its proof, if any, must hold.
pub fn verify(bundle: &Bundle) -> Result<Checked, BundleError> {
    if bundle.format != BUNDLE_FORMAT {
        return Err(BundleError::Format(bundle.format.clone()));
    }
    if let Some(welcome) = &bundle.welcome {
        welcome_of(welcome, &bundle.server_did).map_err(|reason| BundleError::Welcome {
            server_did: bundle.server_did.clone(),
            reason,
        })?;
    }
    let proven = match &bundle.proof {
        None => None,
        Some(Proof::Chain(proof)) => {
            if !same_did(&proof.sequencer, &bundle.server_did) {
                return Err(BundleError::Proof(format!(
                    "the records are {}'s, not {}'s",
                    proof.sequencer, bundle.server_did
                )));
            }
            let broke = proof.verify().map_err(BundleError::Proof)?;
            Some(format!("channel {}: {broke}", proof.channel_id))
        }
        Some(Proof::Downgrade {
            pinned_welcome,
            refusal,
            suite,
        }) => {
            let advertised = welcome_of(pinned_welcome, &bundle.server_did)
                .map_err(|e| BundleError::Proof(format!("the earlier welcome: {e}")))?;
            if !advertised.contains(suite) {
                return Err(BundleError::Proof(format!(
                    "the earlier welcome does not advertise `{suite}`"
                )));
            }
            let listed = match verify_offline(refusal, &bundle.server_did) {
                HandshakeResult::Incompatible(r) => r.suites,
                other => {
                    return Err(BundleError::Proof(format!(
                        "the refusal does not verify: {}",
                        reason_of(&other)
                    )));
                }
            };
            if listed.contains(suite) {
                return Err(BundleError::Proof(format!(
                    "the refusal still lists `{suite}`"
                )));
            }
            Some(format!(
                "{} advertised `{suite}` in a signed welcome and signed a refusal without it",
                bundle.server_did
            ))
        }
    };
    Ok(Checked { proven })
}

/// A [`Proof::Downgrade`] from a welcome this client pinned, advertising
/// `pinned_suites`, and a signed `refusal` that drops one of them; `None`
/// unless both verify as `server_did`'s and the refusal really drops one.
pub fn downgrade_proof(
    pinned_welcome: &str,
    pinned_suites: &std::collections::BTreeSet<String>,
    refusal: &str,
    server_did: &str,
) -> Option<Proof> {
    let advertised = welcome_of(pinned_welcome, server_did).ok()?;
    let HandshakeResult::Incompatible(r) = verify_offline(refusal, server_did) else {
        return None;
    };
    let suite = pinned_suites
        .iter()
        .find(|s| advertised.contains(s) && !r.suites.contains(s))?;
    Some(Proof::Downgrade {
        pinned_welcome: pinned_welcome.to_string(),
        refusal: refusal.to_string(),
        suite: suite.clone(),
    })
}

/// The suites a kept welcome advertises, once it verifies as `server_did`'s.
fn welcome_of(text: &str, server_did: &str) -> Result<Vec<String>, String> {
    match verify_offline(text, server_did) {
        HandshakeResult::Established(w) => Ok(w.suites),
        other => Err(reason_of(&other)),
    }
}

fn reason_of(result: &HandshakeResult) -> String {
    match result {
        HandshakeResult::FailClosed { reason, .. }
        | HandshakeResult::Contradiction { reason, .. } => reason.clone(),
        HandshakeResult::Established(_) => "it is a welcome".to_string(),
        HandshakeResult::Incompatible(_) => "it is a refusal".to_string(),
    }
}

/// Bundles against servers, kept as files: `<dir>/<server>/<time>-<code>.json`.
pub struct EvidenceStore {
    dir: PathBuf,
}

impl EvidenceStore {
    /// `~/.jig/evidence`.
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".jig")
            .join("evidence")
    }

    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// Write `bundle` and return its id (`<server>/<file stem>`). Never
    /// overwrites a bundle already kept.
    pub fn keep(&self, bundle: &Bundle) -> Result<String, BundleError> {
        let server = server_dir(&bundle.server);
        let dir = self.dir.join(&server);
        std::fs::create_dir_all(&dir).map_err(|e| io(&dir, &e))?;
        let bytes = serde_json::to_vec_pretty(bundle)?;
        let code: String = bundle
            .code
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        for n in 0u32.. {
            let stem = match n {
                0 => format!("{}-{code}", bundle.observed_at_ms),
                n => format!("{}-{code}-{n}", bundle.observed_at_ms),
            };
            let path = dir.join(format!("{stem}.json"));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use std::io::Write as _;
                    file.write_all(&bytes).map_err(|e| io(&path, &e))?;
                    return Ok(format!("{server}/{stem}"));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(io(&path, &e)),
            }
        }
        unreachable!("some file name is free")
    }

    /// Every bundle kept, oldest first, by id. Files that are not bundles
    /// (name evidence, anything else) are skipped.
    pub fn list(&self) -> Result<Vec<(String, Bundle)>, BundleError> {
        let mut out = Vec::new();
        let servers = match std::fs::read_dir(&self.dir) {
            Ok(servers) => servers,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(io(&self.dir, &e)),
        };
        for server in servers.flatten() {
            let Ok(files) = std::fs::read_dir(server.path()) else {
                continue;
            };
            for file in files.flatten() {
                let path = file.path();
                let Some(stem) = path
                    .extension()
                    .filter(|ext| *ext == "json")
                    .and(path.file_stem())
                    .and_then(|s| s.to_str())
                else {
                    continue;
                };
                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };
                if let Ok(bundle) = serde_json::from_slice::<Bundle>(&bytes)
                    && bundle.format == BUNDLE_FORMAT
                {
                    let id = format!("{}/{stem}", server.file_name().to_string_lossy());
                    out.push((id, bundle));
                }
            }
        }
        out.sort_by(|a, b| (a.1.observed_at_ms, &a.0).cmp(&(b.1.observed_at_ms, &b.0)));
        Ok(out)
    }

    /// The file of the bundle `id`, which must name one in this store.
    pub fn path_of(&self, id: &str) -> Result<PathBuf, BundleError> {
        let mut parts = id.split('/');
        let (Some(server), Some(stem), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(BundleError::Io(format!("`{id}` is not a bundle id")));
        };
        let plain = |s: &str| !s.is_empty() && s != "." && s != ".." && !s.contains(['\\', '\0']);
        if !plain(server) || !plain(stem) {
            return Err(BundleError::Io(format!("`{id}` is not a bundle id")));
        }
        Ok(self.dir.join(server).join(format!("{stem}.json")))
    }

    pub fn get(&self, id: &str) -> Result<Bundle, BundleError> {
        let path = self.path_of(id)?;
        let bytes = std::fs::read(&path).map_err(|e| io(&path, &e))?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

/// A server as a directory name: [`crate::secure::server_key`], with anything
/// but letters, digits, `.` and `-` replaced.
fn server_dir(server: &str) -> String {
    crate::secure::server_key(server)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn io(path: &Path, e: &std::io::Error) -> BundleError {
    BundleError::Io(format!("{}: {e}", path.display()))
}

use crate::naming::{NameEvidence, NameEvidenceBundle};

/// The format this module writes, named in every file it writes.
pub const INTERIM_FORMAT: &str = "jig-name-evidence-interim";

/// Name evidence kept as files in one directory.
pub struct NameEvidenceDir {
    dir: PathBuf,
}

/// One kept resolution, as written to disk.
#[derive(Serialize)]
struct Kept<'a> {
    format: &'static str,
    kind: &'static str,
    name: String,
    root: &'static str,
    root_id: &'a str,
    observed_at: i64,
    /// Base64 COSE_Sign1, one per attestation.
    attestations: Vec<String>,
    /// The signing nameserver of each attestation, in the same order.
    ns_dids: &'a [String],
    /// Base64, as served.
    links: Vec<String>,
}

impl NameEvidenceDir {
    /// `~/.jig/evidence/names`.
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".jig")
            .join("evidence")
            .join("names")
    }

    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }
}

impl NameEvidence for NameEvidenceDir {
    fn record(&self, bundle: &NameEvidenceBundle) -> Result<(), String> {
        let kept = Kept {
            format: INTERIM_FORMAT,
            kind: "name-resolution",
            name: format!("{}@{}", bundle.key.alias, bundle.key.suffix),
            root: bundle.key.root.as_str(),
            root_id: &bundle.key.root_id,
            observed_at: bundle.observed_at,
            attestations: bundle
                .attestations
                .iter()
                .map(|a| STANDARD.encode(a))
                .collect(),
            ns_dids: &bundle.ns_dids,
            links: bundle.links.iter().map(|l| STANDARD.encode(l)).collect(),
        };
        let bytes = serde_json::to_vec_pretty(&kept).map_err(|e| e.to_string())?;
        // Named by content, so the same answer kept twice is one file.
        let file = format!(
            "{}-{}.json",
            bundle.observed_at,
            &hex::encode(blake3::hash(&bytes).as_bytes())[..16]
        );
        std::fs::create_dir_all(&self.dir)
            .and_then(|()| std::fs::write(self.dir.join(file), bytes))
            .map_err(|e| format!("{}: {e}", self.dir.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::NameKey;
    use jig_core::naming::Root;
    use jig_pipeline::handshake::{
        HelloRefusal, HelloView, ServerOffer, negotiate, seal, seal_refusal,
    };

    fn did_of(key: &ed25519_dalek::SigningKey) -> String {
        jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    /// A welcome `key` signs, advertising `extra` beside what this build
    /// implements.
    fn welcome(key: &ed25519_dalek::SigningKey, extra: &[&str]) -> String {
        let mut statement = negotiate(
            &HelloView {
                versions: vec![1],
                suites: jig_pipeline::handshake::implemented_suite_names(),
                capabilities: Default::default(),
                nonce: jig_pipeline::handshake::fresh_nonce(),
                peer_did: None,
            },
            &ServerOffer::default(),
        )
        .unwrap();
        statement.suites.extend(extra.iter().map(|s| s.to_string()));
        serde_json::to_string(&seal(key, statement)).unwrap()
    }

    fn refusal(key: &ed25519_dalek::SigningKey) -> String {
        serde_json::to_string(&seal_refusal(
            key,
            &HelloRefusal::UnsupportedVersion("v1 only".into()),
            &jig_pipeline::handshake::fresh_nonce(),
        ))
        .unwrap()
    }

    fn bundle(key: &ed25519_dalek::SigningKey, proof: Option<Proof>) -> Bundle {
        Bundle {
            format: BUNDLE_FORMAT.into(),
            class: 3,
            code: "refusal-downgrade".into(),
            reason: "dropped rot13".into(),
            server: "https://host:7117".into(),
            server_did: did_of(key),
            observed_at_ms: 1_700_000_000_000,
            welcome: None,
            items: vec![],
            proof,
        }
    }

    #[test]
    fn a_downgrade_holds_only_with_both_signed_halves() {
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let proof = |pinned_welcome: String, refusal: String, suite: &str| {
            Some(Proof::Downgrade {
                pinned_welcome,
                refusal,
                suite: suite.into(),
            })
        };
        let good = bundle(
            &key,
            proof(welcome(&key, &["rot13"]), refusal(&key), "rot13"),
        );
        let checked = verify(&good).unwrap();
        assert!(checked.proven.unwrap().contains("rot13"));

        // A suite the refusal still lists, or the welcome never advertised.
        for suite in ["mls", "rot14"] {
            let b = bundle(&key, proof(welcome(&key, &["rot13"]), refusal(&key), suite));
            assert!(matches!(verify(&b), Err(BundleError::Proof(_))), "{suite}");
        }
        // Either half signed by someone else.
        let other = jig_core::crypto::ed25519::generate_signing_key();
        for b in [
            bundle(
                &key,
                proof(welcome(&other, &["rot13"]), refusal(&key), "rot13"),
            ),
            bundle(
                &key,
                proof(welcome(&key, &["rot13"]), refusal(&other), "rot13"),
            ),
            bundle(&key, proof(refusal(&key), refusal(&key), "rot13")),
        ] {
            assert!(matches!(verify(&b), Err(BundleError::Proof(_))));
        }
        // No proof: it verifies, and proves nothing.
        assert_eq!(verify(&bundle(&key, None)).unwrap().proven, None);
        // A welcome that is not the pinned DID's fails the bundle.
        let mut foreign = bundle(&key, None);
        foreign.welcome = Some(welcome(&other, &[]));
        assert!(matches!(verify(&foreign), Err(BundleError::Welcome { .. })));
        let mut renamed = bundle(&key, None);
        renamed.format = "jig-evidence-v0".into();
        assert!(matches!(verify(&renamed), Err(BundleError::Format(_))));
    }

    #[test]
    fn a_downgrade_proof_is_built_only_from_a_real_drop() {
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let did = did_of(&key);
        let pinned: std::collections::BTreeSet<String> = ["none", "mls", "rot13"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let w = welcome(&key, &["rot13"]);
        let proof = downgrade_proof(&w, &pinned, &refusal(&key), &did).unwrap();
        assert!(matches!(&proof, Proof::Downgrade { suite, .. } if suite == "rot13"));
        assert!(verify(&bundle(&key, Some(proof))).unwrap().proven.is_some());

        // The pinned welcome never advertised what the refusal drops.
        assert_eq!(
            downgrade_proof(&welcome(&key, &[]), &pinned, &refusal(&key), &did),
            None
        );
        // Nothing pinned is dropped.
        let kept: std::collections::BTreeSet<String> = ["mls".to_string()].into();
        assert_eq!(downgrade_proof(&w, &kept, &refusal(&key), &did), None);
        // Another server's refusal.
        let other = jig_core::crypto::ed25519::generate_signing_key();
        assert_eq!(downgrade_proof(&w, &pinned, &refusal(&other), &did), None);
    }

    #[test]
    fn bundles_are_kept_never_overwritten_and_listed() {
        let dir = tempfile::tempdir().unwrap();
        let store = EvidenceStore::new(dir.path());
        assert!(store.list().unwrap().is_empty());
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let first = bundle(&key, None);
        let a = store.keep(&first).unwrap();
        let b = store.keep(&first).unwrap();
        assert_ne!(a, b, "the same moment twice is two files");
        assert_eq!(a, "host_7117/1700000000000-refusal-downgrade");
        let mut later = first.clone();
        later.observed_at_ms += 1;
        later.code = "chain/../forked".into();
        let c = store.keep(&later).unwrap();
        assert_eq!(c, "host_7117/1700000000001-chain----forked");
        // Name evidence beside it is not a bundle.
        NameEvidenceDir::new(&dir.path().join("names"))
            .record(&NameEvidenceBundle {
                key: NameKey {
                    alias: "a".into(),
                    suffix: "b.example".into(),
                    root: Root::Dns,
                    root_id: "b.example".into(),
                },
                attestations: vec![],
                ns_dids: vec![],
                links: vec![],
                observed_at: 1,
            })
            .unwrap();
        let listed: Vec<String> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(listed, [a.clone(), b, c]);
        assert_eq!(store.get(&a).unwrap(), first);
        for id in [
            "../x",
            "host_7117/../../etc",
            "/etc/passwd",
            "a/b/c",
            "host_7117/",
        ] {
            assert!(store.get(id).is_err(), "{id}");
        }
    }

    #[test]
    fn a_bundle_is_kept_with_its_signed_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let store = NameEvidenceDir::new(dir.path());
        let bundle = NameEvidenceBundle {
            key: NameKey {
                alias: "alice".into(),
                suffix: "example.org".into(),
                root: Root::Dns,
                root_id: "example.org".into(),
            },
            attestations: vec![b"first".to_vec(), b"second".to_vec()],
            ns_dids: vec!["did:jig:zA".into(), "did:jig:zB".into()],
            links: vec![],
            observed_at: 1_700_000_000,
        };
        store.record(&bundle).unwrap();
        store.record(&bundle).unwrap();
        let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(files.len(), 1, "the same evidence is one file");
        let kept: serde_json::Value =
            serde_json::from_slice(&std::fs::read(files[0].as_ref().unwrap().path()).unwrap())
                .unwrap();
        assert_eq!(kept["format"], INTERIM_FORMAT);
        assert_eq!(kept["name"], "alice@example.org");
        assert_eq!(kept["attestations"][1], STANDARD.encode(b"second"));
        assert_eq!(kept["ns_dids"][1], "did:jig:zB");
    }
}
