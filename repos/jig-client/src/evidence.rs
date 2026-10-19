//! Evidence a client keeps against the parties that signed it (design D11
//! item 9). Held by the submitter, never handed to a third party, so a
//! compromised server or nameserver cannot make it disappear.
//!
//! This first part keeps what name resolution acted on
//! ([`crate::naming::NameEvidence`]): every attestation and link exactly as
//! served, one file per resolution under `~/.jig/evidence/names/`. The signed
//! bytes are what make a file hold offline; the JSON around them is only an
//! index. Bundles against servers, and the `jig-evidence-v1` export, follow.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;

use crate::naming::{NameEvidence, NameEvidenceBundle};

/// Name evidence kept as files in one directory.
pub struct NameEvidenceDir {
    dir: PathBuf,
}

/// One kept resolution, as written to disk.
#[derive(Serialize)]
struct Kept<'a> {
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
        assert_eq!(kept["name"], "alice@example.org");
        assert_eq!(kept["attestations"][1], STANDARD.encode(b"second"));
        assert_eq!(kept["ns_dids"][1], "did:jig:zB");
    }
}
