//! What this device has seen of each server, kept so the server cannot
//! quietly change it (threat register OP-02, OP-03, OP-08).
//!
//! Trust on first use. The first signed welcome from a server pins the DID
//! that signed it and the suites it advertised; the first time this device
//! decides whether a channel is encrypted, it pins the channel's creation
//! block, read from the block the owner signed rather than the server's
//! unsigned listing. After that:
//!
//! - a welcome signed by another key fails closed (the handshake enforces the
//!   pinned DID; see [`Pins::offer`]);
//! - a welcome that no longer advertises a pinned suite is a downgrade, and
//!   refused;
//! - a channel whose creation block changed is a different channel under the
//!   same name, and refused.
//!
//! A pin is only as good as the first contact. It turns a server that lies
//! from then on into one that is caught; it does not make the first answer
//! true.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jig_core::{BlockKind, BlockManifest, Did};
use jig_pipeline::handshake::{ClientOffer, VerifiedWelcome};
use serde::{Deserialize, Serialize};

use crate::secure::server_key;

/// A refusal to go on with a server or channel that is not what was pinned.
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error(
        "{server} no longer advertises the `{suite}` suite it advertised before; refusing a \
         downgrade (if the operator really removed it, `jig server forget` drops the pin)"
    )]
    SuiteDropped { server: String, suite: String },
    #[error(
        "{slug} on {server} is not the channel this device pinned: its creation block was \
         {pinned}, the server now names {presented} (if it was deleted and re-created on \
         purpose, `jig server forget` drops the pins)"
    )]
    ChannelReplaced {
        server: String,
        slug: String,
        pinned: String,
        presented: String,
    },
    #[error(
        "{server} names itself {presented}, but this device pinned it as {pinned} (if its key \
         really changed, `jig server forget` drops the pin)"
    )]
    ServerReplaced {
        server: String,
        pinned: String,
        presented: String,
    },
    #[error("the creation block for {slug} does not prove its suite: {reason}")]
    Unproven { slug: String, reason: String },
    #[error("pin store {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("pin store {path}: {source}")]
    Corrupt {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

/// What this device pinned for one channel: the block that created it, the
/// suite that block names, and its signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelPin {
    pub create_cid: String,
    pub suite: String,
    pub owner_did: String,
}

impl ChannelPin {
    /// Anything but `none` is encrypted, including a suite this build does
    /// not know: a pin is never a reason to send in the clear.
    pub fn encrypted(&self) -> bool {
        self.suite != jig_core::EncryptionSuite::Unencrypted.as_str()
    }
}

/// What this device pinned for one server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPin {
    pub server_did: String,
    pub suites: BTreeSet<String>,
    #[serde(default)]
    pub channels: BTreeMap<String, ChannelPin>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PinFile {
    #[serde(default)]
    servers: BTreeMap<String, ServerPin>,
}

/// The store at `path`; a missing file is an empty store. A file that does
/// not parse is an error, never a silent reset: forgetting every pin is what
/// an attacker would want.
fn read(path: &Path) -> Result<PinFile, PinError> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| PinError::Corrupt {
            path: path.display().to_string(),
            source,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PinFile::default()),
        Err(source) => Err(PinError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// File servers pinned while the URL scheme was part of the key under the
/// key [`server_key`] gives them now. Returns whether any moved.
fn rekey(file: &mut PinFile) -> bool {
    let legacy: Vec<String> = file
        .servers
        .keys()
        .filter(|key| server_key(key) != **key)
        .cloned()
        .collect();
    for key in &legacy {
        let pin = file.servers.remove(key).expect("listed above");
        file.servers.entry(server_key(key)).or_insert(pin);
    }
    !legacy.is_empty()
}

/// The pin store: `~/.jig/pins.json` by default.
pub struct Pins {
    path: PathBuf,
    file: PinFile,
}

impl Pins {
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".jig")
            .join("pins.json")
    }

    /// Load the store at `path`; a missing file is an empty store. A file
    /// that does not parse is an error, never a silent reset: forgetting
    /// every pin is what an attacker would want.
    pub fn load(path: &Path) -> Result<Self, PinError> {
        let mut pins = Self {
            path: path.to_path_buf(),
            file: read(path)?,
        };
        // Stores written while the scheme was part of the key are saved
        // rekeyed, under the lock like any other change.
        if rekey(&mut pins.file) {
            pins.update(|_| Ok(((), false)))?;
        }
        Ok(pins)
    }

    pub fn server(&self, server: &str) -> Option<&ServerPin> {
        self.file.servers.get(&server_key(server))
    }

    /// The handshake offer for `server`: the default offer, with the pinned
    /// DID when there is one, so a welcome signed by another key fails closed.
    pub fn offer(&self, server: &str) -> ClientOffer {
        ClientOffer {
            pinned_server_did: self
                .server(server)
                .map(|p| p.server_did.clone())
                .filter(|did| !did.is_empty()),
            ..ClientOffer::default()
        }
    }

    /// Check a verified welcome from `server` against the pin, and pin it on
    /// first sight. The DID is the handshake's to enforce ([`Self::offer`]);
    /// here a suite the server advertised before and does not now is refused.
    /// Suites it adds are pinned too.
    pub fn check_welcome(
        &mut self,
        server: &str,
        welcome: &VerifiedWelcome,
    ) -> Result<(), PinError> {
        let advertised: BTreeSet<String> = welcome.suites.iter().cloned().collect();
        self.update(|file| {
            let key = server_key(server);
            let first = !file.servers.contains_key(&key);
            let pin = file.servers.entry(key).or_insert_with(|| ServerPin {
                server_did: welcome.server_did.clone(),
                ..ServerPin::default()
            });
            if let Some(dropped) = pin.suites.difference(&advertised).next() {
                return Err(PinError::SuiteDropped {
                    server: server.to_string(),
                    suite: dropped.clone(),
                });
            }
            let changed = first || pin.suites != advertised || pin.server_did != welcome.server_did;
            if changed {
                pin.suites = advertised;
                pin.server_did.clone_from(&welcome.server_did);
            }
            Ok(((), changed))
        })
    }

    /// Check the DID `server` names against the pin, and pin it on first
    /// sight. Used where no signed welcome is at hand, as when a TLS probe
    /// takes the DID a certificate is bound to.
    pub fn check_server_did(&mut self, server: &str, did: &str) -> Result<(), PinError> {
        self.update(|file| {
            let pin = file.servers.entry(server_key(server)).or_default();
            if pin.server_did.is_empty() {
                pin.server_did = did.to_string();
                return Ok(((), true));
            }
            if pin.server_did != did {
                return Err(PinError::ServerReplaced {
                    server: server.to_string(),
                    pinned: pin.server_did.clone(),
                    presented: did.to_string(),
                });
            }
            Ok(((), false))
        })
    }

    /// The pin for `slug` on `server`, if this device has one.
    pub fn channel(&self, server: &str, slug: &str) -> Option<&ChannelPin> {
        self.server(server).and_then(|p| p.channels.get(slug))
    }

    /// Check a channel's proven creation against the pin, and pin it on first
    /// sight. A different creation block under a pinned name is refused.
    pub fn check_channel(
        &mut self,
        server: &str,
        slug: &str,
        proven: ChannelPin,
    ) -> Result<ChannelPin, PinError> {
        self.update(|file| {
            let pin = file.servers.entry(server_key(server)).or_default();
            match pin.channels.get(slug) {
                Some(pinned) if pinned.create_cid == proven.create_cid => {
                    Ok((pinned.clone(), false))
                }
                Some(pinned) => Err(PinError::ChannelReplaced {
                    server: server.to_string(),
                    slug: slug.to_string(),
                    pinned: pinned.create_cid.clone(),
                    presented: proven.create_cid,
                }),
                None => {
                    pin.channels.insert(slug.to_string(), proven.clone());
                    Ok((proven, true))
                }
            }
        })
    }

    /// Drop everything pinned for `server`. Returns whether there was any.
    pub fn forget(&mut self, server: &str) -> Result<bool, PinError> {
        self.update(|file| {
            let had = file.servers.remove(&server_key(server)).is_some();
            Ok((had, had))
        })
    }

    /// Apply `change` to the store as it is on disk now, holding an exclusive
    /// lock from the read to the write, and save it when `change` reports a
    /// change. Two processes for one device (a `jig chat` beside a `jig
    /// send`) each pinning something would otherwise each write back their
    /// own copy, and the later one would erase the other's pin.
    fn update<T>(
        &mut self,
        change: impl FnOnce(&mut PinFile) -> Result<(T, bool), PinError>,
    ) -> Result<T, PinError> {
        let _lock = self.lock()?;
        self.file = read(&self.path)?;
        let rekeyed = rekey(&mut self.file);
        let (out, changed) = change(&mut self.file)?;
        if changed || rekeyed {
            self.save()?;
        }
        Ok(out)
    }

    /// The store's lock file, locked exclusively until the returned handle
    /// drops. Blocks while another process holds it.
    fn lock(&self) -> Result<std::fs::File, PinError> {
        let path = self.path.with_extension("json.lock");
        let io = |source| PinError::Io {
            path: path.display().to_string(),
            source,
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(io)?;
        file.lock().map_err(io)?;
        Ok(file)
    }

    /// Write the store through a temporary file and a rename, so a crash
    /// leaves the old store or the new one, never half of either.
    fn save(&self) -> Result<(), PinError> {
        let io = |source| PinError::Io {
            path: self.path.display().to_string(),
            source,
        };
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&self.file).expect("the pin file always serializes");
        std::fs::write(&tmp, bytes).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
        }
        std::fs::rename(&tmp, &self.path).map_err(io)
    }
}

/// Prove what `slug` was created as from its creation block, as the server
/// serves it (`GET /api/v1/blocks/{cid}`): the bundle must hash to `cid`
/// (the channel's id), be a `channel-create` for `slug`, and carry a
/// signature by its author. The suite and owner are then the author's
/// words, not the server's.
pub fn prove_channel(
    slug: &str,
    cid: &str,
    bundle_b64: &str,
    sig_b64: &str,
) -> Result<ChannelPin, PinError> {
    let unproven = |reason: &str| PinError::Unproven {
        slug: slug.to_string(),
        reason: reason.to_string(),
    };
    let bundle_bytes = STANDARD
        .decode(bundle_b64)
        .map_err(|_| unproven("the bundle is not base64"))?;
    let sig = STANDARD
        .decode(sig_b64)
        .map_err(|_| unproven("the signature is not base64"))?;
    let (manifest_bytes, code_bytes): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&bundle_bytes).map_err(|_| unproven("the bundle is malformed"))?;

    let bundle = jig_core::BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    };
    let actual = bundle
        .block_cid()
        .map_err(|_| unproven("its CID cannot be derived"))?;
    if actual.to_string() != cid {
        return Err(unproven(
            "the block served is not the one the channel names",
        ));
    }

    let manifest: BlockManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| unproven("the manifest is malformed"))?;
    if manifest.kind != Some(BlockKind::ChannelCreate) {
        return Err(unproven("it is not a channel-create"));
    }
    if manifest.metadata.get("slug").and_then(|v| v.as_str()) != Some(slug) {
        return Err(unproven("it creates a different channel"));
    }

    let author = manifest
        .authors
        .first()
        .map(|a| a.did.clone())
        .ok_or_else(|| unproven("it names no author"))?;
    let key_bytes = author
        .as_bytes()
        .map_err(|_| unproven("its author is not a did:jig key"))?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| unproven("bad author key"))?;
    let signature = Signature::from_slice(&sig).map_err(|_| unproven("bad signature"))?;
    let signed = serde_json::to_vec(&(&manifest_bytes, &code_bytes))
        .map_err(|_| unproven("the bundle cannot be re-encoded"))?;
    key.verify(&signed, &signature)
        .map_err(|_| unproven("its author did not sign it"))?;

    let suite = jig_pipeline::mls_gate::requested_suite(&manifest)
        .map_err(|_| unproven("it names a suite this client does not know"))?;
    Ok(ChannelPin {
        create_cid: cid.to_string(),
        suite: suite.as_str().to_string(),
        owner_did: Did::from_ed25519_pubkey(&key_bytes).to_did_jig_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocks::{build_channel_create, build_with_metadata};
    use crate::identity::Identity;
    use jig_core::HlcTimestamp;
    use serde_json::json;

    fn identity() -> Identity {
        Identity::generate_and_save(&tempfile::tempdir().unwrap().keep()).unwrap()
    }

    fn welcome(did: &str, suites: &[&str]) -> VerifiedWelcome {
        VerifiedWelcome {
            server_did: did.to_string(),
            version: 1,
            suites: suites.iter().map(|s| s.to_string()).collect(),
            capabilities: Default::default(),
            reputation: jig_pipeline::handshake::Reputation::none(),
            nonce: String::new(),
            evidence: String::new(),
        }
    }

    /// (bundle_b64, sig_b64, cid) as the server serves a creation block.
    fn served(id: &Identity, slug: &str, suite: Option<&str>) -> (String, String, String) {
        let hlc = HlcTimestamp::now_wall(id.did().clone());
        let block = match suite {
            None => build_channel_create(id, slug, "open", hlc),
            Some(s) => build_with_metadata(
                id,
                BlockKind::ChannelCreate,
                hlc,
                json!({"slug": slug, "visibility": "open", "suite": s}),
            ),
        };
        let bundle = jig_core::BlockBundle {
            manifest_bytes: &block.manifest_bytes,
            code_bytes: &block.code_bytes,
            resources: vec![],
        };
        (
            STANDARD.encode(block.canonical_bytes()),
            STANDARD.encode(&block.sender_sig),
            bundle.block_cid().unwrap().to_string(),
        )
    }

    #[test]
    fn a_channels_suite_is_its_creators_word() {
        let owner = identity();
        let (bundle, sig, cid) = served(&owner, "#ops", Some("mls"));
        let pin = prove_channel("#ops", &cid, &bundle, &sig).unwrap();
        assert!(pin.encrypted());
        assert_eq!(pin.owner_did, owner.did_string());

        let (bundle, sig, cid) = served(&owner, "#lobby", None);
        assert!(
            !prove_channel("#lobby", &cid, &bundle, &sig)
                .unwrap()
                .encrypted()
        );
    }

    /// A suite this build does not know is never read as plaintext.
    #[test]
    fn any_suite_but_none_is_encrypted() {
        let pin = |suite: &str| ChannelPin {
            create_cid: "bafy".into(),
            suite: suite.into(),
            owner_did: "did:jig:zA".into(),
        };
        assert!(!pin("none").encrypted());
        assert!(pin("mls").encrypted());
        assert!(pin("test-aead").encrypted());
        assert!(pin("signal-pqxdh").encrypted());
    }

    #[test]
    fn a_creation_block_the_server_cannot_have_is_no_proof() {
        let owner = identity();
        let (bundle, sig, cid) = served(&owner, "#ops", Some("mls"));
        let (other_bundle, other_sig, other_cid) = served(&owner, "#ops", Some("none"));

        // Another block than the channel names.
        assert!(prove_channel("#ops", &cid, &other_bundle, &other_sig).is_err());
        // The right block under another channel's name.
        assert!(prove_channel("#elsewhere", &cid, &bundle, &sig).is_err());
        // A signature by someone else.
        let (_, stranger_sig, _) = served(&identity(), "#ops", Some("none"));
        assert!(prove_channel("#ops", &other_cid, &other_bundle, &stranger_sig).is_err());
        // Not a creation at all.
        let hlc = HlcTimestamp::now_wall(owner.did().clone());
        let text = crate::blocks::build_text_render(&owner, "#ops", "hi", hlc);
        let text_cid = jig_core::BlockBundle {
            manifest_bytes: &text.manifest_bytes,
            code_bytes: &text.code_bytes,
            resources: vec![],
        }
        .block_cid()
        .unwrap()
        .to_string();
        assert!(
            prove_channel(
                "#ops",
                &text_cid,
                &STANDARD.encode(text.canonical_bytes()),
                &STANDARD.encode(&text.sender_sig)
            )
            .is_err()
        );
    }

    #[test]
    fn a_server_cannot_quietly_change_what_was_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let server = "ws://Host:7117/";
        let mut pins = Pins::load(&path).unwrap();
        assert_eq!(pins.offer(server).pinned_server_did, None);

        pins.check_welcome(server, &welcome("did:jig:zA", &["mls", "none"]))
            .unwrap();
        // Pinned, and under any spelling of the same server.
        let pins = Pins::load(&path).unwrap();
        assert_eq!(
            pins.offer("http://host:7117").pinned_server_did.as_deref(),
            Some("did:jig:zA")
        );
        let mut pins = pins;
        // Dropping `mls` is a downgrade.
        assert!(matches!(
            pins.check_welcome(server, &welcome("did:jig:zA", &["none"])),
            Err(PinError::SuiteDropped { suite, .. }) if suite == "mls"
        ));
        // Adding a suite is not.
        pins.check_welcome(server, &welcome("did:jig:zA", &["mls", "none", "x"]))
            .unwrap();

        let first = ChannelPin {
            create_cid: "bafyFirst".into(),
            suite: "mls".into(),
            owner_did: "did:jig:zOwner".into(),
        };
        assert_eq!(
            pins.check_channel(server, "#ops", first.clone()).unwrap(),
            first
        );
        let again = pins.check_channel(server, "#ops", first.clone()).unwrap();
        assert_eq!(again, first);
        let replaced = ChannelPin {
            create_cid: "bafySecond".into(),
            suite: "none".into(),
            ..first.clone()
        };
        assert!(matches!(
            pins.check_channel(server, "#ops", replaced),
            Err(PinError::ChannelReplaced { .. })
        ));
        assert_eq!(
            Pins::load(&path).unwrap().channel(server, "#ops"),
            Some(&first)
        );

        assert!(pins.forget(server).unwrap());
        assert!(Pins::load(&path).unwrap().server(server).is_none());
    }

    /// A TLS probe pins the DID a certificate is bound to; a different DID
    /// for the same server later is refused, under any scheme.
    #[test]
    fn a_probed_did_is_pinned_and_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let mut pins = Pins::load(&path).unwrap();
        pins.check_server_did("https://host:7117", "did:jig:zA")
            .unwrap();
        let mut pins = Pins::load(&path).unwrap();
        assert_eq!(
            pins.offer("http://host:7117").pinned_server_did.as_deref(),
            Some("did:jig:zA"),
            "turning TLS on does not lose the pin"
        );
        pins.check_server_did("wss://host:7117", "did:jig:zA")
            .unwrap();
        assert!(matches!(
            pins.check_server_did("https://host:7117", "did:jig:zB"),
            Err(PinError::ServerReplaced { .. })
        ));
    }

    /// Stores written while the scheme was part of the key are rekeyed when
    /// they are loaded.
    #[test]
    fn pins_written_with_a_scheme_are_rekeyed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        std::fs::write(
            &path,
            br#"{"servers":{"http://host:7117":{"server_did":"did:jig:zA","suites":["mls"]}}}"#,
        )
        .unwrap();
        let pins = Pins::load(&path).unwrap();
        assert_eq!(
            pins.server("https://host:7117")
                .map(|p| p.server_did.as_str()),
            Some("did:jig:zA")
        );
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("http://"), "{on_disk}");
    }

    /// Two processes that loaded the store before either pinned anything
    /// must both keep their pins: each change is made to the store as it is
    /// on disk, not to the copy loaded earlier.
    #[test]
    fn pins_from_two_processes_both_survive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let server = "https://host:7117";
        let (mut chat, mut send) = (Pins::load(&path).unwrap(), Pins::load(&path).unwrap());
        let pin = |cid: &str| ChannelPin {
            create_cid: cid.into(),
            suite: "mls".into(),
            owner_did: "did:jig:zOwner".into(),
        };
        chat.check_channel(server, "#a", pin("bafyA")).unwrap();
        send.check_channel(server, "#b", pin("bafyB")).unwrap();
        let on_disk = Pins::load(&path).unwrap();
        assert_eq!(on_disk.channel(server, "#a"), Some(&pin("bafyA")));
        assert_eq!(on_disk.channel(server, "#b"), Some(&pin("bafyB")));
        // And a later change is checked against what another process pinned.
        assert!(matches!(
            chat.check_channel(server, "#b", pin("bafyOther")),
            Err(PinError::ChannelReplaced { .. })
        ));
    }

    #[test]
    fn a_store_that_does_not_parse_is_an_error_not_a_reset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(Pins::load(&path), Err(PinError::Corrupt { .. })));
    }
}
