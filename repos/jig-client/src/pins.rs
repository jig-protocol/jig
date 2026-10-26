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

use crate::naming::{Binding, NameKey, NamePin, NamePins};
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
    #[error(
        "{server} says {slug} is ordered by {sequencer}, another server, but does not prove \
         it: {reason}"
    )]
    CarriedUnproven {
        server: String,
        slug: String,
        sequencer: String,
        reason: String,
    },
    #[error(
        "{server} says {slug} is ordered by {presented}, but this device pinned it as ordered \
         by {pinned}; a channel's history is held to the server that orders it"
    )]
    SequencerChanged {
        server: String,
        slug: String,
        pinned: String,
        presented: String,
    },
    #[error(
        "{name} is pinned to {pinned}, but now resolves to {presented}; if its holder confirms \
         the change, `jig trust accept-name {name} --did {presented}` moves the pin"
    )]
    NameReplaced {
        name: String,
        pinned: String,
        presented: String,
    },
    #[error(
        "{name} resolves to {presented}, not the {confirmed} given; nothing was pinned (accept \
         only the DID its holder confirmed)"
    )]
    NameUnconfirmed {
        name: String,
        presented: String,
        confirmed: String,
    },
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
    /// The last record of the channel's `ingest` chain this device verified
    /// ([`crate::chain`]); the server is held to it on every later read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_head: Option<crate::chain::ChainHead>,
    /// The server that orders the channel when it is not the pinned server
    /// itself: a channel the pinned server carries for its owner (JEP-0005),
    /// proven by the owner's signed offer ([`prove_carried`]). Its records
    /// are held to this DID, never to the server serving them. `None` for a
    /// channel the pinned server orders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequencer: Option<String>,
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
    /// A welcome from this server that advertised [`Self::suites`],
    /// verbatim, so a later signed refusal that drops one can be shown with
    /// both halves ([`crate::evidence::Proof::Downgrade`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome: Option<String>,
    /// The `server-manifest` this device last checked a welcome against
    /// ([`crate::manifest`]); a welcome citing it needs no second check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<jig_pipeline::handshake::ManifestRef>,
    /// The public key links this pin moved along, and those the server
    /// served leading to its pinned DID, base64 as served: a later link out
    /// of one of their DIDs to another is a fork
    /// ([`crate::evidence::key_link_fork`]), and the DIDs they leave are the
    /// ones its earlier records are checked against ([`Self::sequencers`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<String>,
}

impl ServerPin {
    /// The DIDs this server signed as, in key-link order, ending at the one
    /// pinned: each hop of [`Self::links`] that leads to it, walking back
    /// from the pinned DID. A channel's earlier records are checked against
    /// them ([`crate::chain::ChannelChain::across`]).
    pub fn sequencers(&self) -> Vec<String> {
        dids_along(&self.links, &self.server_did)
    }
}

/// Add to `pin.links` each of `links` on the way to its pinned DID
/// ([`links_along`]). Returns whether any was new.
fn keep_links_on(pin: &mut ServerPin, links: &[String]) -> bool {
    let mut added = false;
    for link in links_along(links, &pin.server_did) {
        if !pin.links.contains(&link) {
            pin.links.push(link);
            added = true;
        }
    }
    added
}

/// The public key links among `links` (base64, as served) that lead to
/// `to`, oldest first: from `to`, the one link that moves to it, then the
/// one that moves to the DID that link leaves, and so on, each verified as
/// signed by both its keys (JEP-0012). The walk stops where no link, or more
/// than one, moves to the DID reached, where a DID repeats, and after
/// [`jig_pipeline::handshake::MAX_KEY_LINK_HOPS`] links. Order in `links`
/// does not matter.
pub fn links_along(links: &[String], to: &str) -> Vec<String> {
    use jig_core::key_link::{Audience, KeyLink, SignedKeyLink};
    use jig_pipeline::handshake::same_did;
    let mut verified: Vec<(&String, KeyLink)> = Vec::new();
    for b64 in links {
        let Some(signed) = STANDARD
            .decode(b64)
            .ok()
            .and_then(|bytes| SignedKeyLink::from_envelope(&bytes).ok())
        else {
            continue;
        };
        let link = signed.link();
        if link.audience == Audience::Public
            && !verified
                .iter()
                .any(|(_, l)| l.old == link.old && l.new == link.new)
        {
            verified.push((b64, link.clone()));
        }
    }
    let mut dids = vec![to.to_string()];
    let mut path = Vec::new();
    while path.len() < jig_pipeline::handshake::MAX_KEY_LINK_HOPS {
        let into: Vec<&(&String, KeyLink)> = verified
            .iter()
            .filter(|(_, l)| same_did(&l.new, &dids[0]))
            .collect();
        let [(b64, link)] = into.as_slice() else {
            break;
        };
        if dids.iter().any(|d| same_did(d, &link.old)) {
            break;
        }
        dids.insert(0, link.old.clone());
        path.insert(0, (*b64).clone());
    }
    path
}

/// The DIDs [`links_along`] passes through to reach `to`, oldest first and
/// ending at `to`.
pub fn dids_along(links: &[String], to: &str) -> Vec<String> {
    let mut dids: Vec<String> = links_along(links, to)
        .iter()
        .filter_map(|b64| STANDARD.decode(b64).ok())
        .filter_map(|bytes| jig_core::key_link::SignedKeyLink::from_envelope(&bytes).ok())
        .map(|signed| signed.link().old.clone())
        .collect();
    dids.push(to.to_string());
    dids
}

/// The key links a welcome carries, base64 as served, oldest first: its
/// `prior_key_links` then its `key_link`. Empty for text that is not a
/// welcome, or one with no link.
pub fn welcome_key_links(evidence: &str) -> Vec<String> {
    match jig_pipeline::envelope::Envelope::parse(evidence).map(|env| env.frame) {
        Ok(jig_pipeline::envelope::Frame::Welcome {
            key_link: Some(newest),
            prior_key_links,
            ..
        }) => prior_key_links.into_iter().chain([newest]).collect(),
        _ => Vec::new(),
    }
}

/// A server this device refuses until its user accepts it again, after it
/// signed a contradiction (JEP-0002 rule 16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StickyRefusal {
    /// The bundle that shows it ([`crate::evidence::EvidenceStore`] id).
    pub bundle: String,
    pub reason: String,
    pub at_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PinFile {
    #[serde(default)]
    servers: BTreeMap<String, ServerPin>,
    /// Servers refused after a signed contradiction, by server key. Kept
    /// apart from `servers` so that forgetting a server's pin does not lift
    /// its refusal: only [`Pins::accept_server`] does.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    refused: BTreeMap<String, StickyRefusal>,
    /// Name pins (JEP-0004 rule 17), one per [`NameKey`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    names: Vec<NamePinEntry>,
}

/// One pinned name: what it is keyed by (rule 6) and what it was bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamePinEntry {
    pub alias: String,
    pub suffix: String,
    /// `config`, `dns` or `contract`.
    pub root: String,
    pub root_id: String,
    pub did: String,
    pub ns_did: String,
    /// When the pinned attestation stops being valid: Unix seconds.
    pub valid_until: i64,
}

impl NamePinEntry {
    fn of(binding: &Binding) -> Self {
        Self {
            alias: binding.key.alias.clone(),
            suffix: binding.key.suffix.clone(),
            root: binding.key.root.as_str().to_string(),
            root_id: binding.key.root_id.clone(),
            did: binding.did().to_string(),
            ns_did: binding.attestation.ns_did.clone(),
            valid_until: binding.attestation.valid_until,
        }
    }

    fn is(&self, key: &NameKey) -> bool {
        self.alias == key.alias
            && self.suffix == key.suffix
            && self.root == key.root.as_str()
            && self.root_id == key.root_id
    }

    /// `alias@suffix`, as people write it.
    pub fn name(&self) -> String {
        format!("{}@{}", self.alias, self.suffix)
    }
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

/// A store written before DIDs had to be canonical may hold a key-derived DID
/// in another spelling. Such a pin is kept, not dropped or re-spelled: it
/// now matches no DID, so whatever it guards is refused, as for a replaced
/// key, and `jig server forget` clears it. Dropping it would turn the next
/// use into a first use; this only says why the refusals are coming.
fn warn_respelled(file: &PinFile) {
    let respelled = |did: &str| {
        matches!(
            jig_core::Did::from_str_unchecked(did).as_bytes(),
            Err(jig_core::DidError::NotLowercase)
        )
    };
    for (server, pin) in &file.servers {
        let dids =
            std::iter::once(&pin.server_did).chain(pin.channels.values().map(|c| &c.owner_did));
        for did in dids.filter(|d| respelled(d)) {
            tracing::warn!(
                "the pin for {server} holds a did:jig ({}) not in its canonical lowercase \
                 spelling; it will be refused (`jig server forget {server}` clears it)",
                jig_core::did::log_tag(did)
            );
        }
    }
    for entry in &file.names {
        for did in [&entry.did, &entry.ns_did]
            .into_iter()
            .filter(|d| respelled(d))
        {
            tracing::warn!(
                "a name pin holds a did:jig ({}) not in its canonical lowercase spelling; \
                 the name will be refused",
                jig_core::did::log_tag(did)
            );
        }
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
        warn_respelled(&pins.file);
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

    /// The servers pinned to `did`, as their pin keys: who this device knows
    /// a signature by `did` to come from. Empty for a DID no server is pinned
    /// to, whatever it signed.
    pub fn servers_pinned_to(&self, did: &str) -> Vec<&str> {
        self.file
            .servers
            .iter()
            .filter(|(_, pin)| !pin.server_did.is_empty() && pin.server_did == did)
            .map(|(server, _)| server.as_str())
            .collect()
    }

    /// The handshake offer for `server`: the default offer, with the pinned
    /// DID when there is one, so a welcome signed by another key fails closed,
    /// and the pinned suites, so a signed refusal that drops one is caught.
    pub fn offer(&self, server: &str) -> ClientOffer {
        let pin = self.server(server);
        ClientOffer {
            pinned_server_did: pin
                .map(|p| p.server_did.clone())
                .filter(|did| !did.is_empty()),
            pinned_suites: pin
                .map(|p| p.suites.iter().cloned().collect())
                .unwrap_or_default(),
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
            // A welcome signed by another DID than the pinned one moves the
            // pin only along key links that verify hop by hop forward from
            // the pinned DID to the welcome's (JEP-0012), as `move_server`
            // moves it. The welcome is the server's word, and over a
            // plaintext connection nothing else vouches for it, so anything
            // short of that is refused and nothing is recorded.
            if !pin.server_did.is_empty()
                && pin.server_did != welcome.server_did
                && !jig_pipeline::handshake::same_did(&pin.server_did, &welcome.server_did)
            {
                let replaced = || PinError::ServerReplaced {
                    server: server.to_string(),
                    pinned: pin.server_did.clone(),
                    presented: welcome.server_did.clone(),
                };
                if !welcome
                    .moved_from
                    .as_deref()
                    .is_some_and(|from| jig_pipeline::handshake::same_did(from, &pin.server_did))
                {
                    return Err(replaced());
                }
                let Ok(followed) = jig_pipeline::handshake::chain_moves(
                    &welcome_key_links(&welcome.evidence),
                    &pin.server_did,
                    &welcome.server_did,
                ) else {
                    return Err(replaced());
                };
                for link in followed {
                    if !pin.links.contains(&link) {
                        pin.links.push(link);
                    }
                }
                // What the old key's welcome was checked against says
                // nothing about the new one's.
                pin.manifest = None;
            }
            let changed = first
                || pin.suites != advertised
                || pin.server_did != welcome.server_did
                || pin.welcome.is_none();
            if changed {
                pin.suites = advertised;
                pin.server_did.clone_from(&welcome.server_did);
                pin.welcome = Some(welcome.evidence.clone());
            }
            // The links it serves to its DID, kept as `move_server` keeps
            // the hops it follows ([`ServerPin::sequencers`]).
            let kept = keep_links_on(pin, &welcome_key_links(&welcome.evidence));
            Ok(((), changed || kept))
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

    /// Move `server`'s pin from `from` to `to` along `key_links` (base64, as
    /// served, oldest first), which must be a chain of public links from the
    /// pinned key to `to` (JEP-0012). Checked here, whoever calls: a pin moves
    /// only along links that verify from it, hop by hop. The hops followed
    /// are kept, for fork detection later. Its channel pins stay; they name
    /// channels, not keys.
    pub fn move_server(
        &mut self,
        server: &str,
        from: &str,
        to: &str,
        key_links: &[String],
    ) -> Result<(), PinError> {
        self.update(|file| {
            let pin = file.servers.entry(server_key(server)).or_default();
            let replaced = || PinError::ServerReplaced {
                server: server.to_string(),
                pinned: pin.server_did.clone(),
                presented: to.to_string(),
            };
            if !jig_pipeline::handshake::same_did(&pin.server_did, from) {
                return Err(replaced());
            }
            let Ok(followed) = jig_pipeline::handshake::chain_moves(key_links, &pin.server_did, to)
            else {
                return Err(replaced());
            };
            pin.server_did = to.to_string();
            for link in followed {
                if !pin.links.contains(&link) {
                    pin.links.push(link);
                }
            }
            // The old key signed these, so they show nothing about the new
            // one: the next welcome is checked against its manifest afresh.
            pin.welcome = None;
            pin.manifest = None;
            Ok(((), true))
        })
    }

    /// Keep the key links `server` serves (base64, as served) that lead to
    /// the DID pinned for it, as [`Self::check_welcome`] does for a welcome's:
    /// for a server first pinned from a TLS probe, they are how its earlier
    /// DIDs' records are checked ([`ServerPin::sequencers`]).
    pub fn keep_links(&mut self, server: &str, links: &[String]) -> Result<(), PinError> {
        self.update(|file| {
            let Some(pin) = file.servers.get_mut(&server_key(server)) else {
                return Ok(((), false));
            };
            Ok(((), keep_links_on(pin, links)))
        })
    }

    /// Record that `server`'s welcome was checked against `manifest`.
    pub fn set_manifest(
        &mut self,
        server: &str,
        manifest: &jig_pipeline::handshake::ManifestRef,
    ) -> Result<(), PinError> {
        self.update(|file| {
            let pin = file.servers.entry(server_key(server)).or_default();
            let changed = pin.manifest.as_ref() != Some(manifest);
            pin.manifest = Some(manifest.clone());
            Ok(((), changed))
        })
    }

    /// The pin for `slug` on `server`, if this device has one.
    pub fn channel(&self, server: &str, slug: &str) -> Option<&ChannelPin> {
        self.server(server).and_then(|p| p.channels.get(slug))
    }

    /// The channel pinned on `server` under `reference`, a slug or the id of
    /// its creation block, with the slug it is pinned under.
    pub fn channel_by_ref(&self, server: &str, reference: &str) -> Option<(&str, &ChannelPin)> {
        let pins = &self.server(server)?.channels;
        pins.get_key_value(reference)
            .or_else(|| pins.iter().find(|(_, c)| c.create_cid == reference))
            .map(|(slug, pin)| (slug.as_str(), pin))
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

    /// Move the pinned chain head of `slug` on `server` to `head`, which the
    /// caller verified follows the pinned one ([`crate::chain::ChannelChain`]).
    /// A head behind the pinned one is ignored: pins never move backwards.
    /// Returns whether the channel is pinned at all.
    pub fn advance_chain(
        &mut self,
        server: &str,
        slug: &str,
        head: &crate::chain::ChainHead,
    ) -> Result<bool, PinError> {
        self.update(|file| {
            let Some(pin) = file
                .servers
                .get_mut(&server_key(server))
                .and_then(|p| p.channels.get_mut(slug))
            else {
                return Ok((false, false));
            };
            // A head in another record format is replaced, never compared:
            // see `ChainHead::is_current`.
            let ahead = pin
                .chain_head
                .as_ref()
                .is_none_or(|h| head.seq > h.seq || h.format != head.format);
            if ahead {
                pin.chain_head = Some(head.clone());
            }
            Ok((true, ahead))
        })
    }

    /// The channels pinned on `server` as carried for their owners, by
    /// channel id, each with its owner ([`Self::anchor_channel`]): what a
    /// live session holds their records to
    /// ([`crate::connection::ConnectOptions::carried`]).
    pub fn carried(&self, server: &str) -> std::collections::HashMap<String, String> {
        self.server(server)
            .map(|p| {
                p.channels
                    .values()
                    .filter_map(|c| Some((c.create_cid.clone(), c.sequencer.clone()?)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Hold `slug` on `server` to the server that orders it: `None` for
    /// `server` itself, else a DID [`prove_carried`] proved for the channel
    /// `create_cid`. The proof is for that channel only: if `slug` is pinned
    /// to another creation block, nothing moves and the substitution is
    /// [`PinError::ChannelReplaced`]. A channel
    /// pinned as `server`'s own may come to be carried for a proven owner
    /// (the server set its own copy aside and follows the owner, JEP-0005):
    /// its chain then starts again from the owner's records, the old head
    /// signed by another key. Nothing else moves the pin: not back to
    /// `server`, not to another owner. Returns whether the pin moved.
    pub fn anchor_channel(
        &mut self,
        server: &str,
        slug: &str,
        create_cid: &str,
        sequencer: Option<&str>,
    ) -> Result<bool, PinError> {
        self.update(|file| {
            let Some(pin) = file
                .servers
                .get_mut(&server_key(server))
                .and_then(|p| p.channels.get_mut(slug))
            else {
                return Ok((false, false));
            };
            if pin.create_cid != create_cid {
                return Err(PinError::ChannelReplaced {
                    server: server.to_string(),
                    slug: slug.to_string(),
                    pinned: pin.create_cid.clone(),
                    presented: create_cid.to_string(),
                });
            }
            match (pin.sequencer.as_deref(), sequencer) {
                (None, None) => Ok((false, false)),
                (Some(pinned), Some(presented)) if pinned == presented => Ok((false, false)),
                (None, Some(presented)) => {
                    pin.sequencer = Some(presented.to_string());
                    pin.chain_head = None;
                    Ok((true, true))
                }
                (Some(pinned), presented) => Err(PinError::SequencerChanged {
                    server: server.to_string(),
                    slug: slug.to_string(),
                    pinned: pinned.to_string(),
                    presented: presented.unwrap_or(server).to_string(),
                }),
            }
        })
    }

    /// Drop everything pinned for `server`. Returns whether there was any.
    /// Why `server` is refused, if it is: a contradiction it signed, kept as
    /// a bundle. Every connection to it, WebSocket or REST, stops here until
    /// [`Self::accept_server`].
    pub fn refusal(&self, server: &str) -> Option<&StickyRefusal> {
        self.file.refused.get(&server_key(server))
    }

    /// Refuse `server` from now on. A second contradiction keeps the first
    /// refusal, which is what its user has to answer.
    pub fn refuse(&mut self, server: &str, refusal: StickyRefusal) -> Result<(), PinError> {
        self.update(|file| {
            let key = server_key(server);
            if file.refused.contains_key(&key) {
                return Ok(((), false));
            }
            file.refused.insert(key, refusal);
            Ok(((), true))
        })
    }

    /// Lift `server`'s refusal (`jig trust accept`), returning it. Its pins
    /// stay: the server is held to them again from the next connection.
    pub fn accept_server(&mut self, server: &str) -> Result<Option<StickyRefusal>, PinError> {
        self.update(|file| {
            let lifted = file.refused.remove(&server_key(server));
            let changed = lifted.is_some();
            Ok((lifted, changed))
        })
    }

    pub fn forget(&mut self, server: &str) -> Result<bool, PinError> {
        self.update(|file| {
            let had = file.servers.remove(&server_key(server)).is_some();
            Ok((had, had))
        })
    }

    /// Pin the name `binding` verified, on first sight ([`crate::naming::Verified::New`]),
    /// or refresh a pin it matches (a renewed attestation). A different DID
    /// under a pinned name is refused: only [`Self::accept_name`] moves a pin.
    pub fn pin_name(&mut self, binding: &Binding) -> Result<(), PinError> {
        let entry = NamePinEntry::of(binding);
        self.update(
            |file| match file.names.iter_mut().find(|e| e.is(&binding.key)) {
                None => {
                    file.names.push(entry);
                    Ok(((), true))
                }
                Some(pinned) if pinned.did == entry.did => {
                    let changed = *pinned != entry;
                    *pinned = entry;
                    Ok(((), changed))
                }
                Some(pinned) => Err(PinError::NameReplaced {
                    name: pinned.name(),
                    pinned: pinned.did.clone(),
                    presented: entry.did,
                }),
            },
        )
    }

    /// Move `binding`'s name to the DID it now resolves to, because its holder
    /// confirmed `confirmed` out of band (rule 9). Refused unless the two
    /// agree, so a pin never moves to a DID nobody typed. Returns the DID the
    /// name was pinned to before, if any.
    pub fn accept_name(
        &mut self,
        binding: &Binding,
        confirmed: &str,
    ) -> Result<Option<String>, PinError> {
        let entry = NamePinEntry::of(binding);
        if entry.did != confirmed {
            return Err(PinError::NameUnconfirmed {
                name: entry.name(),
                presented: entry.did,
                confirmed: confirmed.to_string(),
            });
        }
        self.update(|file| {
            let old = file
                .names
                .iter()
                .position(|e| e.is(&binding.key))
                .map(|i| file.names.remove(i).did);
            file.names.push(entry);
            Ok((old, true))
        })
    }

    /// Every pinned name, for listing and expiry warnings.
    pub fn names(&self) -> &[NamePinEntry] {
        &self.file.names
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
    // A restricted channel's content is confidential from the operator (D25),
    // so a restricted creation under a suite the operator can read (`none`, or
    // `test-aead`, whose key is published) is no channel this client will post
    // to. A suite this client does not know was refused above. Anything but
    // `open` is restricted, as the server reads it.
    let open = manifest.metadata.get("visibility").and_then(|v| v.as_str()) == Some("open");
    if !open && !suite.is_operator_confidential() {
        return Err(unproven(
            "it creates a restricted channel under a suite the server's operator can read",
        ));
    }
    Ok(ChannelPin {
        create_cid: cid.to_string(),
        suite: suite.as_str().to_string(),
        owner_did: Did::from_ed25519_pubkey(&key_bytes).to_did_jig_string(),
        chain_head: None,
        sequencer: None,
    })
}

/// Whether `sequencer`, as a listing names it, is a server other than the
/// one whose DIDs are `server_dids` (its DID and those its key links lead
/// from). An empty name is the server's own.
pub fn names_another_server(server_dids: &[String], sequencer: &str) -> bool {
    let canonical = jig_pipeline::effect::canonical_did_string;
    !sequencer.is_empty()
        && !server_dids
            .iter()
            .any(|did| canonical(did) == canonical(sequencer))
}

/// Prove that `sequencer`, not the server serving it, orders the channel
/// created by `channel_id`, from the offer `sequencer` signed to that server
/// (base64, as the server lists it, JEP-0005 rule 7). The serving server's
/// word for who orders a channel is not taken: a follower naming another
/// sequencer, or itself, proves nothing. The offer must:
///
/// - verify as signed by `sequencer`;
/// - be for `channel_id`, with the creation block that hashes to it;
/// - be made to the serving server, one of `server_dids` (its DID and the
///   ones its key links lead from).
///
/// Returns the sequencer's DID, canonical.
pub fn prove_carried(
    server: &str,
    slug: &str,
    channel_id: &str,
    sequencer: &str,
    server_dids: &[String],
    offer_b64: Option<&str>,
) -> Result<String, PinError> {
    let unproven = |reason: &str| PinError::CarriedUnproven {
        server: server.to_string(),
        slug: slug.to_string(),
        sequencer: sequencer.to_string(),
        reason: reason.to_string(),
    };
    let canonical = jig_pipeline::effect::canonical_did_string;
    let offer_b64 = offer_b64.ok_or_else(|| unproven("it shows no offer from that server"))?;
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(offer_b64)
        .map_err(|_| unproven("its offer is not base64"))?;
    let offer = jig_core::contract::ContractOffer::from_envelope(&envelope)
        .map_err(|e| unproven(&format!("its offer does not verify: {e}")))?;
    if canonical(&offer.owner) != canonical(sequencer) {
        return Err(unproven("the offer is signed by another server"));
    }
    if offer.channel_id.to_string() != channel_id {
        return Err(unproven("the offer is for another channel"));
    }
    if !server_dids
        .iter()
        .any(|did| canonical(did) == canonical(&offer.to))
    {
        return Err(unproven("the offer was made to another server"));
    }
    let (manifest_bytes, code_bytes): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&offer.creation_block)
            .map_err(|_| unproven("the offer's creation block is malformed"))?;
    let created = jig_core::BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    }
    .block_cid()
    .map_err(|_| unproven("the offer's creation block is malformed"))?;
    if created.to_string() != channel_id {
        return Err(unproven("the offer's creation block is another channel's"));
    }
    Ok(canonical(sequencer))
}

/// The resolver's view of the pins (JEP-0004 rule 17): lookup only; the
/// caller pins with [`Pins::pin_name`] on a new binding.
impl NamePins for Pins {
    fn name_pin(&self, key: &NameKey) -> Option<NamePin> {
        self.file.names.iter().find(|e| e.is(key)).map(|e| NamePin {
            did: e.did.clone(),
            ns_did: e.ns_did.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocks::{build_channel_create, build_with_metadata};
    use crate::identity::Identity;
    use jig_core::HlcTimestamp;
    use serde_json::json;

    fn identity() -> Identity {
        Identity::generate_for_tests(&tempfile::tempdir().unwrap().keep())
    }

    fn welcome(did: &str, suites: &[&str]) -> VerifiedWelcome {
        VerifiedWelcome {
            server_did: did.to_string(),
            version: 1,
            suites: suites.iter().map(|s| s.to_string()).collect(),
            capabilities: Default::default(),
            reputation: jig_pipeline::handshake::Reputation::none(),
            nonce: String::new(),
            server_nonce: String::new(),
            tls_exporter: Vec::new(),
            manifest: None,
            admit: None,
            moved_from: None,
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
            chain_head: None,
            sequencer: None,
        };
        assert!(!pin("none").encrypted());
        assert!(pin("mls").encrypted());
        assert!(pin("test-aead").encrypted());
        assert!(pin("signal-pqxdh").encrypted());
    }

    #[test]
    fn a_restricted_channel_is_proven_only_as_mls() {
        let owner = identity();
        let hlc = HlcTimestamp::now_wall(owner.did().clone());
        let served_as = |visibility: &str, suite: Option<&str>| {
            let mut metadata = json!({"slug": "#ops", "visibility": visibility});
            if let Some(suite) = suite {
                metadata["suite"] = json!(suite);
            }
            let block =
                build_with_metadata(&owner, BlockKind::ChannelCreate, hlc.clone(), metadata);
            let cid = jig_core::BlockBundle {
                manifest_bytes: &block.manifest_bytes,
                code_bytes: &block.code_bytes,
                resources: vec![],
            }
            .block_cid()
            .unwrap()
            .to_string();
            prove_channel(
                "#ops",
                &cid,
                &STANDARD.encode(block.canonical_bytes()),
                &STANDARD.encode(&block.sender_sig),
            )
        };
        assert!(served_as("restricted", Some("mls")).unwrap().encrypted());
        for (visibility, suite) in [
            ("restricted", None),
            ("restricted", Some("none")),
            ("secret", Some("none")),
        ] {
            assert!(
                matches!(
                    served_as(visibility, suite),
                    Err(PinError::Unproven { reason, .. }) if reason.contains("restricted")
                ),
                "{visibility} {suite:?}"
            );
        }
        assert!(!served_as("open", None).unwrap().encrypted());
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
        assert_eq!(
            pins.offer(server).pinned_suites,
            vec!["mls".to_string(), "none".to_string()],
            "the offer carries the pinned suites, so a refusal cannot drop one"
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
            chain_head: None,
            sequencer: None,
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
            chain_head: None,
            sequencer: None,
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
    fn a_chain_head_only_moves_forward() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let server = "https://host:7117";
        let mut pins = Pins::load(&path).unwrap();
        let head = |seq: u64| crate::chain::ChainHead {
            format: crate::chain::RECORD_FORMAT.to_string(),
            seq,
            hash: format!("{seq:064x}"),
            ingest_wall_ms: seq,
            ingest_logical: 0,
            record: None,
        };
        assert!(
            !pins.advance_chain(server, "#ops", &head(1)).unwrap(),
            "not pinned"
        );
        pins.check_channel(
            server,
            "#ops",
            ChannelPin {
                create_cid: "bafyC".into(),
                suite: "mls".into(),
                owner_did: "did:jig:zOwner".into(),
                chain_head: None,
                sequencer: None,
            },
        )
        .unwrap();
        assert!(pins.advance_chain(server, "#ops", &head(5)).unwrap());
        pins.advance_chain(server, "#ops", &head(3)).unwrap();
        let reloaded = Pins::load(&path).unwrap();
        assert_eq!(
            reloaded.channel(server, "#ops").unwrap().chain_head,
            Some(head(5)),
            "a head behind the pinned one is ignored"
        );
        // A head pinned in an older format is replaced even from behind:
        // it cannot be compared with records in this one.
        let mut old = head(9);
        old.format = String::new();
        pins.advance_chain(server, "#ops", &old).unwrap();
        pins.advance_chain(server, "#ops", &head(2)).unwrap();
        assert_eq!(
            Pins::load(&path)
                .unwrap()
                .channel(server, "#ops")
                .unwrap()
                .chain_head,
            Some(head(2))
        );
    }

    #[test]
    fn a_refused_server_stays_refused_until_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let server = "https://host:7117";
        let mut pins = Pins::load(&path).unwrap();
        let mut w = welcome("did:jig:zS", &["none", "mls"]);
        w.evidence = "first".into();
        pins.check_welcome(server, &w).unwrap();
        w.evidence = "second".into();
        pins.check_welcome(server, &w).unwrap();
        assert_eq!(
            pins.server(server).unwrap().welcome.as_deref(),
            Some("first"),
            "a welcome that changes nothing is not written again"
        );

        let refusal = |bundle: &str| StickyRefusal {
            bundle: bundle.into(),
            reason: "forked".into(),
            at_ms: 1,
        };
        pins.refuse("wss://HOST:7117/", refusal("a")).unwrap();
        pins.refuse(server, refusal("b")).unwrap();
        let pins = Pins::load(&path).unwrap();
        assert_eq!(
            pins.refusal(server).unwrap().bundle,
            "a",
            "the first stands"
        );

        let mut pins = pins;
        assert!(pins.forget(server).unwrap());
        assert!(
            pins.refusal(server).is_some(),
            "forgetting the pin does not lift the refusal"
        );
        assert_eq!(pins.accept_server(server).unwrap().unwrap().bundle, "a");
        assert!(Pins::load(&path).unwrap().refusal(server).is_none());
        assert_eq!(pins.accept_server(server).unwrap(), None);
    }

    #[test]
    fn a_server_pin_moves_only_along_a_link_from_the_pinned_key() {
        use base64::Engine as _;
        use jig_core::key_link::{Audience, SignedKeyLink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let server = "https://host:7117";
        let key = jig_core::crypto::ed25519::generate_signing_key;
        let did = |k: &ed25519_dalek::SigningKey| {
            jig_core::Did::from_ed25519_pubkey(k.verifying_key().as_bytes()).to_did_jig_string()
        };
        let (old, new, stranger) = (key(), key(), key());
        let link = |a, b| {
            base64::engine::general_purpose::STANDARD.encode(
                SignedKeyLink::sign(a, b, Audience::Public, 1)
                    .unwrap()
                    .envelope(),
            )
        };
        let mut pins = Pins::load(&path).unwrap();
        pins.check_server_did(server, &did(&old)).unwrap();
        let mut signed_by_old = welcome(&did(&old), &["none"]);
        signed_by_old.evidence = "the old key's welcome".into();
        pins.check_welcome(server, &signed_by_old).unwrap();

        // From a key nobody pinned, or claiming to leave one it does not.
        for (from, link) in [
            (did(&stranger), link(&stranger, &new)),
            (did(&old), link(&stranger, &new)),
        ] {
            assert!(matches!(
                pins.move_server(server, &from, &did(&new), std::slice::from_ref(&link)),
                Err(PinError::ServerReplaced { .. })
            ));
        }
        assert_eq!(pins.server(server).unwrap().server_did, did(&old));

        pins.move_server(server, &did(&old), &did(&new), &[link(&old, &new)])
            .unwrap();
        let pins = Pins::load(&path).unwrap();
        assert_eq!(pins.server(server).unwrap().server_did, did(&new));
        assert_eq!(pins.server(server).unwrap().links, [link(&old, &new)]);
        assert_eq!(
            pins.server(server).unwrap().welcome,
            None,
            "a welcome the old key signed is not kept as the new key's"
        );
        assert_eq!(pins.server(server).unwrap().manifest, None);
    }

    /// A welcome that moved the pin itself (no TLS probe in front) leaves
    /// the hops it followed in the pin, so the DIDs before the current one
    /// are known: the history they signed checks against them.
    #[test]
    fn a_welcome_that_moves_the_pin_keeps_the_hops_and_the_dids_along_them() {
        use base64::Engine as _;
        use jig_core::key_link::{Audience, SignedKeyLink};
        use jig_pipeline::envelope::{Envelope, Frame};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let server = "ws://127.0.0.1:7117";
        let key = jig_core::crypto::ed25519::generate_signing_key;
        let did = |k: &ed25519_dalek::SigningKey| {
            jig_core::Did::from_ed25519_pubkey(k.verifying_key().as_bytes()).to_did_jig_string()
        };
        let (a, b, c) = (key(), key(), key());
        let link = |x, y| {
            base64::engine::general_purpose::STANDARD.encode(
                SignedKeyLink::sign(x, y, Audience::Public, 1)
                    .unwrap()
                    .envelope(),
            )
        };
        let signed_by = |k: &ed25519_dalek::SigningKey, links: &[String], moved: Option<String>| {
            let (newest, prior) = match links.split_last() {
                Some((n, p)) => (Some(n.clone()), p.to_vec()),
                None => (None, Vec::new()),
            };
            let mut w = welcome(&did(k), &["none"]);
            w.moved_from = moved;
            w.evidence = serde_json::to_string(&Envelope::new(Frame::Welcome {
                server_did: did(k),
                suites: vec!["none".into()],
                capabilities: Default::default(),
                reputation: jig_pipeline::handshake::Reputation::none(),
                nonce: "n".into(),
                server_nonce: "s".into(),
                tls_exporter: String::new(),
                manifest: None,
                key_link: newest,
                admit: None,
                prior_key_links: prior,
                sig: String::new(),
            }))
            .unwrap();
            w
        };
        let (ab, bc) = (link(&a, &b), link(&b, &c));
        assert_eq!(
            welcome_key_links(&signed_by(&c, &[ab.clone(), bc.clone()], None).evidence),
            [ab.clone(), bc.clone()]
        );
        assert!(welcome_key_links("not a frame").is_empty());

        let mut pins = Pins::load(&path).unwrap();
        pins.check_welcome(server, &signed_by(&a, &[], None))
            .unwrap();
        assert_eq!(pins.server(server).unwrap().sequencers(), [did(&a)]);
        pins.check_welcome(
            server,
            &signed_by(&b, std::slice::from_ref(&ab), Some(did(&a))),
        )
        .unwrap();
        pins.check_welcome(
            server,
            &signed_by(&c, &[ab.clone(), bc.clone()], Some(did(&b))),
        )
        .unwrap();
        let pinned = Pins::load(&path).unwrap().server(server).unwrap().clone();
        assert_eq!(pinned.server_did, did(&c));
        assert_eq!(pinned.links, [ab.clone(), bc.clone()]);
        assert_eq!(pinned.sequencers(), [did(&a), did(&b), did(&c)]);

        // Only links that lead to the pinned DID count, in any order; two
        // that move to one DID lead nowhere.
        let (s1, s2, s3) = (key(), key(), key());
        let stray = link(&s1, &s2);
        assert_eq!(
            dids_along(&[bc.clone(), stray.clone(), ab.clone()], &did(&c)),
            [did(&a), did(&b), did(&c)]
        );
        assert_eq!(dids_along(&[ab.clone(), bc.clone()], &did(&a)), [did(&a)]);
        assert_eq!(dids_along(&[stray], &did(&c)), [did(&c)]);
        let also_to_b = link(&s3, &b);
        assert_eq!(
            dids_along(&[ab.clone(), also_to_b, bc.clone()], &did(&c)),
            [did(&b), did(&c)]
        );

        // A server first pinned at its newest DID keeps the chain it serves.
        let fresh = "ws://127.0.0.1:7118";
        let mut pins = Pins::load(&path).unwrap();
        pins.check_welcome(fresh, &signed_by(&c, &[ab.clone(), bc.clone()], None))
            .unwrap();
        assert_eq!(
            pins.server(fresh).unwrap().sequencers(),
            [did(&a), did(&b), did(&c)]
        );
        let probed = "https://probed:7117";
        pins.check_server_did(probed, &did(&c)).unwrap();
        pins.keep_links(probed, &[ab, bc]).unwrap();
        assert_eq!(
            Pins::load(&path)
                .unwrap()
                .server(probed)
                .unwrap()
                .sequencers(),
            [did(&a), did(&b), did(&c)]
        );
    }

    /// A welcome from another DID moves the pin only along links that chain
    /// forward from the pinned DID; a forged or unchained one, or none,
    /// leaves the pin as it was and is refused.
    #[test]
    fn a_welcome_with_links_that_do_not_chain_from_the_pin_is_refused() {
        use base64::Engine as _;
        use jig_core::key_link::{Audience, SignedKeyLink};
        use jig_pipeline::envelope::{Envelope, Frame};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let server = "ws://127.0.0.1:7117";
        let key = jig_core::crypto::ed25519::generate_signing_key;
        let did = |k: &ed25519_dalek::SigningKey| {
            jig_core::Did::from_ed25519_pubkey(k.verifying_key().as_bytes()).to_did_jig_string()
        };
        let (pinned, new, stranger, middle) = (key(), key(), key(), key());
        let link = |x, y| {
            base64::engine::general_purpose::STANDARD.encode(
                SignedKeyLink::sign(x, y, Audience::Public, 1)
                    .unwrap()
                    .envelope(),
            )
        };
        let signed_by = |links: Vec<String>, moved: Option<String>| {
            let (newest, prior) = match links.split_last() {
                Some((n, p)) => (Some(n.clone()), p.to_vec()),
                None => (None, Vec::new()),
            };
            let mut w = welcome(&did(&new), &["none"]);
            w.moved_from = moved;
            w.evidence = serde_json::to_string(&Envelope::new(Frame::Welcome {
                server_did: did(&new),
                suites: vec!["none".into()],
                capabilities: Default::default(),
                reputation: jig_pipeline::handshake::Reputation::none(),
                nonce: "n".into(),
                server_nonce: "s".into(),
                tls_exporter: String::new(),
                manifest: None,
                key_link: newest,
                admit: None,
                prior_key_links: prior,
                sig: String::new(),
            }))
            .unwrap();
            w
        };
        let mut pins = Pins::load(&path).unwrap();
        pins.check_welcome(server, &welcome(&did(&pinned), &["none"]))
            .unwrap();
        let before = Pins::load(&path).unwrap().server(server).unwrap().clone();

        // A link whose old key's signature is damaged: the envelope ends
        // with the new key's signature (72 bytes with its headers), and the
        // old key's 64 bytes come just before.
        let mut forged = SignedKeyLink::sign(&pinned, &new, Audience::Public, 1)
            .unwrap()
            .envelope()
            .to_vec();
        let at = forged.len() - 72 - 1;
        forged[at] ^= 1;
        assert!(SignedKeyLink::from_envelope(&forged).is_err());
        let forged = base64::engine::general_purpose::STANDARD.encode(&forged);

        for (case, w) in [
            ("no moved_from", signed_by(vec![link(&pinned, &new)], None)),
            ("no link", signed_by(vec![], Some(did(&pinned)))),
            (
                "a link from another DID",
                signed_by(vec![link(&stranger, &new)], Some(did(&pinned))),
            ),
            (
                "a chain that skips the pin",
                signed_by(
                    vec![link(&stranger, &middle), link(&middle, &new)],
                    Some(did(&pinned)),
                ),
            ),
            (
                "moved_from another DID",
                signed_by(vec![link(&stranger, &new)], Some(did(&stranger))),
            ),
            (
                "a forged signature",
                signed_by(vec![forged.clone()], Some(did(&pinned))),
            ),
        ] {
            assert!(
                matches!(
                    pins.check_welcome(server, &w),
                    Err(PinError::ServerReplaced { .. })
                ),
                "{case}"
            );
            assert_eq!(
                Pins::load(&path).unwrap().server(server).unwrap(),
                &before,
                "{case}: the pin is as it was"
            );
        }

        // The real chain moves it.
        pins.check_welcome(
            server,
            &signed_by(vec![link(&pinned, &new)], Some(did(&pinned))),
        )
        .unwrap();
        let after = Pins::load(&path).unwrap().server(server).unwrap().clone();
        assert_eq!(after.server_did, did(&new));
        assert_eq!(after.sequencers(), [did(&pinned), did(&new)]);
    }

    #[test]
    fn a_store_that_does_not_parse_is_an_error_not_a_reset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(Pins::load(&path), Err(PinError::Corrupt { .. })));
    }

    fn binding(did: &str, valid_until: i64) -> crate::naming::Binding {
        crate::naming::Binding {
            key: NameKey {
                alias: "alice".into(),
                suffix: "example.org".into(),
                root: jig_core::naming::Root::Dns,
                root_id: "example.org".into(),
            },
            attestation: jig_core::naming::Attestation {
                did: did.into(),
                alias: "alice@example.org".into(),
                ns_did: "did:jig:zNs".into(),
                valid_from: 0,
                valid_until,
                envelope: vec![],
            },
            reachability: None,
        }
    }

    #[test]
    fn a_name_is_pinned_once_and_only_accepted_onto_another_did() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let mut pins = Pins::load(&path).unwrap();
        let first = binding("did:jig:zAlice", 100);
        assert_eq!(pins.name_pin(&first.key), None);
        pins.pin_name(&first).unwrap();
        // A renewed attestation for the same DID refreshes the pin.
        pins.pin_name(&binding("did:jig:zAlice", 200)).unwrap();
        let reloaded = Pins::load(&path).unwrap();
        assert_eq!(
            reloaded.name_pin(&first.key),
            Some(NamePin {
                did: "did:jig:zAlice".into(),
                ns_did: "did:jig:zNs".into()
            })
        );
        assert_eq!(reloaded.names()[0].valid_until, 200);

        // Another DID under the pinned name is refused, not pinned.
        let other = binding("did:jig:zMallory", 300);
        assert!(matches!(
            pins.pin_name(&other),
            Err(PinError::NameReplaced { .. })
        ));
        // Accepting needs the DID the holder confirmed, exactly.
        assert!(matches!(
            pins.accept_name(&other, "did:jig:zSomeoneElse"),
            Err(PinError::NameUnconfirmed { .. })
        ));
        assert_eq!(
            Pins::load(&path).unwrap().name_pin(&first.key).unwrap().did,
            "did:jig:zAlice"
        );
        assert_eq!(
            pins.accept_name(&other, "did:jig:zMallory").unwrap(),
            Some("did:jig:zAlice".into())
        );
        let moved = Pins::load(&path).unwrap();
        assert_eq!(moved.name_pin(&first.key).unwrap().did, "did:jig:zMallory");
        assert_eq!(moved.names().len(), 1, "one pin per name");
    }

    #[test]
    fn a_name_under_another_root_is_another_pin() {
        let dir = tempfile::tempdir().unwrap();
        let mut pins = Pins::load(&dir.path().join("pins.json")).unwrap();
        let dns = binding("did:jig:zAlice", 100);
        let mut config = binding("did:jig:zOther", 100);
        config.key.root = jig_core::naming::Root::Config;
        pins.pin_name(&dns).unwrap();
        pins.pin_name(&config).unwrap();
        assert_eq!(pins.name_pin(&dns.key).unwrap().did, "did:jig:zAlice");
        assert_eq!(pins.name_pin(&config.key).unwrap().did, "did:jig:zOther");
    }

    // ---- Channels a server carries for their owners ------------------------

    struct Carried {
        owner: ed25519_dalek::SigningKey,
        follower: String,
        channel_id: String,
        offer_b64: String,
    }

    /// A channel created on `owner`'s server and offered to `follower`.
    fn carried() -> Carried {
        use base64::Engine as _;
        let owner = jig_core::crypto::ed25519::generate_signing_key();
        let follower = Did::from_ed25519_pubkey(
            jig_core::crypto::ed25519::generate_signing_key()
                .verifying_key()
                .as_bytes(),
        )
        .to_did_jig_string();
        let create = build_channel_create(
            &identity(),
            "#team",
            "open",
            HlcTimestamp::now_wall(Did::from_ed25519_pubkey(&[1; 32])),
        );
        let creation_block =
            serde_json::to_vec(&(&create.manifest_bytes, &create.code_bytes)).unwrap();
        let channel_id = jig_core::BlockBundle {
            manifest_bytes: &create.manifest_bytes,
            code_bytes: &create.code_bytes,
            resources: vec![],
        }
        .block_cid()
        .unwrap();
        let offer = jig_core::contract::ContractOffer::sign(
            &owner,
            &follower,
            channel_id,
            jig_core::contract::Grant::Read,
            creation_block,
            Vec::new(),
            jig_core::contract::ManifestRef {
                cid: channel_id,
                seq: 0,
            },
            Vec::new(),
        );
        Carried {
            owner,
            follower,
            channel_id: channel_id.to_string(),
            offer_b64: base64::engine::general_purpose::STANDARD.encode(&offer.envelope),
        }
    }

    fn did_of_key(key: &ed25519_dalek::SigningKey) -> String {
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    #[test]
    fn the_owners_offer_proves_who_orders_a_carried_channel() {
        let c = carried();
        let owner = did_of_key(&c.owner);
        let prove = |sequencer: &str, to: &[String], offer: Option<&str>, channel: &str| {
            prove_carried("wss://follower", "#team", channel, sequencer, to, offer)
        };
        let ours = vec![c.follower.clone()];
        assert_eq!(
            prove(&owner, &ours, Some(&c.offer_b64), &c.channel_id).unwrap(),
            owner
        );

        // The follower's word alone proves nothing.
        assert!(matches!(
            prove(&owner, &ours, None, &c.channel_id),
            Err(PinError::CarriedUnproven { .. })
        ));
        // A follower naming a third server as sequencer, with the real
        // owner's offer: the offer is not that server's.
        let third = did_of_key(&jig_core::crypto::ed25519::generate_signing_key());
        assert!(matches!(
            prove(&third, &ours, Some(&c.offer_b64), &c.channel_id),
            Err(PinError::CarriedUnproven { .. })
        ));
        // An offer made to another server, replayed here.
        assert!(matches!(
            prove(
                &owner,
                std::slice::from_ref(&third),
                Some(&c.offer_b64),
                &c.channel_id
            ),
            Err(PinError::CarriedUnproven { .. })
        ));
        // The offer for another channel.
        let other = carried();
        assert!(matches!(
            prove(&owner, &ours, Some(&other.offer_b64), &c.channel_id),
            Err(PinError::CarriedUnproven { .. })
        ));
        // A forged one.
        let mut forged = base64::engine::general_purpose::STANDARD
            .decode(&c.offer_b64)
            .unwrap();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let forged = base64::engine::general_purpose::STANDARD.encode(&forged);
        assert!(matches!(
            prove(&owner, &ours, Some(&forged), &c.channel_id),
            Err(PinError::CarriedUnproven { .. })
        ));
    }

    /// Once a channel is pinned as carried for its owner, the server serving
    /// it cannot take it back as its own, nor name another owner. A channel
    /// pinned as the server's own may come to be carried (the server set its
    /// copy aside and follows the owner): its chain then starts again.
    #[test]
    fn who_orders_a_channel_moves_one_way() {
        let dir = tempfile::tempdir().unwrap();
        let mut pins = Pins::load(&dir.path().join("pins.json")).unwrap();
        let server = "wss://follower";
        let head = crate::chain::ChainHead {
            format: crate::chain::RECORD_FORMAT.to_string(),
            seq: 3,
            hash: "aa".to_string(),
            ingest_wall_ms: 1,
            ingest_logical: 0,
            record: None,
        };
        pins.check_channel(
            server,
            "#team",
            ChannelPin {
                create_cid: "bafycreate".to_string(),
                suite: "none".to_string(),
                owner_did: "did:jig:zuser".to_string(),
                chain_head: None,
                sequencer: None,
            },
        )
        .unwrap();
        pins.advance_chain(server, "#team", &head).unwrap();
        assert!(
            !pins
                .anchor_channel(server, "#team", "bafycreate", None)
                .unwrap()
        );

        assert!(
            pins.anchor_channel(server, "#team", "bafycreate", Some("did:jig:zowner"))
                .unwrap()
        );
        let pin = pins.channel(server, "#team").unwrap();
        assert_eq!(pin.sequencer.as_deref(), Some("did:jig:zowner"));
        assert_eq!(pin.chain_head, None, "the owner's chain starts afresh");
        assert_eq!(
            pins.carried(server).get("bafycreate").map(String::as_str),
            Some("did:jig:zowner")
        );
        assert!(
            !pins
                .anchor_channel(server, "#team", "bafycreate", Some("did:jig:zowner"))
                .unwrap()
        );

        // A hostile follower naming itself, or another server.
        assert!(matches!(
            pins.anchor_channel(server, "#team", "bafycreate", None),
            Err(PinError::SequencerChanged { .. })
        ));
        assert!(matches!(
            pins.anchor_channel(server, "#team", "bafycreate", Some("did:jig:zother")),
            Err(PinError::SequencerChanged { .. })
        ));
        assert_eq!(
            pins.channel(server, "#team").unwrap().sequencer.as_deref(),
            Some("did:jig:zowner")
        );
    }

    /// A follower cannot re-point a pinned slug at another channel with a
    /// valid proof for that other channel. `#team` is pinned on the follower
    /// as its own channel Y; the follower then lists `#team` as X, a channel
    /// it does carry for the owner, with the owner's real offer for X. The
    /// proof holds for X, but the slug stays bound to Y.
    #[test]
    fn a_valid_proof_for_one_channel_cannot_re_point_a_slug_pinned_to_another() {
        let dir = tempfile::tempdir().unwrap();
        let mut pins = Pins::load(&dir.path().join("pins.json")).unwrap();
        let server = "wss://follower";
        let local = "bafylocalteam".to_string();
        let pin = |create_cid: &str| ChannelPin {
            create_cid: create_cid.to_string(),
            suite: "none".to_string(),
            owner_did: "did:jig:zuser".to_string(),
            chain_head: None,
            sequencer: None,
        };
        pins.check_channel(server, "#team", pin(&local)).unwrap();

        let x = carried();
        let owner = did_of_key(&x.owner);
        assert_ne!(x.channel_id, local);
        // The proof is sound for X.
        assert_eq!(
            prove_carried(
                server,
                "#team",
                &x.channel_id,
                &owner,
                std::slice::from_ref(&x.follower),
                Some(&x.offer_b64)
            )
            .unwrap(),
            owner
        );
        // The creation check refuses X under the slug pinned to Y.
        assert!(matches!(
            pins.check_channel(server, "#team", pin(&x.channel_id)),
            Err(PinError::ChannelReplaced { .. })
        ));
        // And so does the anchor, on its own.
        assert!(matches!(
            pins.anchor_channel(server, "#team", &x.channel_id, Some(&owner)),
            Err(PinError::ChannelReplaced { .. })
        ));
        let after = pins.channel(server, "#team").unwrap();
        assert_eq!(after.create_cid, local);
        assert_eq!(after.sequencer, None);
        assert!(pins.carried(server).is_empty());
        assert_eq!(pins.channel_by_ref(server, &x.channel_id), None);
    }
}
