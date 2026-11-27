//! The two block kinds that move standing in a channel (JEP-0005 rules 11a
//! and 7b): what their metadata says, and the checks a reader can make from
//! the block and its `ingest` record alone.
//!
//! - **`sequencer-set`**: the channel's owner moves the job of signing its
//!   records to another server. The block names the new sequencer and the
//!   last record the old one signed (the *cited head*), and carries the new
//!   sequencer's move accept ([`ContractAccept::is_move`]). Its own record is
//!   signed by the new sequencer, at the cited head's `seq` + 1, after it.
//! - **`key-link`**: a member that changed its key moves its roles and its
//!   membership in this channel to the new DID, with a JEP-0012 link whose
//!   audience is this channel.
//!
//! Neither kind is a [`crate::BlockKind`] yet: a build that names them there
//! implements them, and a reader that does not must stop the channel at them
//! (rule 14c). Both names lack the `opt-` prefix, so they are critical.
//!
//! Who may sign a block of either kind, and what follows from it in the
//! chain, is the caller's: this module checks what the bytes say.

use std::collections::BTreeMap;

use base64::Engine as _;
use serde_json::Value;

use crate::contract::{ContractAccept, ContractError};
use crate::did::Did;
use crate::key_link::{Audience, KeyLinkError, SignedKeyLink};

/// The kind name of the block that moves a channel's sequencer.
pub const SEQUENCER_SET_KIND: &str = "sequencer-set";
/// The kind name of the block that moves a member's standing to a new DID.
pub const KEY_LINK_KIND: &str = "key-link";

/// The metadata keys a `sequencer-set` carries.
pub mod keys {
    pub const CHANNEL_ID: &str = "channel_id";
    pub const SEQUENCER: &str = "sequencer";
    pub const HEAD: &str = "head";
    pub const HEAD_SEQ: &str = "seq";
    pub const HEAD_HASH: &str = "hash";
    pub const ACCEPT: &str = "accept";
    pub const REINSTALLS: &str = "reinstalls";
    pub const LINK: &str = "link";
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MoveError {
    #[error("`{0}` is missing or malformed")]
    Field(&'static str),
    #[error("`{0}` is not a did:jig DID in its canonical spelling")]
    NotCanonical(String),
    #[error("the move accept does not verify: {0}")]
    Accept(ContractError),
    #[error("the accept is not a move accept by the new sequencer for this channel: {0}")]
    NotTheMove(&'static str),
    #[error("the accept names {bots} bot DIDs for {reinstalls} reinstalls")]
    BotsAndReinstalls { bots: usize, reinstalls: usize },
    #[error("the key link does not verify: {0}")]
    Link(KeyLinkError),
    #[error("the key link is not for this channel")]
    OtherAudience,
    #[error("the key link moves to {link}, not to the block's author {author}")]
    NotTheAuthor { link: String, author: String },
    #[error("the record is not the set's: {0}")]
    NotItsRecord(&'static str),
}

/// The last record the old sequencer signed, as a `sequencer-set` cites it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CitedHead {
    pub seq: u64,
    /// The record's hash, as the next record's `prev` names it.
    pub hash: [u8; 32],
}

/// A `sequencer-set` block's metadata, read and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencerSet {
    /// The channel, as the block names it: the CID of its creation block.
    pub channel_id: String,
    /// The new sequencer's DID, canonical.
    pub sequencer: String,
    pub head: CitedHead,
    /// The new sequencer's move accept, verified.
    pub accept: ContractAccept,
    /// The owner-signed `block-install`s for the channel's bots under the new
    /// sequencer (lane C's format), as bytes; one per bot DID the accept
    /// names. Empty until lane C defines them.
    pub reinstalls: Vec<Vec<u8>>,
}

impl SequencerSet {
    /// Read a `sequencer-set` from its block's metadata. Other keys the
    /// block carries (`seen`, and the keys every block may carry) are not
    /// this module's, and are left alone.
    ///
    /// Checks:
    /// - `sequencer` is a canonical did:jig;
    /// - `head` is exactly `{seq, hash}`, `hash` 64 lowercase hex digits;
    /// - `accept` is a base64 [`ContractAccept`] that verifies, is a move
    ///   accept, is signed by `sequencer`, and is for `channel_id`;
    /// - `reinstalls` is an array of base64, one per bot DID in the accept.
    pub fn from_metadata(meta: &BTreeMap<String, Value>) -> Result<Self, MoveError> {
        let channel_id = text(meta, keys::CHANNEL_ID)?;
        let sequencer = text(meta, keys::SEQUENCER)?;
        if !is_canonical_did(&sequencer) {
            return Err(MoveError::NotCanonical(sequencer));
        }
        let head = match meta.get(keys::HEAD) {
            Some(Value::Object(head)) if head.len() == 2 => CitedHead {
                seq: head
                    .get(keys::HEAD_SEQ)
                    .and_then(Value::as_u64)
                    .ok_or(MoveError::Field(keys::HEAD))?,
                hash: head
                    .get(keys::HEAD_HASH)
                    .and_then(Value::as_str)
                    .filter(|h| h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|h| <[u8; 32]>::try_from(h).ok())
                    .ok_or(MoveError::Field(keys::HEAD))?,
            },
            _ => return Err(MoveError::Field(keys::HEAD)),
        };
        let accept = ContractAccept::from_envelope(&base64(meta, keys::ACCEPT)?)
            .map_err(MoveError::Accept)?;
        if !accept.is_move() {
            return Err(MoveError::NotTheMove("it names another sequencer"));
        }
        if accept.server != sequencer {
            return Err(MoveError::NotTheMove("it is signed by another server"));
        }
        if accept.channel_id.to_string() != channel_id {
            return Err(MoveError::NotTheMove("it is for another channel"));
        }
        let reinstalls = match meta.get(keys::REINSTALLS) {
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| v.as_str().and_then(|s| b64().decode(s).ok()))
                .collect::<Option<Vec<_>>>()
                .ok_or(MoveError::Field(keys::REINSTALLS))?,
            _ => return Err(MoveError::Field(keys::REINSTALLS)),
        };
        if reinstalls.len() != accept.bot_dids.len() {
            return Err(MoveError::BotsAndReinstalls {
                bots: accept.bot_dids.len(),
                reinstalls: reinstalls.len(),
            });
        }
        Ok(Self {
            channel_id,
            sequencer,
            head,
            accept,
            reinstalls,
        })
    }

    /// The metadata entries a client puts in the block it signs, beside the
    /// keys every block carries.
    pub fn to_metadata(&self) -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                keys::CHANNEL_ID.into(),
                Value::from(self.channel_id.clone()),
            ),
            (keys::SEQUENCER.into(), Value::from(self.sequencer.clone())),
            (
                keys::HEAD.into(),
                serde_json::json!({
                    keys::HEAD_SEQ: self.head.seq,
                    keys::HEAD_HASH: hex::encode(self.head.hash),
                }),
            ),
            (
                keys::ACCEPT.into(),
                Value::from(b64().encode(&self.accept.envelope)),
            ),
            (
                keys::REINSTALLS.into(),
                Value::Array(
                    self.reinstalls
                        .iter()
                        .map(|r| Value::from(b64().encode(r)))
                        .collect(),
                ),
            ),
        ])
    }

    /// Whether a record with `seq`, `prev` (its hex hash of the record before
    /// it) and signer `signer` is this set's own (rule 11a): signed by the
    /// new sequencer, right after the cited head. `signer` is compared by key.
    pub fn check_record(&self, seq: u64, prev: &str, signer: &str) -> Result<(), MoveError> {
        if self.head.seq.checked_add(1) != Some(seq) {
            return Err(MoveError::NotItsRecord(
                "its seq is not the cited head's + 1",
            ));
        }
        if prev != hex::encode(self.head.hash) {
            return Err(MoveError::NotItsRecord("its prev is not the cited head"));
        }
        if !same_key(signer, &self.sequencer) {
            return Err(MoveError::NotItsRecord(
                "it is not signed by the new sequencer",
            ));
        }
        Ok(())
    }
}

/// A `key-link` block's metadata, read and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLinkBlock {
    pub channel_id: String,
    /// The link, verified under both its keys, with this channel as its
    /// audience and the block's author as its `new` DID.
    pub link: SignedKeyLink,
}

impl KeyLinkBlock {
    /// Read a `key-link` from its block's metadata, for a block authored by
    /// `author`. A link for any other audience (another channel, an alias, a
    /// contact, or everyone) is refused: it moves nothing here (rule 7b).
    pub fn from_metadata(meta: &BTreeMap<String, Value>, author: &str) -> Result<Self, MoveError> {
        let channel_id = text(meta, keys::CHANNEL_ID)?;
        let link =
            SignedKeyLink::from_envelope(&base64(meta, keys::LINK)?).map_err(MoveError::Link)?;
        let here = channel_id
            .parse::<cid::Cid>()
            .ok()
            .filter(|cid| crate::canonical_cid::check(cid).is_ok())
            .ok_or(MoveError::Field(keys::CHANNEL_ID))?;
        match &link.link().audience {
            Audience::Channel { channel_id: bytes }
                if crate::canonical_cid::from_bytes(bytes).is_ok_and(|cid| cid == here) => {}
            _ => return Err(MoveError::OtherAudience),
        }
        if !same_key(&link.link().new, author) {
            return Err(MoveError::NotTheAuthor {
                link: link.link().new.clone(),
                author: author.to_string(),
            });
        }
        Ok(Self { channel_id, link })
    }

    /// The metadata entries a client puts in the block it signs.
    pub fn to_metadata(&self) -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                keys::CHANNEL_ID.into(),
                Value::from(self.channel_id.clone()),
            ),
            (
                keys::LINK.into(),
                Value::from(b64().encode(self.link.envelope())),
            ),
        ])
    }
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn text(meta: &BTreeMap<String, Value>, key: &'static str) -> Result<String, MoveError> {
    meta.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or(MoveError::Field(key))
}

fn base64(meta: &BTreeMap<String, Value>, key: &'static str) -> Result<Vec<u8>, MoveError> {
    b64()
        .decode(text(meta, key)?)
        .map_err(|_| MoveError::Field(key))
}

/// The `(old, new)` DIDs of a `key-link` block authored by `author`, read
/// and checked as [`KeyLinkBlock::from_metadata`] checks it, for the channel
/// `channel_id`. `None` for any other block, or a link that does not hold.
pub fn key_link_dids(
    meta: &BTreeMap<String, Value>,
    author: &str,
    channel_id: &str,
) -> Option<(String, String)> {
    let block = KeyLinkBlock::from_metadata(meta, author).ok()?;
    if block.channel_id != channel_id {
        return None;
    }
    let link = block.link.link();
    Some((link.old.clone(), link.new.clone()))
}

/// A channel's root owners after `links` (JEP-0005 rule 7b): the creator
/// and the co-owners its creation block lists, `roots`, each carried along
/// the channel-scoped key links that follow it, in chain order. A link from
/// a DID that is not a root owner at that point moves no root; a root
/// linked away is no longer one.
///
/// The one reading of "owner" for every reader of the chain: the server's
/// rights and creator rule, the takeover of a move, and a client's check of
/// who may move the sequencer all ask it, so none can admit what another
/// refuses. DIDs are compared by key and returned as `roots` and `links`
/// spell them.
pub fn root_owners(
    roots: impl IntoIterator<Item = String>,
    links: impl IntoIterator<Item = (String, String)>,
) -> Vec<String> {
    let mut owners: Vec<String> = roots.into_iter().collect();
    for (old, new) in links {
        if let Some(at) = owners.iter().position(|o| same_owner(o, &old))
            && !owners.iter().any(|o| same_owner(o, &new))
        {
            owners[at] = new;
        }
    }
    owners
}

/// Whether `did` is among [`root_owners`].
pub fn is_root_owner(
    roots: impl IntoIterator<Item = String>,
    links: impl IntoIterator<Item = (String, String)>,
    did: &str,
) -> bool {
    root_owners(roots, links).iter().any(|o| same_owner(o, did))
}

fn is_canonical_did(did: &str) -> bool {
    Did::from_did_jig_string(did)
        .ok()
        .and_then(|d| d.as_bytes().ok())
        .is_some_and(|key| Did::from_ed25519_pubkey(&key).to_did_jig_string() == did)
}

/// The two DIDs are one owner: the same text, or one key however spelled.
fn same_owner(a: &str, b: &str) -> bool {
    a == b || same_key(a, b)
}

/// The two DIDs name one key, whatever their spelling.
fn same_key(a: &str, b: &str) -> bool {
    let key = |s: &str| {
        Did::from_did_jig_string(s)
            .ok()
            .and_then(|d| d.as_bytes().ok())
    };
    matches!((key(a), key(b)), (Some(a), Some(b)) if a == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Roots move along links in chain order; a link from a non-root, a
    /// second link from a DID already linked away, and a link onto a DID
    /// that is already a root move nothing.
    #[test]
    fn root_owners_follow_key_links_in_order() {
        let [a, b, c, d, x] = [10, 11, 12, 13, 14].map(|i| did_of(&key(i)));
        let link = |o: &str, n: &str| (o.to_string(), n.to_string());
        let roots = || vec![a.clone(), b.clone()];
        assert_eq!(root_owners(roots(), []), [a.clone(), b.clone()]);
        assert_eq!(root_owners(roots(), [link(&a, &c)]), [c.clone(), b.clone()]);
        assert_eq!(
            root_owners(roots(), [link(&a, &c), link(&c, &d)]),
            [d.clone(), b.clone()]
        );
        // Linked away: `a` holds nothing, so its second link moves nothing.
        assert_eq!(
            root_owners(roots(), [link(&a, &c), link(&a, &d)]),
            [c.clone(), b.clone()]
        );
        assert_eq!(root_owners(roots(), [link(&x, &d)]), roots());
        assert_eq!(root_owners(roots(), [link(&a, &b)]), roots());
        assert!(is_root_owner(roots(), [link(&a, &c)], &c));
        assert!(!is_root_owner(roots(), [link(&a, &c)], &a));
    }
    use crate::canonical_cid;
    use crate::contract::{ContractOffer, Grant, ManifestRef};
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn did_of(key: &SigningKey) -> String {
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    fn channel() -> cid::Cid {
        canonical_cid::of(b"channel-create")
    }

    /// The offer the old sequencer (seed 1) made to the new one (seed 2),
    /// which it accepted as a follower.
    fn held() -> ContractOffer {
        ContractOffer::sign(
            &key(1),
            &did_of(&key(2)),
            channel(),
            Grant::Member,
            b"channel-create".to_vec(),
            b"ingest head".to_vec(),
            ManifestRef {
                cid: canonical_cid::of(b"old manifest"),
                seq: 4,
            },
            vec![],
        )
    }

    fn move_accept(by: &SigningKey, bots: Vec<String>) -> ContractAccept {
        ContractAccept::sign_move(
            by,
            &held(),
            ManifestRef {
                cid: canonical_cid::of(b"new manifest"),
                seq: 7,
            },
            vec![],
            bots,
            vec![],
        )
    }

    fn set() -> SequencerSet {
        SequencerSet {
            channel_id: channel().to_string(),
            sequencer: did_of(&key(2)),
            head: CitedHead {
                seq: 5,
                hash: [9; 32],
            },
            accept: move_accept(&key(2), vec![]),
            reinstalls: vec![],
        }
    }

    fn with(mut meta: BTreeMap<String, Value>, key: &str, value: Value) -> BTreeMap<String, Value> {
        meta.insert(key.to_string(), value);
        meta
    }

    #[test]
    fn a_move_accept_names_its_signer_as_sequencer_and_round_trips() {
        let accept = move_accept(&key(2), vec![did_of(&key(8))]);
        assert!(accept.is_move());
        assert_eq!(accept.sequencer, did_of(&key(2)));
        assert_eq!(accept.offer_id, held().offer_id);
        assert_eq!(ContractAccept::from_envelope(&accept.envelope), Ok(accept));
    }

    /// `policy_approvals` is signed only in a move accept: an ordinary accept
    /// carrying the key, or a move accept without it, does not verify.
    #[test]
    fn policy_approvals_belong_to_a_move_accept_only() {
        let ordinary = ContractAccept::sign(
            &key(2),
            &held(),
            ManifestRef {
                cid: canonical_cid::of(b"new manifest"),
                seq: 7,
            },
            vec![],
            vec![],
        );
        assert!(!ordinary.is_move());
        assert!(
            !ordinary
                .payload()
                .windows(16)
                .any(|w| w == b"policy_approvals")
        );

        // Approvals set on an ordinary accept were never signed.
        assert_eq!(ordinary.verify(), Ok(()));
        let mut forged = ordinary.clone();
        forged.policy_approvals = vec![b"approval".to_vec()];
        assert!(forged.verify().is_err());
        let mut fields = crate::dcbor::decode(&forged.payload()).unwrap();
        if let crate::dcbor::Value::Map(entries) = &mut fields {
            entries.push((
                crate::dcbor::Value::text("policy_approvals"),
                crate::dcbor::Value::Array(vec![crate::dcbor::Value::Bytes(b"a".to_vec())]),
            ));
        }
        let envelope = crate::cose::sign1(&key(2), &crate::dcbor::encode(&fields).unwrap());
        assert!(ContractAccept::from_envelope(&envelope).is_err());
    }

    #[test]
    fn a_sequencer_set_round_trips_through_its_metadata() {
        let set = set();
        assert_eq!(SequencerSet::from_metadata(&set.to_metadata()), Ok(set));
    }

    #[test]
    fn its_record_is_the_new_sequencers_right_after_the_cited_head() {
        let set = set();
        let prev = hex::encode([9; 32]);
        let new = did_of(&key(2));
        assert_eq!(set.check_record(6, &prev, &new), Ok(()));
        for (seq, prev, signer) in [
            (7, prev.as_str(), new.as_str()),
            (5, prev.as_str(), new.as_str()),
            (6, "00", new.as_str()),
            (6, prev.as_str(), &did_of(&key(1))),
        ] {
            assert!(
                matches!(
                    set.check_record(seq, prev, signer),
                    Err(MoveError::NotItsRecord(_))
                ),
                "{seq} {prev} {signer}"
            );
        }
    }

    #[test]
    fn a_malformed_or_foreign_sequencer_set_is_refused() {
        let good = set().to_metadata();
        let refused =
            |meta: BTreeMap<String, Value>| SequencerSet::from_metadata(&meta).unwrap_err();
        let b64 = |accept: &ContractAccept| Value::from(b64().encode(&accept.envelope));

        // Every key is needed.
        for key in [
            keys::CHANNEL_ID,
            keys::SEQUENCER,
            keys::HEAD,
            keys::ACCEPT,
            keys::REINSTALLS,
        ] {
            let mut meta = good.clone();
            meta.remove(key);
            refused(meta);
        }
        // The head is exactly {seq, hash}, in lowercase hex.
        for head in [
            serde_json::json!({"seq": 5}),
            serde_json::json!({"seq": 5, "hash": "09".repeat(31)}),
            serde_json::json!({"seq": 5, "hash": "0A".repeat(32)}),
            serde_json::json!({"seq": -1, "hash": "09".repeat(32)}),
            serde_json::json!({"seq": 5, "hash": "09".repeat(32), "by": "anyone"}),
        ] {
            assert_eq!(
                refused(with(good.clone(), keys::HEAD, head.clone())),
                MoveError::Field(keys::HEAD),
                "{head}"
            );
        }
        // The new sequencer in its canonical spelling.
        assert!(matches!(
            refused(with(
                good.clone(),
                keys::SEQUENCER,
                Value::from("did:jig:zNotAKey")
            )),
            MoveError::NotCanonical(_)
        ));
        // An accept that is not this move's.
        let ordinary = ContractAccept::sign(
            &key(2),
            &held(),
            ManifestRef {
                cid: canonical_cid::of(b"m"),
                seq: 1,
            },
            vec![],
            vec![],
        );
        assert!(matches!(
            refused(with(good.clone(), keys::ACCEPT, b64(&ordinary))),
            MoveError::NotTheMove(_)
        ));
        assert!(matches!(
            refused(with(
                good.clone(),
                keys::ACCEPT,
                b64(&move_accept(&key(3), vec![]))
            )),
            MoveError::NotTheMove(_)
        ));
        assert!(matches!(
            refused(with(
                good.clone(),
                keys::CHANNEL_ID,
                Value::from(canonical_cid::of(b"another").to_string())
            )),
            MoveError::NotTheMove(_)
        ));
        assert!(matches!(
            refused(with(good.clone(), keys::ACCEPT, Value::from("not base64!"))),
            MoveError::Field(keys::ACCEPT)
        ));
        // One reinstall per bot DID the new sequencer minted.
        let one_bot = move_accept(&key(2), vec![did_of(&key(8))]);
        assert_eq!(
            refused(with(good.clone(), keys::ACCEPT, b64(&one_bot))),
            MoveError::BotsAndReinstalls {
                bots: 1,
                reinstalls: 0
            }
        );
        // Keys of other parts of the protocol are left alone.
        assert!(SequencerSet::from_metadata(&with(good, "seen", Value::from("record"))).is_ok());
    }

    fn link(audience: Audience) -> SignedKeyLink {
        SignedKeyLink::sign(&key(4), &key(5), audience, 1_700_000_000).unwrap()
    }

    fn here() -> Audience {
        Audience::Channel {
            channel_id: channel().to_bytes(),
        }
    }

    fn key_link_block(audience: Audience) -> BTreeMap<String, Value> {
        KeyLinkBlock {
            channel_id: channel().to_string(),
            link: link(audience),
        }
        .to_metadata()
    }

    #[test]
    fn a_key_link_for_this_channel_by_its_new_did_is_read() {
        let block = KeyLinkBlock::from_metadata(&key_link_block(here()), &did_of(&key(5))).unwrap();
        assert_eq!(block.link.link().old, did_of(&key(4)));
        assert_eq!(block.to_metadata(), key_link_block(here()));
    }

    /// A link moves nothing outside its audience (rule 7b): another
    /// channel's, an alias's, a contact's or everyone's link is refused here,
    /// and so is a block not authored by the link's new DID.
    #[test]
    fn a_key_link_for_another_audience_or_author_is_refused() {
        let new = did_of(&key(5));
        for audience in [
            Audience::Channel {
                channel_id: canonical_cid::of(b"another").to_bytes(),
            },
            Audience::Public,
            Audience::Contact {
                did: did_of(&key(6)),
            },
        ] {
            assert_eq!(
                KeyLinkBlock::from_metadata(&key_link_block(audience.clone()), &new),
                Err(MoveError::OtherAudience),
                "{audience:?}"
            );
        }
        assert!(matches!(
            KeyLinkBlock::from_metadata(&key_link_block(here()), &did_of(&key(4))),
            Err(MoveError::NotTheAuthor { .. })
        ));
        let mut meta = key_link_block(here());
        meta.insert(keys::LINK.into(), Value::from(b64().encode(b"not a link")));
        assert!(matches!(
            KeyLinkBlock::from_metadata(&meta, &new),
            Err(MoveError::Link(_))
        ));
    }

    fn vectors() -> serde_json::Value {
        let set = set();
        let with_bot = move_accept(&key(2), vec![did_of(&key(8))]);
        serde_json::json!({
            "comment": "JEP-0005 rules 11a and 7b. `sequencer_set.metadata` and `key_link.metadata` are the kind-specific metadata of the two blocks, as JSON; the block's own fields and signature are JEP-0002's and not shown. `move_accept` is the new sequencer's contract-accept naming itself as sequencer, which carries `policy_approvals`; payload_hex is its deterministic CBOR payload and cose_sign1_hex its envelope.",
            "keys": {
                "comment": "Ed25519 seeds: every byte set to the given value",
                "old_sequencer": {"seed_byte": 1, "did": did_of(&key(1))},
                "new_sequencer": {"seed_byte": 2, "did": did_of(&key(2))},
                "bot": {"seed_byte": 8, "did": did_of(&key(8))},
                "old_member": {"seed_byte": 4, "did": did_of(&key(4))},
                "new_member": {"seed_byte": 5, "did": did_of(&key(5))},
            },
            "held_offer_id_hex": hex::encode(held().offer_id),
            "sequencer_set": {
                "kind": SEQUENCER_SET_KIND,
                "metadata": set.to_metadata(),
                "record": {"seq": 6, "prev": hex::encode([9; 32]), "signed_by": did_of(&key(2))},
            },
            "move_accept": {
                "payload_hex": hex::encode(set.accept.payload()),
                "cose_sign1_hex": hex::encode(&set.accept.envelope),
            },
            "move_accept_with_one_bot": {
                "payload_hex": hex::encode(with_bot.payload()),
                "cose_sign1_hex": hex::encode(&with_bot.envelope),
            },
            "key_link": {
                "kind": KEY_LINK_KIND,
                "author": did_of(&key(5)),
                "metadata": key_link_block(here()),
            },
        })
    }

    #[test]
    fn bytes_match_the_committed_vectors() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../jig-spec/jep/vectors/0005/sequencer-move.json"
        ))
        .unwrap();
        assert_eq!(vectors(), v);
    }

    /// `cargo test -p jig-core --features ed25519 sequencer_move::tests::print_vectors -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_vectors() {
        println!("{}", serde_json::to_string_pretty(&vectors()).unwrap());
    }
}
