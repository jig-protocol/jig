//! Key links: the statement that moves what one DID held to another.
//!
//! A DID is its key and does not outlive it, so rotating a key means a new DID
//! (identity design, Q2). A link says that `old` hands over to `new` for one
//! audience: a channel, one nameserver's alias, one contact, or `public` (a
//! server's own key change). Both keys sign it, so neither alone can claim the
//! other, and it moves nothing outside its audience. The holder chooses who is
//! shown a link; once shown, it can be forwarded.
//!
//! A link is a COSE_Sign ([`crate::cose`]) with two signatures, `old`'s then
//! `new`'s, over a text-keyed deterministic CBOR map ([`crate::dcbor`]) with a
//! `domain` entry, as every signed object in [`crate::naming`] has. The
//! envelope bytes are what travels and what a verifier keeps as evidence.
//!
//! In an ordered log, such as a channel's chain, the first link from a DID
//! takes effect at its place in the log. A later link from the same DID to
//! another is refused, since the DID holds nothing any more, and both are kept
//! as fork evidence ([`fork`]). A verifier with no order to go by follows
//! neither. A holder never links one DID to two others, even for different
//! audiences: that is indistinguishable from theft.
//!
//! DIDs must be in their canonical lowercase spelling, so that one key is one
//! string when links are compared. The encoding is JEP-0012; its test vectors
//! live in `repos/jig-spec/jep/vectors/0012/`.

use ed25519_dalek::SigningKey;

use crate::cose::{self, CoseError};
use crate::dcbor::{self, Value};
use crate::did::Did;
use crate::naming::{AliasLink, Name, NamingError};

pub const KEY_LINK_DOMAIN: &str = "jig-key-link-v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyLinkError {
    #[error("a link must name two different DIDs")]
    SameDid,
    #[error("`{0}` is not a did:jig key")]
    BadDid(String),
    #[error("the channel id is not a canonical binary CIDv1")]
    BadChannelId,
    #[error("`{0}` is not a full, lowercased alias@suffix")]
    BadAlias(String),
    #[error("not a key link")]
    BadPayload,
    #[error("the link is not signed by both {old} and {new}")]
    BadSignature { old: String, new: String },
    #[error(transparent)]
    Envelope(CoseError),
}

impl From<CoseError> for KeyLinkError {
    fn from(e: CoseError) -> Self {
        Self::Envelope(e)
    }
}

/// Who a link is for. A verifier acts on a link only for the audience it
/// names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    /// One channel: the old DID's roles and membership move to the new one.
    /// `channel_id` is the channel's binary canonical CIDv1, as ingest
    /// records carry it.
    Channel { channel_id: Vec<u8> },
    /// One alias at one nameserver (JEP-0004 rule 9). `alias` is the full,
    /// lowercased `local@suffix`.
    Alias { ns_did: String, alias: String },
    /// One contact, whose pin of the old DID moves.
    Contact { did: String },
    /// Anyone: a server's own key change, which peers and clients follow.
    Public,
}

impl Audience {
    fn kind(&self) -> &'static str {
        match self {
            Self::Channel { .. } => "channel",
            Self::Alias { .. } => "alias",
            Self::Contact { .. } => "contact",
            Self::Public => "public",
        }
    }

    fn to_value(&self) -> Value {
        let kind = ("kind", Value::Text(self.kind().into()));
        match self {
            Self::Channel { channel_id } => {
                Value::text_map([kind, ("channel_id", Value::Bytes(channel_id.clone()))])
            }
            Self::Alias { ns_did, alias } => Value::text_map([
                kind,
                ("ns_did", Value::Text(ns_did.clone())),
                ("alias", Value::Text(alias.clone())),
            ]),
            Self::Contact { did } => Value::text_map([kind, ("did", Value::Text(did.clone()))]),
            Self::Public => Value::text_map([kind]),
        }
    }

    fn from_value(v: &Value) -> Result<Self, KeyLinkError> {
        Ok(match text(v, "kind")?.as_str() {
            "channel" => Self::Channel {
                channel_id: v
                    .get("channel_id")
                    .and_then(Value::as_bytes)
                    .ok_or(KeyLinkError::BadPayload)?
                    .to_vec(),
            },
            "alias" => Self::Alias {
                ns_did: text(v, "ns_did")?,
                alias: text(v, "alias")?,
            },
            "contact" => Self::Contact {
                did: text(v, "did")?,
            },
            "public" => Self::Public,
            _ => return Err(KeyLinkError::BadPayload),
        })
    }

    /// The fields are well formed: DIDs are did:jig keys, a channel id is a
    /// canonical CIDv1, an alias is a full name in its canonical spelling.
    fn check(&self) -> Result<(), KeyLinkError> {
        match self {
            Self::Channel { channel_id } => {
                crate::canonical_cid::from_bytes(channel_id)
                    .map_err(|_| KeyLinkError::BadChannelId)?;
            }
            Self::Alias { ns_did, alias } => {
                check_did(ns_did)?;
                let canonical = Name::parse(alias)
                    .map_err(|_| KeyLinkError::BadAlias(alias.clone()))?
                    .as_alias();
                if canonical != *alias {
                    return Err(KeyLinkError::BadAlias(alias.clone()));
                }
            }
            Self::Contact { did } => check_did(did)?,
            Self::Public => {}
        }
        Ok(())
    }
}

/// What a link says, before or after signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLink {
    /// The DID being left.
    pub old: String,
    /// The DID taking over.
    pub new: String,
    pub audience: Audience,
    /// When it was signed, in Unix seconds.
    pub issued_at: i64,
}

impl KeyLink {
    /// The exact bytes both keys sign: `{domain, old, new, audience, issued_at}`.
    pub fn payload(&self) -> Vec<u8> {
        dcbor::encode(&Value::text_map([
            ("domain", Value::Text(KEY_LINK_DOMAIN.into())),
            ("old", Value::Text(self.old.clone())),
            ("new", Value::Text(self.new.clone())),
            ("audience", self.audience.to_value()),
            ("issued_at", Value::int(self.issued_at)),
        ]))
        .expect("a map of text, bytes and integers encodes")
    }

    fn check(&self) -> Result<(), KeyLinkError> {
        check_did(&self.old)?;
        check_did(&self.new)?;
        if self.old == self.new {
            return Err(KeyLinkError::SameDid);
        }
        self.audience.check()
    }
}

/// A link signed by both of its keys. Only [`SignedKeyLink::sign`] and
/// [`SignedKeyLink::from_envelope`] make one, and both check the signatures,
/// so holding one means it verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedKeyLink {
    link: KeyLink,
    envelope: Vec<u8>,
}

impl SignedKeyLink {
    /// Link `old`'s DID to `new`'s for `audience`.
    pub fn sign(
        old: &SigningKey,
        new: &SigningKey,
        audience: Audience,
        issued_at: i64,
    ) -> Result<Self, KeyLinkError> {
        let link = KeyLink {
            old: did_of(old),
            new: did_of(new),
            audience,
            issued_at,
        };
        link.check()?;
        let envelope = cose::sign_all(&[old, new], &link.payload());
        Ok(Self { link, envelope })
    }

    /// Parse a link and check it: its fields, that its payload is exactly the
    /// one these fields encode (which also refuses unknown keys), and that
    /// `old` and then `new` signed it.
    pub fn from_envelope(envelope: &[u8]) -> Result<Self, KeyLinkError> {
        let opened = cose::open_sign(envelope)?;
        let p = dcbor::decode(&opened.payload).map_err(|_| KeyLinkError::BadPayload)?;
        if text(&p, "domain")? != KEY_LINK_DOMAIN {
            return Err(KeyLinkError::BadPayload);
        }
        let link = KeyLink {
            old: text(&p, "old")?,
            new: text(&p, "new")?,
            audience: Audience::from_value(p.get("audience").ok_or(KeyLinkError::BadPayload)?)?,
            issued_at: p
                .get("issued_at")
                .and_then(Value::as_i64)
                .ok_or(KeyLinkError::BadPayload)?,
        };
        link.check()?;
        if link.payload() != opened.payload {
            return Err(KeyLinkError::BadPayload);
        }
        opened
            .verify_all(&[&link.old, &link.new])
            .map_err(|_| KeyLinkError::BadSignature {
                old: link.old.clone(),
                new: link.new.clone(),
            })?;
        Ok(Self {
            link,
            envelope: envelope.to_vec(),
        })
    }

    pub fn link(&self) -> &KeyLink {
        &self.link
    }

    /// The COSE_Sign bytes: what travels, and what a verifier keeps.
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// Whether this is a `public` link from the DID a peer has pinned to the
    /// DID it now presents: a server's own key change. The two DIDs come from
    /// outside the link, so they are compared by key, not by spelling.
    pub fn moves_public(&self, pinned: &str, presented: &str) -> bool {
        self.link.audience == Audience::Public
            && same_key(&self.link.old, pinned)
            && same_key(&self.link.new, presented)
    }
}

/// Two links from one DID to two different DIDs: the old key signed both, so
/// someone other than its holder has it. A verifier holding both keeps them as
/// evidence. With no order to go by, it follows neither; in an ordered log,
/// the first link has already taken effect and the later one is refused (see
/// the module docs).
pub fn fork(a: &SignedKeyLink, b: &SignedKeyLink) -> bool {
    a.link.old == b.link.old && a.link.new != b.link.new
}

impl AliasLink for SignedKeyLink {
    fn old_did(&self) -> &str {
        &self.link.old
    }

    fn new_did(&self) -> &str {
        &self.link.new
    }

    /// The nameserver an `alias` audience names; empty for any other
    /// audience, which no rotation chain accepts.
    fn audience_ns_did(&self) -> &str {
        match &self.link.audience {
            Audience::Alias { ns_did, .. } => ns_did,
            _ => "",
        }
    }

    fn audience_alias(&self) -> &str {
        match &self.link.audience {
            Audience::Alias { alias, .. } => alias,
            _ => "",
        }
    }

    /// Checked when the link was made or parsed; checked again here so the
    /// trait holds for any copy.
    fn verify_signatures(&self) -> Result<(), NamingError> {
        cose::open_sign(&self.envelope)
            .and_then(|o| o.verify_all(&[&self.link.old, &self.link.new]))
            .map_err(|_| NamingError::BadSignature(self.link.old.clone()))
    }
}

fn did_of(key: &SigningKey) -> String {
    Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
}

fn same_key(a: &str, b: &str) -> bool {
    let key = |s: &str| Did::from_did_jig_string(s).and_then(|d| d.as_bytes()).ok();
    matches!((key(a), key(b)), (Some(a), Some(b)) if a == b)
}

fn check_did(did: &str) -> Result<(), KeyLinkError> {
    // `Did` parsing accepts any letter case, so compare against the spelling
    // the key itself gives: one key, one string, for forks and audience matches.
    let bytes = Did::from_did_jig_string(did)
        .and_then(|d| d.as_bytes())
        .map_err(|_| KeyLinkError::BadDid(did.into()))?;
    if Did::from_ed25519_pubkey(&bytes).to_did_jig_string() != did {
        return Err(KeyLinkError::BadDid(did.into()));
    }
    Ok(())
}

fn text(map: &Value, key: &str) -> Result<String, KeyLinkError> {
    map.get(key)
        .and_then(Value::as_text)
        .map(str::to_string)
        .ok_or(KeyLinkError::BadPayload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::verify_rotation_chain;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn channel() -> Audience {
        Audience::Channel {
            channel_id: crate::canonical_cid::of(b"#general").to_bytes(),
        }
    }

    fn alias_at(ns: &SigningKey) -> Audience {
        Audience::Alias {
            ns_did: did_of(ns),
            alias: "alice@example.org".into(),
        }
    }

    const AT: i64 = 1_800_000_000;

    #[test]
    fn every_audience_round_trips_through_its_envelope() {
        let (old, new) = (key(1), key(2));
        for audience in [
            channel(),
            alias_at(&key(7)),
            Audience::Contact {
                did: did_of(&key(3)),
            },
            Audience::Public,
        ] {
            let link = SignedKeyLink::sign(&old, &new, audience.clone(), AT).unwrap();
            let back = SignedKeyLink::from_envelope(link.envelope()).unwrap();
            assert_eq!(back, link);
            assert_eq!(back.link().audience, audience);
            assert_eq!(back.link().old, did_of(&old));
            assert_eq!(back.link().new, did_of(&new));
        }
    }

    #[test]
    fn a_link_needs_two_different_keys() {
        assert_eq!(
            SignedKeyLink::sign(&key(1), &key(1), Audience::Public, AT),
            Err(KeyLinkError::SameDid)
        );
    }

    #[test]
    fn one_signature_is_not_enough_and_the_order_is_old_then_new() {
        let (old, new) = (key(1), key(2));
        let link = SignedKeyLink::sign(&old, &new, Audience::Public, AT).unwrap();
        let payload = link.link().payload();
        // Only the new key signed: the new key alone cannot claim the old.
        let one = cose::sign_all(&[&new], &payload);
        assert!(matches!(
            SignedKeyLink::from_envelope(&one),
            Err(KeyLinkError::BadSignature { .. })
        ));
        // Both signed, in the wrong order.
        let swapped = cose::sign_all(&[&new, &old], &payload);
        assert!(matches!(
            SignedKeyLink::from_envelope(&swapped),
            Err(KeyLinkError::BadSignature { .. })
        ));
        // A third key signing in the old key's place.
        let other = cose::sign_all(&[&key(9), &new], &payload);
        assert!(matches!(
            SignedKeyLink::from_envelope(&other),
            Err(KeyLinkError::BadSignature { .. })
        ));
    }

    /// Re-sign `link`'s payload after `edit`, as someone holding both keys
    /// but writing a payload this crate would not.
    fn resigned(old: &SigningKey, new: &SigningKey, edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let link = SignedKeyLink::sign(old, new, Audience::Public, AT).unwrap();
        let mut p = dcbor::decode(&link.link().payload()).unwrap();
        edit(&mut p);
        cose::sign_all(&[old, new], &dcbor::encode(&p).unwrap())
    }

    fn set(map: &mut Value, key: &str, value: Value) {
        let Value::Map(entries) = map else { panic!() };
        entries.retain(|(k, _)| k.as_text() != Some(key));
        entries.push((Value::Text(key.into()), value));
    }

    #[test]
    fn payloads_this_crate_would_not_write_are_refused() {
        let (old, new) = (key(1), key(2));
        // Another object's domain.
        let other = resigned(&old, &new, |p| {
            set(p, "domain", Value::Text("jig-key-revoke-v1".into()))
        });
        assert_eq!(
            SignedKeyLink::from_envelope(&other),
            Err(KeyLinkError::BadPayload)
        );
        // An extra key.
        let extra = resigned(&old, &new, |p| set(p, "expires", Value::int(AT + 1)));
        assert_eq!(
            SignedKeyLink::from_envelope(&extra),
            Err(KeyLinkError::BadPayload)
        );
        // An audience kind nobody defined.
        let kind = resigned(&old, &new, |p| {
            set(
                p,
                "audience",
                Value::text_map([("kind", Value::Text("everyone".into()))]),
            )
        });
        assert_eq!(
            SignedKeyLink::from_envelope(&kind),
            Err(KeyLinkError::BadPayload)
        );
        // An alias that is not in its canonical spelling.
        let shouty = resigned(&old, &new, |p| {
            set(
                p,
                "audience",
                Value::text_map([
                    ("kind", Value::Text("alias".into())),
                    ("ns_did", Value::Text(did_of(&key(7)))),
                    ("alias", Value::Text("Alice@Example.org".into())),
                ]),
            )
        });
        assert!(matches!(
            SignedKeyLink::from_envelope(&shouty),
            Err(KeyLinkError::BadAlias(_))
        ));
        // A channel id that is not a canonical CID.
        let cid = resigned(&old, &new, |p| {
            set(
                p,
                "audience",
                Value::text_map([
                    ("kind", Value::Text("channel".into())),
                    ("channel_id", Value::Bytes(b"#general".to_vec())),
                ]),
            )
        });
        assert_eq!(
            SignedKeyLink::from_envelope(&cid),
            Err(KeyLinkError::BadChannelId)
        );
    }

    /// The same key spelled in upper case, which would decode to the same key.
    fn shouted(did: &str) -> String {
        let body = did.strip_prefix("did:jig:z").unwrap();
        format!("did:jig:z{}", body.to_uppercase())
    }

    #[test]
    fn a_did_in_another_spelling_is_refused() {
        // Otherwise a thief's link from a re-spelled `old` would not fork with
        // the holder's, and an audience DID would not match its own spelling.
        let (old, new) = (key(1), key(2));
        let respelled = resigned(&old, &new, |p| {
            set(p, "old", Value::Text(shouted(&did_of(&old))))
        });
        assert!(matches!(
            SignedKeyLink::from_envelope(&respelled),
            Err(KeyLinkError::BadDid(_))
        ));
        let contact = resigned(&old, &new, |p| {
            set(
                p,
                "audience",
                Value::text_map([
                    ("kind", Value::Text("contact".into())),
                    ("did", Value::Text(shouted(&did_of(&key(3))))),
                ]),
            )
        });
        assert!(matches!(
            SignedKeyLink::from_envelope(&contact),
            Err(KeyLinkError::BadDid(_))
        ));
        let ns = resigned(&old, &new, |p| {
            set(
                p,
                "audience",
                Value::text_map([
                    ("kind", Value::Text("alias".into())),
                    ("ns_did", Value::Text(shouted(&did_of(&key(7))))),
                    ("alias", Value::Text("alice@example.org".into())),
                ]),
            )
        });
        assert!(matches!(
            SignedKeyLink::from_envelope(&ns),
            Err(KeyLinkError::BadDid(_))
        ));
        assert!(matches!(
            SignedKeyLink::sign(
                &old,
                &new,
                Audience::Contact {
                    did: shouted(&did_of(&key(3)))
                },
                AT
            ),
            Err(KeyLinkError::BadDid(_))
        ));
    }

    #[test]
    fn a_fork_is_two_links_from_one_key_to_two() {
        let old = key(1);
        let a = SignedKeyLink::sign(&old, &key(2), Audience::Public, AT).unwrap();
        let b = SignedKeyLink::sign(&old, &key(3), Audience::Public, AT).unwrap();
        let again = SignedKeyLink::sign(&old, &key(2), channel(), AT + 1).unwrap();
        assert!(fork(&a, &b));
        assert!(!fork(&a, &again), "the same move twice is not a fork");
        let elsewhere = SignedKeyLink::sign(&key(4), &key(3), Audience::Public, AT).unwrap();
        assert!(!fork(&a, &elsewhere));
    }

    #[test]
    fn a_public_link_moves_a_pin_from_old_to_new() {
        let (old, new) = (key(1), key(2));
        let (pinned, presented) = (did_of(&old), did_of(&new));
        let link = SignedKeyLink::sign(&old, &new, Audience::Public, AT).unwrap();
        assert!(link.moves_public(&pinned, &presented));
        assert!(!link.moves_public(&presented, &pinned));
        assert!(!link.moves_public(&pinned, &did_of(&key(3))));
        assert!(!link.moves_public(&pinned, "did:jig:alice"));
        let contact = SignedKeyLink::sign(
            &old,
            &new,
            Audience::Contact {
                did: did_of(&key(3)),
            },
            AT,
        )
        .unwrap();
        assert!(!contact.moves_public(&pinned, &presented));
    }

    #[test]
    fn only_an_alias_link_for_that_nameserver_and_alias_moves_the_alias() {
        let (ns, a, b, c) = (key(7), key(1), key(2), key(3));
        let ab = SignedKeyLink::sign(&a, &b, alias_at(&ns), AT).unwrap();
        let bc = SignedKeyLink::sign(&b, &c, alias_at(&ns), AT + 1).unwrap();
        let alias = "alice@example.org";
        assert_eq!(
            verify_rotation_chain(
                alias,
                &did_of(&ns),
                &did_of(&a),
                &[ab.clone(), bc],
                &did_of(&c)
            ),
            Ok(())
        );
        // A channel link between the same keys moves no alias.
        let in_channel = SignedKeyLink::sign(&a, &b, channel(), AT).unwrap();
        assert!(
            verify_rotation_chain(alias, &did_of(&ns), &did_of(&a), &[in_channel], &did_of(&b))
                .is_err()
        );
        // Nor does an alias link for another nameserver.
        let elsewhere = SignedKeyLink::sign(&a, &b, alias_at(&key(8)), AT).unwrap();
        assert!(
            verify_rotation_chain(alias, &did_of(&ns), &did_of(&a), &[elsewhere], &did_of(&b))
                .is_err()
        );
        assert_eq!(ab.verify_signatures(), Ok(()));
    }

    /// One link per audience, from fixed keys. The committed vectors pin the
    /// encoding: a change to any signed byte fails here.
    fn vectors() -> serde_json::Value {
        let (old, new) = (key(1), key(2));
        let mut out = serde_json::Map::new();
        out.insert(
            "comment".into(),
            "payload_hex is the deterministic CBOR payload; cose_sign_hex is the envelope, \
             signed by old then new. Keys are ed25519 seeds of one repeated byte: old 0x01, \
             new 0x02, nameserver 0x07, contact 0x03"
                .into(),
        );
        for audience in [
            channel(),
            alias_at(&key(7)),
            Audience::Contact {
                did: did_of(&key(3)),
            },
            Audience::Public,
        ] {
            let kind = audience.kind();
            let link = SignedKeyLink::sign(&old, &new, audience, AT).unwrap();
            out.insert(
                kind.into(),
                serde_json::json!({
                    "old": link.link().old,
                    "new": link.link().new,
                    "payload_hex": hex::encode(link.link().payload()),
                    "cose_sign_hex": hex::encode(link.envelope()),
                }),
            );
        }
        serde_json::Value::Object(out)
    }

    #[test]
    fn signed_bytes_match_the_committed_vectors() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../jig-spec/jep/vectors/0012/vectors.json"))
                .unwrap();
        assert_eq!(vectors(), v);
        // And every committed envelope opens.
        for kind in ["channel", "alias", "contact", "public"] {
            let hex_env = v[kind]["cose_sign_hex"].as_str().unwrap();
            SignedKeyLink::from_envelope(&hex::decode(hex_env).unwrap()).unwrap();
        }
    }

    /// `cargo test -p jig-core --features ed25519 key_link::tests::print_vectors -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_vectors() {
        println!("{}", serde_json::to_string_pretty(&vectors()).unwrap());
    }
}
