//! The channel contract: the signed messages of JEP-0005 and the exact bytes
//! each signs.
//!
//! The owning server offers a channel to another server under a [`Grant`]
//! ([`ContractOffer`]). The other server answers with exactly one of
//! [`ContractAccept`] or [`ContractRefuse`]. Either side ends the share with
//! [`ContractEnd`]. Each is a COSE_Sign1 ([`crate::cose`]) by the server it
//! names, over a text-keyed map in deterministic CBOR ([`crate::dcbor`]) with a
//! `domain` entry naming the message (rule 0). CIDs are canonical binary CIDs
//! ([`crate::canonical_cid`]). Test vectors live in
//! `repos/jig-spec/jep/vectors/0005/`.
//!
//! This module checks what the bytes say and who signed them. Whether a
//! server is a configured peer, implements the suite, or should accept at all
//! is the caller's business.

use cid::Cid;
use ed25519_dalek::SigningKey;

use crate::canonical_cid;
use crate::cose::{self, CoseError};
use crate::dcbor::{self, Value};
use crate::did::Did;
use crate::naming::Name;

pub const OFFER_DOMAIN: &str = "jig-contract-offer-v1";
pub const ACCEPT_DOMAIN: &str = "jig-contract-accept-v1";
pub const REFUSE_DOMAIN: &str = "jig-contract-refuse-v1";
pub const END_DOMAIN: &str = "jig-contract-end-v1";
pub const KP_REQUEST_DOMAIN: &str = "jig-kp-request-v1";
pub const LOCAL_ADDS_DOMAIN: &str = "jig-local-adds-v1";
pub const OWNER_KEY_LINKS_DOMAIN: &str = "jig-owner-key-links-v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("not a {0}")]
    BadPayload(&'static str),
    #[error("`{0}` is not a did:jig key")]
    BadDid(String),
    #[error("the signature is not by {0}")]
    BadSignature(String),
    #[error(transparent)]
    Envelope(CoseError),
    #[error("a CID in the {0} is not canonical")]
    BadCid(&'static str),
    #[error("the offer_id does not match the offer")]
    OfferIdMismatch,
    #[error("`{0}` is not a grant")]
    UnknownGrant(String),
    #[error("`{0}` is not a refusal code")]
    UnknownCode(String),
    #[error("`{0}` is not a name suffix")]
    BadSuffix(String),
    #[error("the answer does not answer this offer: {0}")]
    NotAnAnswer(&'static str),
}

impl From<CoseError> for ContractError {
    fn from(e: CoseError) -> Self {
        match e {
            CoseError::BadDid(did) => ContractError::BadDid(did),
            CoseError::BadSignature(did) => ContractError::BadSignature(did),
            other => ContractError::Envelope(other),
        }
    }
}

/// What a follower may relay (rule 7a).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Grant {
    /// Protocol traffic only: MLS self-updates and self-leave. No content.
    Read,
    /// Also content blocks from channel members.
    Write,
    /// Also the membership blocks the channel's rule allows.
    Member,
}

impl Grant {
    /// Whether this grant relays nothing `other` does not (rule 7a): `read`
    /// is within `write`, which is within `member`.
    pub fn within(self, other: Grant) -> bool {
        let rank = |g: Grant| match g {
            Grant::Read => 0,
            Grant::Write => 1,
            Grant::Member => 2,
        };
        rank(self) <= rank(other)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Grant::Read => "read",
            Grant::Write => "write",
            Grant::Member => "member",
        }
    }

    pub fn parse(s: &str) -> Result<Self, ContractError> {
        match s {
            "read" => Ok(Grant::Read),
            "write" => Ok(Grant::Write),
            "member" => Ok(Grant::Member),
            other => Err(ContractError::UnknownGrant(other.to_string())),
        }
    }
}

/// Whether a follower holding `grant` may relay a block of `kind` (rule 7a).
///
/// - `write` carries content: text, and the email bridge's two kinds.
/// - `member` carries content and the membership blocks; the owner's gate
///   still decides, by the signer's rights (rule 7b), which of those the
///   channel's rule allows.
/// - `read` carries only MLS protocol traffic, which this build does not
///   relay yet: nothing.
///
/// No grant relays a channel's terms, shares, roles or lifecycle
/// (`channel-create`, `channel-share`, `role-assign`, `channel-archive` and
/// the like), or a server's own kinds: those go to the owner directly.
pub fn grant_allows(grant: Grant, kind: crate::BlockKind) -> bool {
    use crate::BlockKind as K;
    let content = matches!(kind, K::TextRender | K::EmailRender | K::EmailEncrypted);
    let membership = matches!(kind, K::MemberAdd | K::MemberRemove);
    match grant {
        Grant::Read => false,
        Grant::Write => content,
        Grant::Member => content || membership,
    }
}

/// Why a server refused an offer (rule 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefuseCode {
    UnsupportedSuite,
    UnsupportedVersion,
    PolicyRefused,
    NotAPeer,
    /// The two servers claim one name suffix under different authorities.
    SuffixConflict,
}

impl RefuseCode {
    pub fn as_str(self) -> &'static str {
        match self {
            RefuseCode::UnsupportedSuite => "UNSUPPORTED_SUITE",
            RefuseCode::UnsupportedVersion => "UNSUPPORTED_VERSION",
            RefuseCode::PolicyRefused => "POLICY_REFUSED",
            RefuseCode::NotAPeer => "NOT_A_PEER",
            RefuseCode::SuffixConflict => "SUFFIX_CONFLICT",
        }
    }

    pub fn parse(s: &str) -> Result<Self, ContractError> {
        match s {
            "UNSUPPORTED_SUITE" => Ok(RefuseCode::UnsupportedSuite),
            "UNSUPPORTED_VERSION" => Ok(RefuseCode::UnsupportedVersion),
            "POLICY_REFUSED" => Ok(RefuseCode::PolicyRefused),
            "NOT_A_PEER" => Ok(RefuseCode::NotAPeer),
            "SUFFIX_CONFLICT" => Ok(RefuseCode::SuffixConflict),
            other => Err(ContractError::UnknownCode(other.to_string())),
        }
    }
}

/// A server's current `server-manifest` (its peer policy, rule 16), by CID
/// and position in its manifest log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRef {
    pub cid: Cid,
    pub seq: u64,
}

impl ManifestRef {
    fn value(&self) -> Value {
        Value::text_map([
            ("cid", Value::Bytes(self.cid.to_bytes())),
            ("seq", Value::Unsigned(self.seq)),
        ])
    }

    fn read(v: &Value, what: &'static str) -> Result<Self, ContractError> {
        Ok(Self {
            cid: cid(v, "cid", what)?,
            seq: v
                .get("seq")
                .and_then(Value::as_u64)
                .ok_or(ContractError::BadPayload(what))?,
        })
    }
}

/// A name suffix a server attests, with the authority it attests it under
/// (JEP-0004 rules 4 and 7), so two servers can tell one claim from two.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttestedSuffix {
    /// A normalised name suffix.
    pub suffix: String,
    pub authority: SuffixAuthority,
}

/// What a suffix's attestations rest on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SuffixAuthority {
    /// `config`: the DIDs a delegation names, canonical, sorted and distinct.
    Config { authorities: Vec<String> },
    /// `dns`: the DNS name whose zone roots the suffix.
    Dns { domain: String },
}

impl AttestedSuffix {
    /// A `config`-rooted suffix under `authorities`, in their canonical order.
    pub fn config(
        suffix: impl Into<String>,
        authorities: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut authorities: Vec<String> = authorities.into_iter().collect();
        authorities.sort();
        authorities.dedup();
        Self {
            suffix: suffix.into(),
            authority: SuffixAuthority::Config { authorities },
        }
    }

    /// A `dns`-rooted suffix under `domain`.
    pub fn dns(suffix: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            suffix: suffix.into(),
            authority: SuffixAuthority::Dns {
                domain: domain.into(),
            },
        }
    }

    /// The two claim one suffix under different authorities: the contract
    /// MUST be refused (`SUFFIX_CONFLICT`, JEP-0004 rule 7). The same suffix
    /// under the same authority is one claim, and no conflict.
    pub fn conflicts_with(&self, other: &AttestedSuffix) -> bool {
        self.suffix == other.suffix && self.authority != other.authority
    }

    fn value(&self) -> Value {
        match &self.authority {
            SuffixAuthority::Config { authorities } => Value::text_map([
                ("suffix", Value::text(self.suffix.clone())),
                ("root", Value::text("config")),
                ("authorities", texts(authorities)),
            ]),
            SuffixAuthority::Dns { domain } => Value::text_map([
                ("suffix", Value::text(self.suffix.clone())),
                ("root", Value::text("dns")),
                ("domain", Value::text(domain.clone())),
            ]),
        }
    }

    fn read(v: &Value, what: &'static str) -> Result<Self, ContractError> {
        let suffix = text(v, "suffix", what)?;
        let bad = || ContractError::BadSuffix(suffix.clone());
        if !is_suffix(&suffix) {
            return Err(bad());
        }
        let entry = match text(v, "root", what)?.as_str() {
            "config" => {
                let authorities = array(v, "authorities", what)?
                    .iter()
                    .map(|a| a.as_text().map(str::to_string))
                    .collect::<Option<Vec<_>>>()
                    .ok_or(ContractError::BadPayload(what))?;
                // One spelling for one set: canonical DIDs, ascending, none twice.
                let canonical = authorities.iter().all(|a| is_canonical_did(a))
                    && authorities.windows(2).all(|w| w[0] < w[1]);
                if authorities.is_empty() || !canonical {
                    return Err(bad());
                }
                Self::config(suffix.clone(), authorities)
            }
            "dns" => {
                let domain = text(v, "domain", what)?;
                if !is_suffix(&domain) {
                    return Err(bad());
                }
                Self::dns(suffix.clone(), domain)
            }
            // `contract` roots come in v0.3; no other root exists.
            _ => return Err(bad()),
        };
        // Exactly these fields: the re-encoding is compared with the signed
        // bytes, which refuses any other key.
        Ok(entry)
    }
}

/// The owning server's offer of a channel to another server (rule 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractOffer {
    /// BLAKE3 of the payload's deterministic encoding without `offer_id`.
    pub offer_id: [u8; 32],
    /// The owning server, which signs the offer.
    pub owner: String,
    /// The server offered the channel. Naming it keeps an offer from being
    /// replayed to another server.
    pub to: String,
    pub channel_id: Cid,
    pub grant: Grant,
    /// The `channel-create` block, as it travels. The receiver checks that it
    /// hashes to `channel_id`.
    pub creation_block: Vec<u8>,
    /// The owner's current `ingest` head (JEP-0002), as it travels.
    pub ingest_head: Vec<u8>,
    pub manifest: ManifestRef,
    /// The suffixes the owner attests, each with its authority. A
    /// `config`-rooted one is disclosed only here and in an accept, never
    /// published (JEP-0004 rule 7).
    pub attested_suffixes: Vec<AttestedSuffix>,
    /// `owner`'s COSE_Sign1 over [`ContractOffer::payload`].
    pub envelope: Vec<u8>,
}

impl ContractOffer {
    const WHAT: &'static str = "contract offer";

    fn fields(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("domain", Value::text(OFFER_DOMAIN)),
            ("owner", Value::text(self.owner.clone())),
            ("to", Value::text(self.to.clone())),
            ("channel_id", Value::Bytes(self.channel_id.to_bytes())),
            ("grant", Value::text(self.grant.as_str())),
            ("creation_block", Value::Bytes(self.creation_block.clone())),
            ("ingest_head", Value::Bytes(self.ingest_head.clone())),
            ("manifest", self.manifest.value()),
            ("attested_suffixes", suffix_values(&self.attested_suffixes)),
        ]
    }

    /// What `offer_id` hashes: the payload without `offer_id`.
    fn unidentified(&self) -> Vec<u8> {
        encode(Value::text_map(self.fields()))
    }

    pub fn payload(&self) -> Vec<u8> {
        let mut fields = self.fields();
        fields.push(("offer_id", Value::Bytes(self.offer_id.to_vec())));
        encode(Value::text_map(fields))
    }

    /// An offer signed by `owner_key`, with its `offer_id` computed.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        owner_key: &SigningKey,
        to: &str,
        channel_id: Cid,
        grant: Grant,
        creation_block: Vec<u8>,
        ingest_head: Vec<u8>,
        manifest: ManifestRef,
        attested_suffixes: Vec<AttestedSuffix>,
    ) -> Self {
        let mut offer = Self {
            offer_id: [0; 32],
            owner: did_of(owner_key),
            to: to.to_string(),
            channel_id,
            grant,
            creation_block,
            ingest_head,
            manifest,
            attested_suffixes,
            envelope: Vec::new(),
        };
        offer.offer_id = *blake3::hash(&offer.unidentified()).as_bytes();
        offer.envelope = cose::sign1(owner_key, &offer.payload());
        offer
    }

    /// Parse an envelope, recompute `offer_id`, and check that `owner` signed.
    pub fn from_envelope(envelope: &[u8]) -> Result<Self, ContractError> {
        let p = open(envelope, OFFER_DOMAIN, Self::WHAT)?;
        let offer = Self {
            offer_id: digest(&p, "offer_id", Self::WHAT)?,
            owner: text(&p, "owner", Self::WHAT)?,
            to: text(&p, "to", Self::WHAT)?,
            channel_id: cid(&p, "channel_id", Self::WHAT)?,
            grant: Grant::parse(&text(&p, "grant", Self::WHAT)?)?,
            creation_block: bytes(&p, "creation_block", Self::WHAT)?,
            ingest_head: bytes(&p, "ingest_head", Self::WHAT)?,
            manifest: ManifestRef::read(field(&p, "manifest", Self::WHAT)?, Self::WHAT)?,
            attested_suffixes: suffixes(&p, Self::WHAT)?,
            envelope: envelope.to_vec(),
        };
        offer.verify()?;
        Ok(offer)
    }

    /// The envelope carries exactly these fields, `offer_id` is theirs, and
    /// `owner` signed.
    pub fn verify(&self) -> Result<(), ContractError> {
        if self.offer_id != *blake3::hash(&self.unidentified()).as_bytes() {
            return Err(ContractError::OfferIdMismatch);
        }
        verify_envelope(&self.envelope, &self.payload(), &self.owner)
    }
}

/// The offered server's acceptance (rule 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractAccept {
    /// The accepting server, which signs.
    pub server: String,
    pub channel_id: Cid,
    /// The offer accepted. An accept binds only that offer's grant.
    pub offer_id: [u8; 32],
    /// The channel's sequencer, as the accepting server understands it.
    pub sequencer: String,
    pub manifest: ManifestRef,
    /// The suffixes the accepting server attests, each with its authority.
    pub attested_suffixes: Vec<AttestedSuffix>,
    /// On a sequencer move, the bot DIDs the new sequencer minted (rule
    /// 11a); otherwise empty.
    pub bot_dids: Vec<String>,
    /// On a sequencer move, the new sequencer's `policy-approval`s (rule
    /// 11b), as COSE_Sign1 bytes: for the channel's current `channel-policy`
    /// and every live `block-install`. Signed only in a move accept
    /// ([`Self::is_move`]): an accept that is not one has no such key, so
    /// its bytes are what they were before moves existed.
    pub policy_approvals: Vec<Vec<u8>>,
    /// `server`'s COSE_Sign1 over [`ContractAccept::payload`].
    pub envelope: Vec<u8>,
}

impl ContractAccept {
    const WHAT: &'static str = "contract accept";

    pub fn payload(&self) -> Vec<u8> {
        let mut fields = vec![
            ("domain", Value::text(ACCEPT_DOMAIN)),
            ("server", Value::text(self.server.clone())),
            ("channel_id", Value::Bytes(self.channel_id.to_bytes())),
            ("offer_id", Value::Bytes(self.offer_id.to_vec())),
            ("sequencer", Value::text(self.sequencer.clone())),
            ("manifest", self.manifest.value()),
            ("attested_suffixes", suffix_values(&self.attested_suffixes)),
            ("bot_dids", texts(&self.bot_dids)),
        ];
        if self.is_move() {
            fields.push((
                "policy_approvals",
                Value::Array(
                    self.policy_approvals
                        .iter()
                        .cloned()
                        .map(Value::Bytes)
                        .collect(),
                ),
            ));
        }
        encode(Value::text_map(fields))
    }

    /// Whether this is a move accept (JEP-0005 rule 11a): the accepting
    /// server names itself as the channel's sequencer, which only a server
    /// taking the channel over does. It travels inside the owner's
    /// `sequencer-set` block, never as a `contract-answer`.
    pub fn is_move(&self) -> bool {
        self.server == self.sequencer
    }

    /// A move accept (rule 11a) as `server_key`, the new sequencer: of
    /// `held`, the offer of the channel it already accepted as a follower,
    /// naming itself as the sequencer, with the bot DIDs it minted for the
    /// channel's bots and its `policy-approval`s (rule 11b).
    pub fn sign_move(
        server_key: &SigningKey,
        held: &ContractOffer,
        manifest: ManifestRef,
        attested_suffixes: Vec<AttestedSuffix>,
        bot_dids: Vec<String>,
        policy_approvals: Vec<Vec<u8>>,
    ) -> Self {
        let server = did_of(server_key);
        let mut accept = Self {
            server: server.clone(),
            channel_id: held.channel_id,
            offer_id: held.offer_id,
            sequencer: server,
            manifest,
            attested_suffixes,
            bot_dids,
            policy_approvals,
            envelope: Vec::new(),
        };
        accept.envelope = cose::sign1(server_key, &accept.payload());
        accept
    }

    /// Accept `offer` as `server_key`.
    pub fn sign(
        server_key: &SigningKey,
        offer: &ContractOffer,
        manifest: ManifestRef,
        attested_suffixes: Vec<AttestedSuffix>,
        bot_dids: Vec<String>,
    ) -> Self {
        let mut accept = Self {
            server: did_of(server_key),
            channel_id: offer.channel_id,
            offer_id: offer.offer_id,
            sequencer: offer.owner.clone(),
            manifest,
            attested_suffixes,
            bot_dids,
            policy_approvals: Vec::new(),
            envelope: Vec::new(),
        };
        accept.envelope = cose::sign1(server_key, &accept.payload());
        accept
    }

    pub fn from_envelope(envelope: &[u8]) -> Result<Self, ContractError> {
        let p = open(envelope, ACCEPT_DOMAIN, Self::WHAT)?;
        let bot_dids = array(&p, "bot_dids", Self::WHAT)?
            .iter()
            .map(|v| v.as_text().map(str::to_string))
            .collect::<Option<_>>()
            .ok_or(ContractError::BadPayload(Self::WHAT))?;
        // Read when present; `verify` then refuses it on an accept that is not
        // a move, and its absence on one that is, by re-encoding.
        let policy_approvals = match p.get("policy_approvals") {
            None => Vec::new(),
            Some(v) => v
                .as_array()
                .ok_or(ContractError::BadPayload(Self::WHAT))?
                .iter()
                .map(|a| a.as_bytes().map(<[u8]>::to_vec))
                .collect::<Option<_>>()
                .ok_or(ContractError::BadPayload(Self::WHAT))?,
        };
        let accept = Self {
            server: text(&p, "server", Self::WHAT)?,
            channel_id: cid(&p, "channel_id", Self::WHAT)?,
            offer_id: digest(&p, "offer_id", Self::WHAT)?,
            sequencer: text(&p, "sequencer", Self::WHAT)?,
            manifest: ManifestRef::read(field(&p, "manifest", Self::WHAT)?, Self::WHAT)?,
            attested_suffixes: suffixes(&p, Self::WHAT)?,
            bot_dids,
            policy_approvals,
            envelope: envelope.to_vec(),
        };
        accept.verify()?;
        Ok(accept)
    }

    pub fn verify(&self) -> Result<(), ContractError> {
        verify_envelope(&self.envelope, &self.payload(), &self.server)
    }

    /// This accept answers `offer`: same offer, same channel, signed by the
    /// server the offer was made to.
    pub fn answers(&self, offer: &ContractOffer) -> Result<(), ContractError> {
        answers(self.offer_id, self.channel_id, &self.server, offer)
    }
}

/// The offered server's refusal (rule 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractRefuse {
    pub server: String,
    pub channel_id: Cid,
    pub offer_id: [u8; 32],
    pub code: RefuseCode,
    /// `server`'s COSE_Sign1 over [`ContractRefuse::payload`].
    pub envelope: Vec<u8>,
}

impl ContractRefuse {
    const WHAT: &'static str = "contract refuse";

    pub fn payload(&self) -> Vec<u8> {
        encode(Value::text_map([
            ("domain", Value::text(REFUSE_DOMAIN)),
            ("server", Value::text(self.server.clone())),
            ("channel_id", Value::Bytes(self.channel_id.to_bytes())),
            ("offer_id", Value::Bytes(self.offer_id.to_vec())),
            ("code", Value::text(self.code.as_str())),
        ]))
    }

    pub fn sign(server_key: &SigningKey, offer: &ContractOffer, code: RefuseCode) -> Self {
        let mut refuse = Self {
            server: did_of(server_key),
            channel_id: offer.channel_id,
            offer_id: offer.offer_id,
            code,
            envelope: Vec::new(),
        };
        refuse.envelope = cose::sign1(server_key, &refuse.payload());
        refuse
    }

    pub fn from_envelope(envelope: &[u8]) -> Result<Self, ContractError> {
        let p = open(envelope, REFUSE_DOMAIN, Self::WHAT)?;
        let refuse = Self {
            server: text(&p, "server", Self::WHAT)?,
            channel_id: cid(&p, "channel_id", Self::WHAT)?,
            offer_id: digest(&p, "offer_id", Self::WHAT)?,
            code: RefuseCode::parse(&text(&p, "code", Self::WHAT)?)?,
            envelope: envelope.to_vec(),
        };
        refuse.verify()?;
        Ok(refuse)
    }

    pub fn verify(&self) -> Result<(), ContractError> {
        verify_envelope(&self.envelope, &self.payload(), &self.server)
    }

    pub fn answers(&self, offer: &ContractOffer) -> Result<(), ContractError> {
        answers(self.offer_id, self.channel_id, &self.server, offer)
    }
}

/// Either side's end of a share (rule 11). Names the accepted offer, so it
/// ends exactly that share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractEnd {
    /// The server ending the share, which signs: the owner or the follower.
    pub server: String,
    pub channel_id: Cid,
    pub offer_id: [u8; 32],
    /// `server`'s COSE_Sign1 over [`ContractEnd::payload`].
    pub envelope: Vec<u8>,
}

impl ContractEnd {
    const WHAT: &'static str = "contract end";

    pub fn payload(&self) -> Vec<u8> {
        encode(Value::text_map([
            ("domain", Value::text(END_DOMAIN)),
            ("server", Value::text(self.server.clone())),
            ("channel_id", Value::Bytes(self.channel_id.to_bytes())),
            ("offer_id", Value::Bytes(self.offer_id.to_vec())),
        ]))
    }

    pub fn sign(server_key: &SigningKey, channel_id: Cid, offer_id: [u8; 32]) -> Self {
        let mut end = Self {
            server: did_of(server_key),
            channel_id,
            offer_id,
            envelope: Vec::new(),
        };
        end.envelope = cose::sign1(server_key, &end.payload());
        end
    }

    pub fn from_envelope(envelope: &[u8]) -> Result<Self, ContractError> {
        let p = open(envelope, END_DOMAIN, Self::WHAT)?;
        let end = Self {
            server: text(&p, "server", Self::WHAT)?,
            channel_id: cid(&p, "channel_id", Self::WHAT)?,
            offer_id: digest(&p, "offer_id", Self::WHAT)?,
            envelope: envelope.to_vec(),
        };
        end.verify()?;
        Ok(end)
    }

    pub fn verify(&self) -> Result<(), ContractError> {
        verify_envelope(&self.envelope, &self.payload(), &self.server)
    }
}

/// The most key links an [`OwnerKeyLinks`] carries: as many as a server
/// serves in its welcome, and a client follows (JEP-0012).
pub const MAX_OWNER_KEY_LINKS: usize = 16;

/// The owner's key-link chain for one offer (JEP-0005 rule 7, note D37):
/// from the DID the channel's creation block names as its sequencer to the
/// DID that signs the offer, when the owner has changed its key since the
/// channel was created. It travels in its own peer frame beside the
/// `contract-offer`, never inside it.
///
/// It is not signed. Each link is a COSE_Sign by both of its keys, and the
/// chain's ends are fixed by things that are signed: the creation block's
/// `sequencer` and the offer's `owner`. A receiver checks the chain against
/// both before it relies on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyLinks {
    /// The offer the chain is for.
    pub offer_id: [u8; 32],
    /// The links as COSE_Sign bytes, oldest first, as a welcome serves them.
    pub links: Vec<Vec<u8>>,
}

impl OwnerKeyLinks {
    const WHAT: &'static str = "owner key-link chain";

    /// The frame body: `{domain, offer_id, links}` in deterministic CBOR.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode(Value::text_map([
            ("domain", Value::text(OWNER_KEY_LINKS_DOMAIN)),
            ("offer_id", Value::Bytes(self.offer_id.to_vec())),
            (
                "links",
                Value::Array(self.links.iter().cloned().map(Value::Bytes).collect()),
            ),
        ]))
    }

    /// Read a frame body. It must be exactly [`Self::to_bytes`] of what it
    /// says: no other key, no other encoding. One to
    /// [`MAX_OWNER_KEY_LINKS`] links; whether they verify is the caller's to
    /// check, against the creation block and the offer.
    pub fn from_bytes(body: &[u8]) -> Result<Self, ContractError> {
        let p = dcbor::decode(body).map_err(|_| ContractError::BadPayload(Self::WHAT))?;
        if text(&p, "domain", Self::WHAT)? != OWNER_KEY_LINKS_DOMAIN {
            return Err(ContractError::BadPayload(Self::WHAT));
        }
        let links = array(&p, "links", Self::WHAT)?
            .iter()
            .map(|v| v.as_bytes().map(<[u8]>::to_vec))
            .collect::<Option<Vec<_>>>()
            .ok_or(ContractError::BadPayload(Self::WHAT))?;
        if links.is_empty() || links.len() > MAX_OWNER_KEY_LINKS {
            return Err(ContractError::BadPayload(Self::WHAT));
        }
        let read = Self {
            offer_id: digest(&p, "offer_id", Self::WHAT)?,
            links,
        };
        if read.to_bytes() != body {
            return Err(ContractError::BadPayload(Self::WHAT));
        }
        Ok(read)
    }
}

/// A request for one of `did`'s key packages, sent to one of its custodians
/// (rule 21). Signed by the requester, it names the channel the package is
/// for and the custodian it is addressed to, so a custodian can neither be
/// asked on another's behalf nor replay the request to another custodian as
/// a fresh one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KpRequest {
    /// The DID asking, which signs: the member adding `did`.
    pub requester: String,
    /// The DID whose key package is asked for.
    pub did: String,
    pub channel_id: Cid,
    /// The custodian's server DID.
    pub custodian: String,
    /// Fresh per request, so two requests never share bytes.
    pub nonce: [u8; 16],
    /// When the requester signed it, in Unix seconds on its clock.
    pub issued_at: i64,
    /// `requester`'s COSE_Sign1 over [`KpRequest::payload`].
    pub envelope: Vec<u8>,
}

impl KpRequest {
    const WHAT: &'static str = "key-package request";

    pub fn payload(&self) -> Vec<u8> {
        encode(Value::text_map([
            ("domain", Value::text(KP_REQUEST_DOMAIN)),
            ("requester", Value::text(self.requester.clone())),
            ("did", Value::text(self.did.clone())),
            ("channel_id", Value::Bytes(self.channel_id.to_bytes())),
            ("custodian", Value::text(self.custodian.clone())),
            ("nonce", Value::Bytes(self.nonce.to_vec())),
            ("issued_at", Value::int(self.issued_at)),
        ]))
    }

    pub fn sign(
        requester_key: &SigningKey,
        did: &str,
        channel_id: Cid,
        custodian: &str,
        nonce: [u8; 16],
        issued_at: i64,
    ) -> Self {
        let mut req = Self {
            requester: did_of(requester_key),
            did: did.to_string(),
            channel_id,
            custodian: custodian.to_string(),
            nonce,
            issued_at,
            envelope: Vec::new(),
        };
        req.envelope = cose::sign1(requester_key, &req.payload());
        req
    }

    pub fn from_envelope(envelope: &[u8]) -> Result<Self, ContractError> {
        let p = open(envelope, KP_REQUEST_DOMAIN, Self::WHAT)?;
        let nonce = bytes(&p, "nonce", Self::WHAT)?
            .try_into()
            .map_err(|_| ContractError::BadPayload(Self::WHAT))?;
        let issued_at = field(&p, "issued_at", Self::WHAT)?
            .as_i64()
            .ok_or(ContractError::BadPayload(Self::WHAT))?;
        let req = Self {
            requester: text(&p, "requester", Self::WHAT)?,
            did: text(&p, "did", Self::WHAT)?,
            channel_id: cid(&p, "channel_id", Self::WHAT)?,
            custodian: text(&p, "custodian", Self::WHAT)?,
            nonce,
            issued_at,
            envelope: envelope.to_vec(),
        };
        req.verify()?;
        Ok(req)
    }

    /// The requester signed exactly these fields, and the two DIDs it names
    /// are keys in their canonical spelling.
    pub fn verify(&self) -> Result<(), ContractError> {
        for did in [&self.did, &self.custodian] {
            if !is_canonical_did(did) {
                return Err(ContractError::BadDid(did.clone()));
            }
        }
        verify_envelope(&self.envelope, &self.payload(), &self.requester)
    }
}

/// A member's word to one server on whether others may add it to the
/// channels that server sequences (JEP-0017 R2, rules 16-20). Signed by the
/// member, it names the server, so it cannot be replayed to another, and
/// carries a `seq`: the server keeps only a higher one, and `allow = true`
/// at a higher `seq` undoes an earlier `allow = false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAdds {
    /// The member, which signs.
    pub did: String,
    /// The server DID the marker is addressed to.
    pub server: String,
    /// `false` ends local adds; `true` undoes that.
    pub allow: bool,
    pub seq: u64,
    /// `did`'s COSE_Sign1 over [`LocalAdds::payload`].
    pub envelope: Vec<u8>,
}

impl LocalAdds {
    const WHAT: &'static str = "local-adds marker";

    pub fn payload(&self) -> Vec<u8> {
        encode(Value::text_map([
            ("domain", Value::text(LOCAL_ADDS_DOMAIN)),
            ("did", Value::text(self.did.clone())),
            ("server", Value::text(self.server.clone())),
            ("allow", Value::Bool(self.allow)),
            ("seq", Value::Unsigned(self.seq)),
        ]))
    }

    pub fn sign(key: &SigningKey, server: &str, allow: bool, seq: u64) -> Self {
        let mut marker = Self {
            did: did_of(key),
            server: server.to_string(),
            allow,
            seq,
            envelope: Vec::new(),
        };
        marker.envelope = cose::sign1(key, &marker.payload());
        marker
    }

    pub fn from_envelope(envelope: &[u8]) -> Result<Self, ContractError> {
        let p = open(envelope, LOCAL_ADDS_DOMAIN, Self::WHAT)?;
        let allow = match field(&p, "allow", Self::WHAT)? {
            Value::Bool(b) => *b,
            _ => return Err(ContractError::BadPayload(Self::WHAT)),
        };
        let seq = field(&p, "seq", Self::WHAT)?
            .as_u64()
            .ok_or(ContractError::BadPayload(Self::WHAT))?;
        let marker = Self {
            did: text(&p, "did", Self::WHAT)?,
            server: text(&p, "server", Self::WHAT)?,
            allow,
            seq,
            envelope: envelope.to_vec(),
        };
        marker.verify()?;
        Ok(marker)
    }

    /// The member signed exactly these fields, and both DIDs are keys in
    /// their canonical spelling.
    pub fn verify(&self) -> Result<(), ContractError> {
        for did in [&self.did, &self.server] {
            if !is_canonical_did(did) {
                return Err(ContractError::BadDid(did.clone()));
            }
        }
        verify_envelope(&self.envelope, &self.payload(), &self.did)
    }
}

fn answers(
    offer_id: [u8; 32],
    channel_id: Cid,
    server: &str,
    offer: &ContractOffer,
) -> Result<(), ContractError> {
    if offer_id != offer.offer_id {
        return Err(ContractError::NotAnAnswer("another offer_id"));
    }
    if channel_id != offer.channel_id {
        return Err(ContractError::NotAnAnswer("another channel"));
    }
    if server != offer.to {
        return Err(ContractError::NotAnAnswer("signed by a server not offered"));
    }
    Ok(())
}

fn did_of(key: &SigningKey) -> String {
    Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
}

fn encode(map: Value) -> Vec<u8> {
    dcbor::encode(&map).expect("a map of text, bytes, integers and arrays encodes")
}

fn texts(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::text(s.clone())).collect())
}

fn field<'a>(map: &'a Value, key: &str, what: &'static str) -> Result<&'a Value, ContractError> {
    map.get(key).ok_or(ContractError::BadPayload(what))
}

fn text(map: &Value, key: &str, what: &'static str) -> Result<String, ContractError> {
    field(map, key, what)?
        .as_text()
        .map(str::to_string)
        .ok_or(ContractError::BadPayload(what))
}

fn bytes(map: &Value, key: &str, what: &'static str) -> Result<Vec<u8>, ContractError> {
    field(map, key, what)?
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or(ContractError::BadPayload(what))
}

fn digest(map: &Value, key: &str, what: &'static str) -> Result<[u8; 32], ContractError> {
    bytes(map, key, what)?
        .try_into()
        .map_err(|_| ContractError::BadPayload(what))
}

fn array<'a>(map: &'a Value, key: &str, what: &'static str) -> Result<&'a [Value], ContractError> {
    field(map, key, what)?
        .as_array()
        .ok_or(ContractError::BadPayload(what))
}

fn cid(map: &Value, key: &str, what: &'static str) -> Result<Cid, ContractError> {
    canonical_cid::from_bytes(&bytes(map, key, what)?).map_err(|_| ContractError::BadCid(what))
}

/// `attested_suffixes`: attested suffixes, each named once.
fn suffixes(map: &Value, what: &'static str) -> Result<Vec<AttestedSuffix>, ContractError> {
    let entries = array(map, "attested_suffixes", what)?
        .iter()
        .map(|v| AttestedSuffix::read(v, what))
        .collect::<Result<Vec<_>, _>>()?;
    for (i, entry) in entries.iter().enumerate() {
        if entries[..i].iter().any(|e| e.suffix == entry.suffix) {
            return Err(ContractError::BadSuffix(entry.suffix.clone()));
        }
    }
    Ok(entries)
}

fn suffix_values(entries: &[AttestedSuffix]) -> Value {
    Value::Array(entries.iter().map(AttestedSuffix::value).collect())
}

/// A normalised name suffix, as a name's part after `@` parses.
fn is_suffix(s: &str) -> bool {
    matches!(Name::parse(&format!("a@{s}")), Ok(n) if n.suffix == s)
}

/// `did` is a did:jig in its canonical spelling.
fn is_canonical_did(did: &str) -> bool {
    Did::from_did_jig_string(did)
        .ok()
        .and_then(|d| d.as_bytes().ok())
        .is_some_and(|key| Did::from_ed25519_pubkey(&key).to_did_jig_string() == did)
}

/// Open `envelope`, decode its payload and check its `domain`. The caller
/// still verifies the signature, through its own `verify`.
fn open(envelope: &[u8], domain: &str, what: &'static str) -> Result<Value, ContractError> {
    let opened = cose::open_sign1(envelope)?;
    let payload = dcbor::decode(&opened.payload).map_err(|_| ContractError::BadPayload(what))?;
    if text(&payload, "domain", what)? != domain {
        return Err(ContractError::BadPayload(what));
    }
    Ok(payload)
}

/// `envelope` carries exactly `payload` and is signed by `did`. Comparing
/// the re-encoded fields with the signed bytes also refuses unknown keys.
fn verify_envelope(envelope: &[u8], payload: &[u8], did: &str) -> Result<(), ContractError> {
    let opened = cose::open_sign1(envelope)?;
    if opened.payload != payload {
        return Err(ContractError::BadSignature(did.to_string()));
    }
    Ok(opened.verify(did)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_grant_relays_its_kinds_and_nothing_else() {
        use crate::BlockKind as K;
        for kind in [K::TextRender, K::EmailRender, K::EmailEncrypted] {
            assert!(!grant_allows(Grant::Read, kind), "{kind:?}");
            assert!(grant_allows(Grant::Write, kind), "{kind:?}");
            assert!(grant_allows(Grant::Member, kind), "{kind:?}");
        }
        for kind in [K::MemberAdd, K::MemberRemove] {
            assert!(!grant_allows(Grant::Write, kind), "{kind:?}");
            assert!(grant_allows(Grant::Member, kind), "{kind:?}");
        }
        for kind in [
            K::ChannelCreate,
            K::ChannelShare,
            K::ChannelUnshare,
            K::RoleAssign,
            K::ChannelArchive,
            K::ChannelPromote,
            K::ContractAccept,
            K::ServerManifest,
        ] {
            assert!(!grant_allows(Grant::Member, kind), "{kind:?}");
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn manifest(seq: u64) -> ManifestRef {
        ManifestRef {
            cid: canonical_cid::of(format!("manifest {seq}").as_bytes()),
            seq,
        }
    }

    /// Owner is key 1; the offered server is key 2.
    fn offer(grant: Grant) -> ContractOffer {
        ContractOffer::sign(
            &key(1),
            &did_of(&key(2)),
            canonical_cid::of(b"channel-create"),
            grant,
            b"channel-create".to_vec(),
            b"ingest head".to_vec(),
            manifest(3),
            vec![AttestedSuffix::config(
                "internal.example",
                [did_of(&key(1))],
            )],
        )
    }

    /// Re-sign `payload` as `key`: what a signer who changed a field after
    /// the fact, or a forger, would produce.
    fn resigned(key: &SigningKey, payload: Value) -> Vec<u8> {
        cose::sign1(key, &encode(payload))
    }

    #[test]
    fn every_message_round_trips() {
        let o = offer(Grant::Write);
        assert_eq!(ContractOffer::from_envelope(&o.envelope), Ok(o.clone()));
        let a = ContractAccept::sign(&key(2), &o, manifest(9), vec![], vec![]);
        assert_eq!(ContractAccept::from_envelope(&a.envelope), Ok(a.clone()));
        let r = ContractRefuse::sign(&key(2), &o, RefuseCode::NotAPeer);
        assert_eq!(ContractRefuse::from_envelope(&r.envelope), Ok(r.clone()));
        let e = ContractEnd::sign(&key(1), o.channel_id, o.offer_id);
        assert_eq!(ContractEnd::from_envelope(&e.envelope), Ok(e));
        assert_eq!(a.answers(&o), Ok(()));
        assert_eq!(r.answers(&o), Ok(()));
        assert_eq!(a.sequencer, o.owner);
    }

    #[test]
    fn offer_id_covers_every_other_field() {
        let a = offer(Grant::Write);
        let b = offer(Grant::Read);
        assert_ne!(a.offer_id, b.offer_id);

        // The owner re-signs a changed grant but keeps the old offer_id.
        let mut forged = b.clone();
        forged.offer_id = a.offer_id;
        let envelope = cose::sign1(&key(1), &forged.payload());
        assert_eq!(
            ContractOffer::from_envelope(&envelope),
            Err(ContractError::OfferIdMismatch)
        );
    }

    #[test]
    fn a_message_signed_by_anyone_but_its_server_is_refused() {
        let o = offer(Grant::Write);
        let mut by_stranger = o.clone();
        by_stranger.envelope = cose::sign1(&key(42), &o.payload());
        assert_eq!(
            by_stranger.verify(),
            Err(ContractError::BadSignature(o.owner.clone()))
        );

        let a = ContractAccept::sign(&key(2), &o, manifest(9), vec![], vec![]);
        let mut forged = a.clone();
        forged.envelope = cose::sign1(&key(42), &a.payload());
        assert!(ContractAccept::from_envelope(&forged.envelope).is_err());
    }

    #[test]
    fn a_field_changed_after_signing_fails() {
        let o = offer(Grant::Write);
        let mut changed = o.clone();
        changed.grant = Grant::Member;
        // `verify` re-derives offer_id first, so the change shows as either
        // error; both refuse.
        assert!(changed.verify().is_err());

        let a = ContractAccept::sign(&key(2), &o, manifest(9), vec![], vec![]);
        let mut changed = a.clone();
        changed.bot_dids.push(did_of(&key(77)));
        assert_eq!(
            changed.verify(),
            Err(ContractError::BadSignature(a.server.clone()))
        );
    }

    #[test]
    fn an_answer_to_another_offer_or_from_another_server_does_not_answer() {
        let o = offer(Grant::Write);
        let other = offer(Grant::Read);
        let for_other = ContractAccept::sign(&key(2), &other, manifest(9), vec![], vec![]);
        assert_eq!(
            for_other.answers(&o),
            Err(ContractError::NotAnAnswer("another offer_id"))
        );
        let from_third = ContractAccept::sign(&key(3), &o, manifest(9), vec![], vec![]);
        assert_eq!(
            from_third.answers(&o),
            Err(ContractError::NotAnAnswer("signed by a server not offered"))
        );
        let refused_by_third = ContractRefuse::sign(&key(3), &o, RefuseCode::PolicyRefused);
        assert!(refused_by_third.answers(&o).is_err());
    }

    #[test]
    fn unknown_codes_grants_and_domains_do_not_parse() {
        let o = offer(Grant::Write);
        let base = |code: &str| {
            Value::text_map([
                ("domain", Value::text(REFUSE_DOMAIN)),
                ("server", Value::text(did_of(&key(2)))),
                ("channel_id", Value::Bytes(o.channel_id.to_bytes())),
                ("offer_id", Value::Bytes(o.offer_id.to_vec())),
                ("code", Value::text(code)),
            ])
        };
        assert_eq!(
            ContractRefuse::from_envelope(&resigned(&key(2), base("PLEASE_GO_AWAY"))),
            Err(ContractError::UnknownCode("PLEASE_GO_AWAY".into()))
        );
        assert!(ContractRefuse::from_envelope(&resigned(&key(2), base("NOT_A_PEER"))).is_ok());
        for code in [
            "UNSUPPORTED_SUITE",
            "UNSUPPORTED_VERSION",
            "POLICY_REFUSED",
            "SUFFIX_CONFLICT",
        ] {
            assert_eq!(RefuseCode::parse(code).unwrap().as_str(), code);
        }
        assert_eq!(
            Grant::parse("admin"),
            Err(ContractError::UnknownGrant("admin".into()))
        );

        // An accept is not an offer, whatever its bytes.
        let a = ContractAccept::sign(&key(2), &o, manifest(9), vec![], vec![]);
        assert_eq!(
            ContractOffer::from_envelope(&a.envelope),
            Err(ContractError::BadPayload("contract offer"))
        );
    }

    #[test]
    fn an_unknown_key_or_a_non_canonical_cid_is_refused() {
        let o = offer(Grant::Write);
        let mut entries = match dcbor::decode(&o.payload()).unwrap() {
            Value::Map(entries) => entries,
            _ => unreachable!(),
        };
        entries.push((Value::text("extra"), Value::Unsigned(1)));
        assert!(ContractOffer::from_envelope(&resigned(&key(1), Value::Map(entries))).is_err());

        let end = |channel_id: Vec<u8>| {
            Value::text_map([
                ("domain", Value::text(END_DOMAIN)),
                ("server", Value::text(did_of(&key(1)))),
                ("channel_id", Value::Bytes(channel_id)),
                ("offer_id", Value::Bytes(o.offer_id.to_vec())),
            ])
        };
        let sha256 = Cid::new_v1(
            canonical_cid::RAW_CODEC,
            cid::multihash::Multihash::<64>::wrap(0x12, &[7; 32]).unwrap(),
        );
        assert_eq!(
            ContractEnd::from_envelope(&resigned(&key(1), end(sha256.to_bytes()))),
            Err(ContractError::BadCid("contract end"))
        );
    }

    /// Re-sign `o` with `entries` as its `attested_suffixes`, as raw values.
    fn with_suffix_values(mut o: ContractOffer, entries: Vec<Value>) -> Vec<u8> {
        let mut fields = o.fields();
        for (k, v) in fields.iter_mut() {
            if *k == "attested_suffixes" {
                *v = Value::Array(entries.clone());
            }
        }
        o.offer_id = *blake3::hash(&encode(Value::text_map(fields.clone()))).as_bytes();
        fields.push(("offer_id", Value::Bytes(o.offer_id.to_vec())));
        cose::sign1(&key(1), &encode(Value::text_map(fields)))
    }

    #[test]
    fn attested_suffixes_carry_one_authority_each() {
        let (a, b) = (did_of(&key(1)), did_of(&key(2)));
        let (low, high) = if a < b { (a, b) } else { (b, a) };
        let config = |suffix: &str, dids: Vec<&str>| {
            Value::text_map([
                ("suffix", Value::text(suffix)),
                ("root", Value::text("config")),
                (
                    "authorities",
                    Value::Array(dids.into_iter().map(Value::text).collect()),
                ),
            ])
        };
        let dns = |suffix: &str, domain: &str| {
            Value::text_map([
                ("suffix", Value::text(suffix)),
                ("root", Value::text("dns")),
                ("domain", Value::text(domain)),
            ])
        };
        let open = |entries| {
            ContractOffer::from_envelope(&with_suffix_values(offer(Grant::Read), entries))
        };

        // Both roots round-trip.
        let ok = open(vec![
            config("internal.example", vec![&low, &high]),
            dns("names.example.org", "names.example.org"),
        ])
        .unwrap();
        assert_eq!(
            ok.attested_suffixes,
            [
                AttestedSuffix::config("internal.example", [high.clone(), low.clone()]),
                AttestedSuffix::dns("names.example.org", "names.example.org"),
            ]
        );

        // One spelling only: refused otherwise.
        let upper = format!(
            "did:jig:z{}",
            low.strip_prefix("did:jig:z").unwrap().to_uppercase()
        );
        for (entries, suffix) in [
            (
                vec![config("Internal.Example", vec![&low])],
                "Internal.Example",
            ),
            (vec![config("x..y", vec![&low])], "x..y"),
            (vec![config("internal.example", vec![])], "internal.example"),
            (
                vec![config("internal.example", vec![&high, &low])],
                "internal.example",
            ),
            (
                vec![config("internal.example", vec![&low, &low])],
                "internal.example",
            ),
            (
                vec![config("internal.example", vec![&upper])],
                "internal.example",
            ),
            (
                vec![dns("names.example.org", "Names.Example.org")],
                "names.example.org",
            ),
            (
                vec![Value::text_map([
                    ("suffix", Value::text("internal.example")),
                    ("root", Value::text("contract")),
                ])],
                "internal.example",
            ),
            (
                vec![
                    config("internal.example", vec![&low]),
                    dns("internal.example", "internal.example"),
                ],
                "internal.example",
            ),
        ] {
            assert_eq!(
                open(entries),
                Err(ContractError::BadSuffix(suffix.into())),
                "{suffix}"
            );
        }
        // A bare string, as the format had before authorities.
        assert_eq!(
            open(vec![Value::text("internal.example")]),
            Err(ContractError::BadPayload("contract offer"))
        );
        // A field past the root's own.
        let mut extra = config("internal.example", vec![&low]);
        if let Value::Map(m) = &mut extra {
            m.push((Value::text("domain"), Value::text("internal.example")));
        }
        assert!(open(vec![extra]).is_err());
    }

    #[test]
    fn a_suffix_conflicts_only_under_another_authority() {
        let (a, b) = (did_of(&key(1)), did_of(&key(2)));
        let ours = AttestedSuffix::config("acme", [a.clone(), b.clone()]);
        assert!(!ours.conflicts_with(&AttestedSuffix::config("acme", [b.clone(), a.clone()])));
        assert!(ours.conflicts_with(&AttestedSuffix::config("acme", [a.clone()])));
        assert!(ours.conflicts_with(&AttestedSuffix::dns("acme", "acme")));
        assert!(!ours.conflicts_with(&AttestedSuffix::config("other", [a])));
        let dns = AttestedSuffix::dns("names.example.org", "names.example.org");
        assert!(!dns.conflicts_with(&dns.clone()));
        assert!(dns.conflicts_with(&AttestedSuffix::dns("names.example.org", "example.org")));
    }

    fn vectors() -> serde_json::Value {
        let (owner, follower) = (key(1), key(2));
        let o = ContractOffer::sign(
            &owner,
            &did_of(&follower),
            canonical_cid::of(b"channel-create"),
            Grant::Write,
            b"channel-create".to_vec(),
            b"ingest head".to_vec(),
            ManifestRef {
                cid: canonical_cid::of(b"owner manifest"),
                seq: 3,
            },
            vec![AttestedSuffix::config("internal.example", [did_of(&owner)])],
        );
        let follower_manifest = ManifestRef {
            cid: canonical_cid::of(b"follower manifest"),
            seq: 9,
        };
        let a = ContractAccept::sign(
            &follower,
            &o,
            follower_manifest,
            vec![AttestedSuffix::dns(
                "names.example.org",
                "names.example.org",
            )],
            vec![],
        );
        let r = ContractRefuse::sign(&follower, &o, RefuseCode::UnsupportedSuite);
        let e = ContractEnd::sign(&follower, o.channel_id, o.offer_id);
        serde_json::json!({
            "comment": "payload_hex is the deterministic CBOR payload; cose_sign1_hex is the envelope. creation_block and ingest_head are placeholder bytes.",
            "keys": {
                "comment": "Ed25519 seeds: every byte set to the given value",
                "owner": {"seed_byte": 1, "did": did_of(&owner)},
                "follower": {"seed_byte": 2, "did": did_of(&follower)},
            },
            "offer": {
                "offer_id_hex": hex::encode(o.offer_id),
                "payload_hex": hex::encode(o.payload()),
                "cose_sign1_hex": hex::encode(&o.envelope),
            },
            "accept": {
                "payload_hex": hex::encode(a.payload()),
                "cose_sign1_hex": hex::encode(&a.envelope),
            },
            "refuse": {
                "payload_hex": hex::encode(r.payload()),
                "cose_sign1_hex": hex::encode(&r.envelope),
            },
            "end": {
                "payload_hex": hex::encode(e.payload()),
                "cose_sign1_hex": hex::encode(&e.envelope),
            },
        })
    }

    /// The committed vectors pin the encoding: a change to any signed byte
    /// fails here, and the JEP's vectors must be regenerated on purpose.
    #[test]
    fn signed_bytes_match_the_committed_vectors() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../jig-spec/jep/vectors/0005/vectors.json"))
                .unwrap();
        assert_eq!(vectors(), v);
    }

    fn kp_request() -> KpRequest {
        // Derived, not a literal: CodeQL reads a literal nonce as a
        // hard-coded cryptographic value. Fixed all the same, for the vectors.
        let digest = blake3::hash(b"kp-request vector: nonce");
        let nonce: [u8; 16] = digest.as_bytes()[..16]
            .try_into()
            .expect("a blake3 digest is 32 bytes");
        KpRequest::sign(
            &key(3),
            &did_of(&key(4)),
            canonical_cid::of(b"channel-create"),
            &did_of(&key(5)),
            nonce,
            1_800_000_000,
        )
    }

    #[test]
    fn a_kp_request_round_trips_and_names_what_it_was_signed_for() {
        let r = kp_request();
        let back = KpRequest::from_envelope(&r.envelope).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.requester, did_of(&key(3)));
    }

    #[test]
    fn a_kp_request_signed_by_anyone_but_its_requester_is_refused() {
        let mut r = kp_request();
        r.requester = did_of(&key(9));
        r.envelope = cose::sign1(&key(3), &r.payload());
        assert!(matches!(
            KpRequest::from_envelope(&r.envelope),
            Err(ContractError::BadSignature(_))
        ));
    }

    #[test]
    fn a_kp_request_naming_a_non_canonical_did_is_refused() {
        let mut r = kp_request();
        r.custodian = "did:jig:not-a-key".into();
        r.envelope = cose::sign1(&key(3), &r.payload());
        assert!(matches!(
            KpRequest::from_envelope(&r.envelope),
            Err(ContractError::BadDid(_))
        ));
    }

    #[test]
    fn a_kp_request_under_another_domain_is_not_a_kp_request() {
        let e = ContractEnd::sign(&key(3), canonical_cid::of(b"c"), [1; 32]);
        assert!(matches!(
            KpRequest::from_envelope(&e.envelope),
            Err(ContractError::BadPayload(_))
        ));
    }

    fn kp_request_vectors() -> serde_json::Value {
        let r = kp_request();
        serde_json::json!({
            "comment": "A jig-kp-request-v1 (JEP-0005 rule 21). payload_hex is the deterministic CBOR payload; cose_sign1_hex is the envelope.",
            "keys": {
                "comment": "Ed25519 seeds: every byte set to the given value",
                "requester": {"seed_byte": 3, "did": did_of(&key(3))},
                "did": {"seed_byte": 4, "did": did_of(&key(4))},
                "custodian": {"seed_byte": 5, "did": did_of(&key(5))},
            },
            "request": {
                "payload_hex": hex::encode(r.payload()),
                "cose_sign1_hex": hex::encode(&r.envelope),
            },
        })
    }

    #[test]
    fn kp_request_bytes_match_the_committed_vectors() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../jig-spec/jep/vectors/0005/kp-request.json"
        ))
        .unwrap();
        assert_eq!(kp_request_vectors(), v);
    }

    fn local_adds() -> LocalAdds {
        LocalAdds::sign(&key(6), &did_of(&key(7)), false, 3)
    }

    #[test]
    fn a_local_adds_marker_round_trips() {
        for allow in [false, true] {
            let m = LocalAdds::sign(&key(6), &did_of(&key(7)), allow, 9);
            let back = LocalAdds::from_envelope(&m.envelope).unwrap();
            assert_eq!(back, m);
            assert_eq!(back.did, did_of(&key(6)));
            assert_eq!(back.server, did_of(&key(7)));
            assert_eq!((back.allow, back.seq), (allow, 9));
        }
    }

    #[test]
    fn a_local_adds_marker_signed_by_anyone_but_its_member_is_refused() {
        let mut m = local_adds();
        m.did = did_of(&key(9));
        m.envelope = cose::sign1(&key(6), &m.payload());
        assert!(matches!(
            LocalAdds::from_envelope(&m.envelope),
            Err(ContractError::BadSignature(_))
        ));
    }

    #[test]
    fn a_local_adds_marker_naming_a_non_canonical_server_is_refused() {
        let mut m = local_adds();
        m.server = "did:jig:not-a-key".into();
        m.envelope = cose::sign1(&key(6), &m.payload());
        assert!(matches!(
            LocalAdds::from_envelope(&m.envelope),
            Err(ContractError::BadDid(_))
        ));
    }

    #[test]
    fn a_local_adds_marker_under_another_domain_is_not_one() {
        let r = kp_request();
        assert!(matches!(
            LocalAdds::from_envelope(&r.envelope),
            Err(ContractError::BadPayload(_))
        ));
    }

    fn local_adds_vectors() -> serde_json::Value {
        let m = local_adds();
        serde_json::json!({
            "comment": "A jig-local-adds-v1 (JEP-0017 rule 8, R2) with allow = false. payload_hex is the deterministic CBOR payload; cose_sign1_hex is the envelope.",
            "keys": {
                "comment": "Ed25519 seeds: every byte set to the given value",
                "did": {"seed_byte": 6, "did": did_of(&key(6))},
                "server": {"seed_byte": 7, "did": did_of(&key(7))},
            },
            "marker": {
                "allow": false,
                "seq": 3,
                "payload_hex": hex::encode(m.payload()),
                "cose_sign1_hex": hex::encode(&m.envelope),
            },
        })
    }

    #[test]
    fn local_adds_bytes_match_the_committed_vectors() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../jig-spec/jep/vectors/0017/local-adds.json"
        ))
        .unwrap();
        assert_eq!(local_adds_vectors(), v);
    }

    /// `cargo test -p jig-core --features ed25519 contract::tests::print_local_adds_vectors -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_local_adds_vectors() {
        println!(
            "{}",
            serde_json::to_string_pretty(&local_adds_vectors()).unwrap()
        );
    }

    /// `cargo test -p jig-core --features ed25519 contract::tests::print_kp_request_vectors -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_kp_request_vectors() {
        println!(
            "{}",
            serde_json::to_string_pretty(&kp_request_vectors()).unwrap()
        );
    }

    /// A two-hop chain: the creation block's sequencer (seed 1) moved to
    /// seed 11, then to seed 12, which signs the offer.
    fn owner_key_links() -> OwnerKeyLinks {
        use crate::key_link::{Audience, SignedKeyLink};
        let hop = |old: u8, new: u8, at: i64| {
            SignedKeyLink::sign(&key(old), &key(new), Audience::Public, at)
                .unwrap()
                .envelope()
                .to_vec()
        };
        OwnerKeyLinks {
            offer_id: [7; 32],
            links: vec![hop(1, 11, 1_700_000_000), hop(11, 12, 1_700_000_600)],
        }
    }

    #[test]
    fn an_owner_key_link_chain_round_trips() {
        let chain = owner_key_links();
        assert_eq!(OwnerKeyLinks::from_bytes(&chain.to_bytes()), Ok(chain));
    }

    #[test]
    fn an_owner_key_link_chain_in_any_other_shape_is_refused() {
        let chain = owner_key_links();
        let refused = |body: Vec<u8>| {
            assert_eq!(
                OwnerKeyLinks::from_bytes(&body),
                Err(ContractError::BadPayload("owner key-link chain"))
            );
        };
        // No link, and more than a welcome serves.
        refused(
            OwnerKeyLinks {
                links: vec![],
                ..chain.clone()
            }
            .to_bytes(),
        );
        refused(
            OwnerKeyLinks {
                links: vec![chain.links[0].clone(); MAX_OWNER_KEY_LINKS + 1],
                ..chain.clone()
            }
            .to_bytes(),
        );
        // Another domain, a short offer_id, a link that is not bytes, and a
        // key the frame does not have.
        let with = |entries: Vec<(&str, Value)>| encode(Value::text_map(entries));
        let links = Value::Array(chain.links.iter().cloned().map(Value::Bytes).collect());
        refused(with(vec![
            ("domain", Value::text(END_DOMAIN)),
            ("offer_id", Value::Bytes(vec![7; 32])),
            ("links", links.clone()),
        ]));
        refused(with(vec![
            ("domain", Value::text(OWNER_KEY_LINKS_DOMAIN)),
            ("offer_id", Value::Bytes(vec![7; 31])),
            ("links", links.clone()),
        ]));
        refused(with(vec![
            ("domain", Value::text(OWNER_KEY_LINKS_DOMAIN)),
            ("offer_id", Value::Bytes(vec![7; 32])),
            ("links", Value::Array(vec![Value::text("a link")])),
        ]));
        refused(with(vec![
            ("domain", Value::text(OWNER_KEY_LINKS_DOMAIN)),
            ("offer_id", Value::Bytes(vec![7; 32])),
            ("links", links),
            ("signer", Value::text("anyone")),
        ]));
        refused(b"not cbor".to_vec());
    }

    fn owner_key_links_vectors() -> serde_json::Value {
        let chain = owner_key_links();
        serde_json::json!({
            "comment": "A jig-owner-key-links-v1 peer frame body (JEP-0005 rule 7, note D37): the owner's key-link chain from the DID its channel's creation block names to the DID that signs the offer. body_hex is the deterministic CBOR body; it is not signed. Each link is a public JEP-0012 key link (COSE_Sign), oldest first.",
            "keys": {
                "comment": "Ed25519 seeds: every byte set to the given value",
                "named": {"seed_byte": 1, "did": did_of(&key(1))},
                "between": {"seed_byte": 11, "did": did_of(&key(11))},
                "signer": {"seed_byte": 12, "did": did_of(&key(12))},
            },
            "offer_id_hex": hex::encode(chain.offer_id),
            "links_hex": chain.links.iter().map(hex::encode).collect::<Vec<_>>(),
            "body_hex": hex::encode(chain.to_bytes()),
        })
    }

    #[test]
    fn owner_key_link_bytes_match_the_committed_vectors() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../jig-spec/jep/vectors/0005/owner-key-links.json"
        ))
        .unwrap();
        assert_eq!(owner_key_links_vectors(), v);
    }

    /// `cargo test -p jig-core --features ed25519 contract::tests::print_owner_key_links_vectors -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_owner_key_links_vectors() {
        println!(
            "{}",
            serde_json::to_string_pretty(&owner_key_links_vectors()).unwrap()
        );
    }

    /// `cargo test -p jig-core --features ed25519 contract::tests::print_vectors -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_vectors() {
        println!("{}", serde_json::to_string_pretty(&vectors()).unwrap());
    }
}
