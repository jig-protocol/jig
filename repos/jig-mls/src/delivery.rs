//! The server's half: a validating MLS delivery service.
//!
//! Holds no group secret. Each encrypted channel has a public state snapshot
//! (an openmls `PublicGroup`) that starts from the creator's epoch-0 group
//! info and advances only through commits that pass [`apply_commit`]. A commit
//! is accepted only if it is built on the current epoch, is valid MLS, and
//! does exactly what the jig block carrying it claims — so the tree and the
//! membership table cannot drift apart, and no member can wedge the channel
//! with a commit nobody else can process.

use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    Ciphersuite, GroupId, KeyPackageIn, MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent,
    ProposalStore, ProposalType, ProtocolMessage, ProtocolVersion, PublicGroup, RatchetTreeIn,
    Sender, StagedCommit,
};
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;

use crate::credential::leaf_did;
use crate::{CIPHERSUITE, MlsError, PAST_EPOCHS, Result, internal, malformed, rejected, snapshot};

/// A channel's public MLS state at creation.
#[derive(Debug, Clone)]
pub struct Genesis {
    pub state: Vec<u8>,
    pub group_id: Vec<u8>,
}

/// What a commit-carrying block claims the commit does. The DIDs are the
/// canonical strings the block's signature established.
#[derive(Debug, Clone, Copy)]
pub enum Intent<'a> {
    /// `committer`, already in the group, adds `member` (member-add by the owner).
    Add { committer: &'a str, member: &'a str },
    /// `joiner` adds itself with an external commit (self-join on an open channel).
    Join { joiner: &'a str },
    /// `committer`, in the group, removes `member`'s leaf.
    Remove { committer: &'a str, member: &'a str },
}

/// Public state after an accepted commit.
#[derive(Debug, Clone)]
pub struct Applied {
    pub state: Vec<u8>,
    pub epoch: u64,
}

/// A validated key package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackageInfo {
    /// The DID the key package belongs to; its key signed the package.
    pub did: String,
    /// The package's hash reference: what a welcome names it by, and what a
    /// server remembers so a consumed package cannot be uploaded again.
    pub reference: Vec<u8>,
    /// Handed out without being consumed, so its owner stays reachable.
    pub last_resort: bool,
}

/// Start tracking a channel from its creator's epoch-0 group info and ratchet
/// tree. The group must be at epoch 0 with exactly one member: `creator`.
pub fn genesis(group_info: &[u8], ratchet_tree: &[u8], creator: &str) -> Result<Genesis> {
    let info = decode_group_info(group_info)?;
    let tree = RatchetTreeIn::tls_deserialize_exact(ratchet_tree).map_err(malformed)?;
    let storage = MemoryStorage::default();
    let (group, _) = PublicGroup::from_external(
        &RustCrypto::default(),
        &storage,
        tree,
        info,
        ProposalStore::new(),
    )
    .map_err(rejected)?;
    let epoch = group.group_context().epoch().as_u64();
    if epoch != 0 {
        return Err(MlsError::Rejected(format!(
            "a new channel's group must be at epoch 0, not {epoch}"
        )));
    }
    let members: Vec<_> = group.members().collect();
    let [only] = members.as_slice() else {
        return Err(MlsError::Rejected(format!(
            "a new channel's group must hold only its creator, not {} members",
            members.len()
        )));
    };
    let did = crate::credential::bound_did(&only.credential, &only.signature_key)?;
    if did != creator {
        return Err(MlsError::Rejected(format!(
            "the group's only member is {did}, but the channel is created by {creator}"
        )));
    }
    Ok(Genesis {
        state: snapshot::encode(&storage),
        group_id: group.group_id().as_slice().to_vec(),
    })
}

/// The epoch a channel's public state is at.
pub fn epoch(state: &[u8], group_id: &[u8]) -> Result<u64> {
    let (_, group) = load(state, group_id)?;
    Ok(group.group_context().epoch().as_u64())
}

/// The DIDs whose leaves are in the tree.
pub fn members(state: &[u8], group_id: &[u8]) -> Result<Vec<String>> {
    let (_, group) = load(state, group_id)?;
    group
        .members()
        .map(|m| crate::credential::bound_did(&m.credential, &m.signature_key))
        .collect()
}

/// Validate `commit` against the channel's state and the block's `intent`,
/// and return the state after it.
pub fn apply_commit(
    state: &[u8],
    group_id: &[u8],
    commit: &[u8],
    intent: Intent<'_>,
) -> Result<Applied> {
    let (storage, mut group) = load(state, group_id)?;
    let message = MlsMessageIn::tls_deserialize_exact(commit).map_err(malformed)?;
    let message: ProtocolMessage = message.try_into_protocol_message().map_err(malformed)?;
    if !matches!(message, ProtocolMessage::PublicMessage(_)) {
        return Err(MlsError::Rejected(
            "a commit must be sent as an MLS PublicMessage so the server can validate it"
                .to_string(),
        ));
    }
    if message.group_id().as_slice() != group_id {
        return Err(MlsError::Rejected(
            "the commit is for a different group than this channel's".to_string(),
        ));
    }
    let current = group.group_context().epoch().as_u64();
    let got = message.epoch().as_u64();
    if got != current {
        return Err(MlsError::StaleEpoch { current, got });
    }

    let processed = group
        .process_message(&RustCrypto::default(), message)
        .map_err(rejected)?;
    let sender = processed.sender().clone();
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        return Err(MlsError::Rejected(
            "the MLS message is not a commit".to_string(),
        ));
    };

    let signer = match (&intent, &sender) {
        (Intent::Add { committer, .. } | Intent::Remove { committer, .. }, Sender::Member(i)) => {
            let leaf = group
                .leaf(*i)
                .ok_or_else(|| MlsError::Rejected("commit from an empty leaf".to_string()))?;
            expect_did(leaf_did(leaf)?, committer, "the commit is signed by")?
        }
        (Intent::Join { joiner }, Sender::NewMemberCommit) => {
            let leaf = staged.update_path_leaf_node().ok_or_else(|| {
                MlsError::Rejected("an external commit must carry a path".to_string())
            })?;
            expect_did(leaf_did(leaf)?, joiner, "the external commit joins")?
        }
        _ => {
            return Err(MlsError::Rejected(format!(
                "a {intent:?} block cannot carry a commit from {sender:?}"
            )));
        }
    };
    // A member commit may also refresh the committer's own leaf; it must stay
    // the committer's.
    if let Some(leaf) = staged.update_path_leaf_node() {
        expect_did(leaf_did(leaf)?, &signer, "the commit's new leaf belongs to")?;
    }
    check_proposals(&group, &staged, intent)?;

    group.merge_commit(&storage, *staged).map_err(internal)?;
    Ok(Applied {
        state: snapshot::encode(&storage),
        epoch: group.group_context().epoch().as_u64(),
    })
}

/// Check that `message` is an MLS application message for this channel's
/// group at the current epoch or one of the last [`PAST_EPOCHS`]. Returns its
/// epoch. The content itself is opaque here; that is the point.
pub fn check_application(state: &[u8], group_id: &[u8], message: &[u8]) -> Result<u64> {
    let (_, group) = load(state, group_id)?;
    let message = MlsMessageIn::tls_deserialize_exact(message).map_err(malformed)?;
    let MlsMessageBodyIn::PrivateMessage(private) = message.extract() else {
        return Err(MlsError::Rejected(
            "encrypted content must be an MLS PrivateMessage".to_string(),
        ));
    };
    if private.group_id().as_slice() != group_id {
        return Err(MlsError::Rejected(
            "the message is for a different group than this channel's".to_string(),
        ));
    }
    if private.content_type() != openmls::prelude::ContentType::Application {
        return Err(MlsError::Rejected(
            "only application messages may be posted as content; commits ride membership blocks"
                .to_string(),
        ));
    }
    let current = group.group_context().epoch().as_u64();
    let got = private.epoch().as_u64();
    if got > current || current - got > PAST_EPOCHS {
        return Err(MlsError::StaleEpoch { current, got });
    }
    Ok(got)
}

/// The group id and epoch a serialized group info claims. The server stores a
/// committer's group info for external joiners; a joiner verifies its
/// signature, so the server only checks it describes the state it just
/// accepted.
pub fn group_info_epoch(group_info: &[u8]) -> Result<(Vec<u8>, u64)> {
    let info = decode_group_info(group_info)?;
    Ok((info.group_id().as_slice().to_vec(), info.epoch().as_u64()))
}

/// Validate a key package someone is publishing: well-formed, self-signed,
/// jig's ciphersuite, and bound to the DID whose key signed it.
pub fn validate_key_package(bytes: &[u8]) -> Result<KeyPackageInfo> {
    let crypto = RustCrypto::default();
    let package = decode_key_package(bytes)?
        .validate(&crypto, ProtocolVersion::Mls10)
        .map_err(rejected)?;
    let did = leaf_did(package.leaf_node())?;
    let reference = package.hash_ref(&crypto).map_err(internal)?;
    Ok(KeyPackageInfo {
        did,
        reference: reference.as_slice().to_vec(),
        last_resort: package.last_resort(),
    })
}

/// Re-serialize a group info, so callers can store a canonical copy.
pub fn reencode(bytes: &[u8]) -> Result<Vec<u8>> {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(malformed)?
        .tls_serialize_detached()
        .map_err(internal)
}

fn load(state: &[u8], group_id: &[u8]) -> Result<(MemoryStorage, PublicGroup)> {
    let storage = snapshot::decode(state)?;
    let group = PublicGroup::load(&storage, &GroupId::from_slice(group_id))
        .map_err(internal)?
        .ok_or(MlsError::UnknownGroup)?;
    Ok((storage, group))
}

/// Decode a group info, refusing any ciphersuite but jig's before its
/// signature, or anything else in it, is checked.
pub(crate) fn decode_group_info(bytes: &[u8]) -> Result<VerifiableGroupInfo> {
    match MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(malformed)?
        .extract()
    {
        MlsMessageBodyIn::GroupInfo(info) => {
            require_ciphersuite(info.ciphersuite(), "group")?;
            Ok(info)
        }
        _ => Err(MlsError::Malformed("not an MLS group info".to_string())),
    }
}

/// Decode a key package, refusing any ciphersuite but jig's before its
/// signature is checked. openmls reads the ciphersuite only once it has
/// verified the package, so it is taken from the encoding: RFC 9420 §10 puts
/// it right after the two-byte protocol version.
pub(crate) fn decode_key_package(bytes: &[u8]) -> Result<KeyPackageIn> {
    let package = KeyPackageIn::tls_deserialize_exact(bytes).map_err(malformed)?;
    let suite = u16::from_be_bytes([bytes[2], bytes[3]]);
    let suite = Ciphersuite::try_from(suite).map_err(|_| {
        MlsError::Rejected(format!("key package ciphersuite {suite:#06x} is not jig's"))
    })?;
    require_ciphersuite(suite, "key package")?;
    Ok(package)
}

/// The one check every MLS structure jig is handed passes first: anything in
/// another ciphersuite would run that suite's crypto (P-256, for one) on it.
pub(crate) fn require_ciphersuite(suite: Ciphersuite, what: &str) -> Result<()> {
    if suite == CIPHERSUITE {
        Ok(())
    } else {
        Err(MlsError::Rejected(format!(
            "{what} ciphersuite {suite:?} is not jig's {CIPHERSUITE:?}"
        )))
    }
}

fn expect_did(found: String, expected: &str, what: &str) -> Result<String> {
    if found == expected {
        Ok(found)
    } else {
        Err(MlsError::Rejected(format!(
            "{what} {found}, but the block says {expected}"
        )))
    }
}

/// The proposals a commit covers must be exactly what the block says: one add
/// of `member`, one removal of `member`, or (external join) nothing but the
/// joiner replacing an old leaf of its own. Anything else — group-context
/// changes, pre-shared keys, re-init, updates by reference — is refused rather
/// than reasoned about.
fn check_proposals(group: &PublicGroup, staged: &StagedCommit, intent: Intent<'_>) -> Result<()> {
    for queued in staged.queued_proposals() {
        let kind = queued.proposal().proposal_type();
        let allowed = matches!(kind, ProposalType::Add | ProposalType::Remove)
            || (matches!(intent, Intent::Join { .. }) && kind == ProposalType::ExternalInit);
        if !allowed {
            return Err(MlsError::Rejected(format!(
                "a jig commit may not carry a {kind:?} proposal"
            )));
        }
    }
    let adds = staged
        .add_proposals()
        .map(|a| leaf_did(a.add_proposal().key_package().leaf_node()))
        .collect::<Result<Vec<_>>>()?;
    let removes = staged
        .remove_proposals()
        .map(|r| {
            let leaf = group.leaf(r.remove_proposal().removed()).ok_or_else(|| {
                MlsError::Rejected("the commit removes an empty leaf".to_string())
            })?;
            leaf_did(leaf)
        })
        .collect::<Result<Vec<_>>>()?;

    let ok = match intent {
        Intent::Add { member, .. } => removes.is_empty() && adds == [member],
        Intent::Remove { member, .. } => adds.is_empty() && removes == [member],
        Intent::Join { joiner } => adds.is_empty() && removes.iter().all(|d| d == joiner),
    };
    if ok {
        Ok(())
    } else {
        Err(MlsError::Rejected(format!(
            "the commit adds {adds:?} and removes {removes:?}, which is not what a {intent:?} block does"
        )))
    }
}
