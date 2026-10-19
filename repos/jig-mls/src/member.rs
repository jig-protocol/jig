//! The client's half: one DID's MLS state across all its channels.
//!
//! Every operation writes through to the in-memory storage provider; callers
//! persist with [`Member::snapshot`] after anything that changes state and
//! restore with [`Member::restore`].
//!
//! # Commits are two-phase
//!
//! A member builds a commit, the server accepts or refuses the block carrying
//! it, and only then does the member merge ([`Member::confirm`]) or drop
//! ([`Member::abandon`]) it. Merging first would put the member in an epoch
//! the rest of the channel never reaches if the server says no.

use jig_core::Did;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    Capabilities, CredentialWithKey, ExtensionType, GroupId, KeyPackage, KeyPackageIn, MlsGroup,
    MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessageContent, ProtocolMessage,
    ProtocolVersion, Sender, StagedCommit, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider as _;

use crate::credential::{bound_did, credential_for, leaf_did, signer_from_seed};
use crate::delivery::decode_group_info;
use crate::{CIPHERSUITE, MlsError, Result, internal, malformed, rejected, snapshot};

pub struct Member {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    did: String,
    /// The lifetime of this member's own leaves, when not openmls's default
    /// (about three months from now). See [`Member::with_lifetime_until`].
    lifetime: Option<openmls::prelude::Lifetime>,
}

/// A new group: its id, and the epoch-0 public state a `channel-create` block
/// carries.
#[derive(Debug, Clone)]
pub struct CreatedGroup {
    pub group_id: Vec<u8>,
    pub group_info: Vec<u8>,
    pub ratchet_tree: Vec<u8>,
}

/// A commit waiting on the server.
#[derive(Debug, Clone)]
pub struct Commit {
    /// The commit (an MLS `PublicMessage`).
    pub commit: Vec<u8>,
    /// For adds: the welcome the new member joins from.
    pub welcome: Option<Vec<u8>>,
    /// The group info for the epoch the commit creates, for later external
    /// joiners.
    pub group_info: Option<Vec<u8>>,
    /// The epoch the commit is built on.
    pub epoch: u64,
}

/// What applying someone else's commit did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The commit is merged; the group is at `epoch`.
    Applied { epoch: u64 },
    /// The commit is from an epoch this member has already passed — its own,
    /// or one replayed in history.
    AlreadyApplied,
    /// The commit removed this member. Its state for the group is gone.
    Removed,
}

/// A decrypted application message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decrypted {
    pub plaintext: Vec<u8>,
    /// The sender's DID, from a leaf bound to its key.
    pub sender: String,
}

impl Member {
    /// A member with no groups. `seed` is the DID's 32-byte Ed25519 secret.
    pub fn new(seed: &[u8; 32], did: &Did) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer = signer_from_seed(seed, did)?;
        signer.store(provider.storage()).map_err(internal)?;
        let credential = credential_for(did)?;
        let did = did.to_did_jig_string();
        Ok(Self {
            provider,
            signer,
            credential,
            did,
            lifetime: None,
        })
    }

    /// Give this member's key packages and new groups a leaf lifetime that
    /// runs until `not_after` (seconds since the Unix epoch) instead of
    /// openmls's three months. openmls checks leaf lifetimes against the
    /// clock, so the checked-in conformance vectors are generated with a
    /// long one; nothing else may mint leaves like that.
    #[cfg(feature = "conformance")]
    pub fn with_lifetime_until(mut self, not_after: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.lifetime = Some(openmls::prelude::Lifetime::init(
            now.saturating_sub(3600),
            not_after,
        ));
        self
    }

    /// A member restored from [`Member::snapshot`] bytes.
    pub fn restore(seed: &[u8; 32], did: &Did, snapshot_bytes: &[u8]) -> Result<Self> {
        let member = Self::new(seed, did)?;
        snapshot::decode_into(snapshot_bytes, member.provider.storage())?;
        Ok(member)
    }

    /// Every group and pending key package, as bytes to persist.
    pub fn snapshot(&self) -> Vec<u8> {
        snapshot::encode(self.provider.storage())
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    /// Fresh key packages to publish. Their private halves stay in this
    /// member's state until a welcome consumes them, so snapshot afterwards.
    pub fn key_packages(&self, count: usize, last_resort: bool) -> Result<Vec<Vec<u8>>> {
        (0..count)
            .map(|_| {
                // Every package declares it understands the last-resort
                // extension, so a last-resort one validates like any other.
                let mut builder = KeyPackage::builder().leaf_node_capabilities(
                    Capabilities::builder()
                        .extensions(vec![ExtensionType::LastResort])
                        .build(),
                );
                if last_resort {
                    builder = builder.mark_as_last_resort();
                }
                if let Some(lifetime) = self.lifetime {
                    builder = builder.key_package_lifetime(lifetime);
                }
                builder
                    .build(
                        CIPHERSUITE,
                        &self.provider,
                        &self.signer,
                        self.credential.clone(),
                    )
                    .map_err(internal)?
                    .key_package()
                    .tls_serialize_detached()
                    .map_err(internal)
            })
            .collect()
    }

    /// Start a group with this member alone in it, at epoch 0.
    pub fn create_group(&self) -> Result<CreatedGroup> {
        let group = MlsGroup::new(
            &self.provider,
            &self.signer,
            &crate::create_config(self.lifetime),
            self.credential.clone(),
        )
        .map_err(internal)?;
        let group_info = group
            .export_group_info(self.provider.crypto(), &self.signer, true)
            .map_err(internal)?
            .tls_serialize_detached()
            .map_err(internal)?;
        let ratchet_tree = group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(internal)?;
        Ok(CreatedGroup {
            group_id: group.group_id().as_slice().to_vec(),
            group_info,
            ratchet_tree,
        })
    }

    pub fn has_group(&self, group_id: &[u8]) -> bool {
        self.load(group_id).is_ok()
    }

    pub fn epoch(&self, group_id: &[u8]) -> Result<u64> {
        Ok(self.load(group_id)?.epoch().as_u64())
    }

    /// DIDs in the group's tree, this member included.
    pub fn members(&self, group_id: &[u8]) -> Result<Vec<String>> {
        let group = self.load(group_id)?;
        group
            .members()
            .map(|m| bound_did(&m.credential, &m.signature_key))
            .collect()
    }

    /// Build a commit adding the owner of `key_package`, who must be
    /// `expected_did` — a server handing out someone else's package is
    /// refused here rather than discovered later.
    pub fn add(&self, group_id: &[u8], key_package: &[u8], expected_did: &str) -> Result<Commit> {
        let mut group = self.load(group_id)?;
        let package = KeyPackageIn::tls_deserialize_exact(key_package)
            .map_err(malformed)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(rejected)?;
        let owner = leaf_did(package.leaf_node())?;
        if owner != expected_did {
            return Err(MlsError::Rejected(format!(
                "the key package belongs to {owner}, not {expected_did}"
            )));
        }
        let epoch = group.epoch().as_u64();
        let (commit, welcome, info) = group
            .add_members(&self.provider, &self.signer, &[package])
            .map_err(rejected)?;
        Ok(Commit {
            commit: commit.tls_serialize_detached().map_err(internal)?,
            welcome: Some(welcome.tls_serialize_detached().map_err(internal)?),
            group_info: info.map(serialize_group_info).transpose()?,
            epoch,
        })
    }

    /// Build a commit removing `did`'s leaf.
    pub fn remove(&self, group_id: &[u8], did: &str) -> Result<Commit> {
        let mut group = self.load(group_id)?;
        let index = group
            .members()
            .find(|m| bound_did(&m.credential, &m.signature_key).as_deref() == Ok(did))
            .map(|m| m.index)
            .ok_or_else(|| MlsError::Rejected(format!("{did} is not in the group")))?;
        let epoch = group.epoch().as_u64();
        let (commit, _, info) = group
            .remove_members(&self.provider, &self.signer, &[index])
            .map_err(rejected)?;
        Ok(Commit {
            commit: commit.tls_serialize_detached().map_err(internal)?,
            welcome: None,
            group_info: info.map(serialize_group_info).transpose()?,
            epoch,
        })
    }

    /// Whether a commit this member built is waiting on the server.
    pub fn has_pending_commit(&self, group_id: &[u8]) -> bool {
        self.load(group_id)
            .map(|g| g.pending_commit().is_some())
            .unwrap_or(false)
    }

    /// The server accepted this member's commit: merge it.
    pub fn confirm(&self, group_id: &[u8]) -> Result<()> {
        let mut group = self.load(group_id)?;
        if group.pending_commit().is_some() {
            group
                .merge_pending_commit(&self.provider)
                .map_err(internal)?;
        }
        Ok(())
    }

    /// The server refused this member's commit: drop it.
    pub fn abandon(&self, group_id: &[u8]) -> Result<()> {
        let mut group = self.load(group_id)?;
        group
            .clear_pending_commit(self.provider.storage())
            .map_err(internal)
    }

    /// Join a group from its published group info with an external commit.
    /// The group is created locally at the new epoch straight away; if the
    /// server refuses the commit, [`Member::forget`] it.
    pub fn join_external(&self, group_info: &[u8]) -> Result<(Vec<u8>, Commit)> {
        let info = decode_group_info(group_info)?;
        let (group, bundle) = MlsGroup::external_commit_builder()
            .with_config(crate::join_config())
            .build_group(&self.provider, info, self.credential.clone())
            .map_err(rejected)?
            .load_psks(self.provider.storage())
            .map_err(internal)?
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &self.signer,
                |_| true,
            )
            .map_err(rejected)?
            .finalize(&self.provider)
            .map_err(rejected)?;
        let group_id = group.group_id().as_slice().to_vec();
        if let Err(e) = self.check_members(&group) {
            self.forget(&group_id)?;
            return Err(e);
        }
        let (commit, _, info) = bundle.into_contents();
        let new_epoch = group.epoch().as_u64();
        Ok((
            group_id,
            Commit {
                commit: commit.tls_serialize_detached().map_err(internal)?,
                welcome: None,
                group_info: info.map(serialize_group_info).transpose()?,
                epoch: new_epoch.saturating_sub(1),
            },
        ))
    }

    /// Join a group from a welcome addressed to one of this member's key
    /// packages. Returns the group id.
    pub fn join_welcome(&self, welcome: &[u8]) -> Result<Vec<u8>> {
        let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(malformed)?
            .extract()
        else {
            return Err(MlsError::Malformed("not an MLS welcome".to_string()));
        };
        let staged =
            StagedWelcome::new_from_welcome(&self.provider, &crate::join_config(), welcome, None)
                .map_err(rejected)?;
        for m in staged.members() {
            bound_did(&m.credential, &m.signature_key)?;
        }
        let group = staged.into_group(&self.provider).map_err(rejected)?;
        Ok(group.group_id().as_slice().to_vec())
    }

    /// Apply a commit someone else built, after the server accepted it.
    pub fn apply_commit(&self, group_id: &[u8], commit: &[u8]) -> Result<CommitOutcome> {
        let mut group = self.load(group_id)?;
        let message: ProtocolMessage = MlsMessageIn::tls_deserialize_exact(commit)
            .map_err(malformed)?
            .try_into_protocol_message()
            .map_err(malformed)?;
        let current = group.epoch().as_u64();
        let got = message.epoch().as_u64();
        if got < current {
            return Ok(CommitOutcome::AlreadyApplied);
        }
        if got > current {
            return Err(MlsError::StaleEpoch { current, got });
        }
        let processed = group
            .process_message(&self.provider, message)
            .map_err(rejected)?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(MlsError::Rejected(
                "the MLS message is not a commit".to_string(),
            ));
        };
        check_new_leaves(&staged)?;
        let removed = staged.self_removed();
        group
            .merge_staged_commit(&self.provider, *staged)
            .map_err(internal)?;
        if removed {
            self.forget(group_id)?;
            return Ok(CommitOutcome::Removed);
        }
        Ok(CommitOutcome::Applied {
            epoch: group.epoch().as_u64(),
        })
    }

    /// Encrypt an application message. Returns the message and the epoch it
    /// was encrypted in.
    pub fn encrypt(&self, group_id: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, u64)> {
        let mut group = self.load(group_id)?;
        let message = group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(rejected)?;
        Ok((
            message.tls_serialize_detached().map_err(internal)?,
            group.epoch().as_u64(),
        ))
    }

    /// Decrypt an application message. Works once per message: MLS deletes the
    /// key after use, so callers keep the plaintext.
    pub fn decrypt(&self, group_id: &[u8], message: &[u8]) -> Result<Decrypted> {
        let mut group = self.load(group_id)?;
        let message: ProtocolMessage = MlsMessageIn::tls_deserialize_exact(message)
            .map_err(malformed)?
            .try_into_protocol_message()
            .map_err(malformed)?;
        let processed = group
            .process_message(&self.provider, message)
            .map_err(rejected)?;
        let Sender::Member(index) = processed.sender() else {
            return Err(MlsError::Rejected(
                "application message from outside the group".to_string(),
            ));
        };
        let sender = group
            .member_at(*index)
            .ok_or_else(|| MlsError::Rejected("message from an empty leaf".to_string()))?;
        let sender = bound_did(&sender.credential, &sender.signature_key)?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => Ok(Decrypted {
                plaintext: m.into_bytes(),
                sender,
            }),
            _ => Err(MlsError::Rejected("not an application message".to_string())),
        }
    }

    /// Drop all local state for a group.
    pub fn forget(&self, group_id: &[u8]) -> Result<()> {
        if let Ok(mut group) = self.load(group_id) {
            group.delete(self.provider.storage()).map_err(internal)?;
        }
        Ok(())
    }

    fn load(&self, group_id: &[u8]) -> Result<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(internal)?
            .ok_or(MlsError::UnknownGroup)
    }

    fn check_members(&self, group: &MlsGroup) -> Result<()> {
        for m in group.members() {
            bound_did(&m.credential, &m.signature_key)?;
        }
        Ok(())
    }
}

/// The epoch an MLS commit or application message was built in, read from
/// its framing without decrypting anything. `None` for anything else.
pub fn message_epoch(bytes: &[u8]) -> Option<u64> {
    let message: ProtocolMessage = MlsMessageIn::tls_deserialize_exact(bytes)
        .ok()?
        .try_into_protocol_message()
        .ok()?;
    Some(message.epoch().as_u64())
}

fn serialize_group_info(info: openmls::messages::group_info::GroupInfo) -> Result<Vec<u8>> {
    MlsMessageOut::from(info)
        .tls_serialize_detached()
        .map_err(internal)
}

/// Every leaf a commit brings in must be bound to its DID. The delivery
/// service checks this too; a member checks it again because the server is
/// not trusted to.
fn check_new_leaves(staged: &StagedCommit) -> Result<()> {
    for add in staged.add_proposals() {
        leaf_did(add.add_proposal().key_package().leaf_node())?;
    }
    if let Some(leaf) = staged.update_path_leaf_node() {
        leaf_did(leaf)?;
    }
    Ok(())
}
