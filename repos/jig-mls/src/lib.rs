//! MLS for jig: one channel is one MLS group.
//!
//! Two roles share this crate so they share one configuration:
//!
//! - [`delivery`] is the server. It never holds a group secret. It tracks
//!   each encrypted channel's public state (an openmls `PublicGroup`), runs
//!   every commit through it before the block carrying the commit is accepted,
//!   and checks that application messages name the channel's group and a
//!   current epoch. That is what makes the channel's history linear and keeps
//!   the MLS tree and jig's membership table from drifting apart.
//! - [`member`] is the client: create, join, commit, encrypt, decrypt.
//!
//! # Identity
//!
//! A `did:jig` is an Ed25519 public key, and the ciphersuite below signs with
//! Ed25519, so the DID's own key is the MLS signature key. Every leaf carries a
//! basic credential whose identity is the canonical DID string; [`credential`]
//! checks that the two agree wherever a leaf enters a group.
//!
//! # Wire format
//!
//! Handshake messages (commits) are MLS `PublicMessage`s so the delivery
//! service can validate them; application messages are always
//! `PrivateMessage`s. Revealing commits reveals adds, removes and key updates —
//! the membership metadata the spec already says a server sees.

pub mod credential;
pub mod delivery;
pub mod member;
pub mod snapshot;

use openmls::prelude::{
    Ciphersuite, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY, MlsGroupCreateConfig, MlsGroupJoinConfig,
};

/// The one MLS ciphersuite jig speaks: X25519 key agreement, AES-128-GCM,
/// SHA-256, Ed25519 signatures. Ed25519 is the reason — see the crate docs.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// How many epochs back a member keeps secrets for, so a message encrypted
/// just before a commit landed still decrypts after it. The delivery service
/// accepts application messages up to this far behind the current epoch.
pub const PAST_EPOCHS: u64 = 3;

/// Errors from either role. The variants are what a caller branches on; the
/// strings are diagnostics.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum MlsError {
    /// Bytes that do not decode as the MLS structure they were supposed to be.
    #[error("malformed MLS data: {0}")]
    Malformed(String),
    /// A commit built on an epoch other than the group's current one. The
    /// sender has to catch up and rebuild it.
    #[error("commit is for epoch {got}, the channel is at epoch {current}")]
    StaleEpoch { current: u64, got: u64 },
    /// Well-formed MLS that does not do what the jig block carrying it says,
    /// or that openmls refuses as invalid.
    #[error("MLS message rejected: {0}")]
    Rejected(String),
    /// A leaf whose credential does not name the DID of its own signature key.
    #[error("credential is not bound to its key: {0}")]
    Unbound(String),
    /// No local state for the group.
    #[error("not a member of this group")]
    UnknownGroup,
    /// A storage or library failure that is not about the input.
    #[error("MLS internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, MlsError>;

pub(crate) fn create_config(lifetime: Option<openmls::prelude::Lifetime>) -> MlsGroupCreateConfig {
    let mut builder = MlsGroupCreateConfig::builder();
    if let Some(lifetime) = lifetime {
        builder = builder.lifetime(lifetime);
    }
    builder
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(PAST_EPOCHS as usize)
        .build()
}

pub(crate) fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(PAST_EPOCHS as usize)
        .build()
}

pub(crate) fn internal(e: impl std::fmt::Display) -> MlsError {
    MlsError::Internal(e.to_string())
}

pub(crate) fn malformed(e: impl std::fmt::Display) -> MlsError {
    MlsError::Malformed(e.to_string())
}

pub(crate) fn rejected(e: impl std::fmt::Display) -> MlsError {
    MlsError::Rejected(e.to_string())
}
