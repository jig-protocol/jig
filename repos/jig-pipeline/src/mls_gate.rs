//! The suite gate, and the MLS delivery service behind it.
//!
//! A channel's suite is fixed when it is created and every later block is
//! checked against it (spec: Encryption → Channels; JEP-0001). On an `mls`
//! channel the gate also validates the MLS payload each block carries, so the
//! server accepts a block only if the group can follow it:
//!
//! | Kind | On an `mls` channel |
//! | --- | --- |
//! | `channel-create` | `mls_group_info` + `mls_ratchet_tree`: the creator alone, at epoch 0 |
//! | `channel-create` of a `#dm/` slug | also `dm_peer`, and the slug must be the sender's and that peer's |
//! | `member-add` | `mls_commit` adding `member_did` (+ `mls_welcome`), or the sender's external commit |
//! | `member-remove` | `mls_commit` removing `member_did`; none when the sender leaves |
//! | content | `mls_message`, an application `PrivateMessage` for this group; no `body` |
//!
//! A restricted channel is always `mls` (ROADMAP D25): a `channel-create` that
//! is not open and names no suite, or suite `none`, is refused. Restricted
//! channels created as plaintext before that rule are frozen: they keep their
//! history, but take no new content.
//!
//! Pure like the write gate: the caller resolves the rows and applies the
//! returned [`MlsPlan`]. Validation is a pure function of the stored state, so
//! two racing commits both validate; the store's compare-and-swap on the epoch
//! decides which one lands.

use base64::{Engine, engine::general_purpose::STANDARD};
use jig_core::{BlockKind, BlockManifest, EncryptionSuite};
use jig_mls::delivery::{self, Intent};

use crate::persist::{StoredChannel, StoredMlsGroup};

/// Metadata keys the gate reads.
pub mod keys {
    pub const SUITE: &str = "suite";
    pub const GROUP_INFO: &str = "mls_group_info";
    pub const RATCHET_TREE: &str = "mls_ratchet_tree";
    pub const COMMIT: &str = "mls_commit";
    pub const WELCOME: &str = "mls_welcome";
    pub const MESSAGE: &str = "mls_message";
    pub const EPOCH: &str = "mls_epoch";
}

/// Why the gate refused a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteRefusal {
    /// A `channel-create` named a suite that is not in the registry.
    UnknownSuite(String),
    /// The block's suite is not the channel's.
    Mismatch {
        slug: String,
        channel: String,
        block: String,
    },
    /// A field the suite requires is absent or is not base64.
    Missing { field: &'static str },
    /// Plaintext `body` on an encrypted channel. Refused outright, so a buggy
    /// client cannot leak a message into a channel its users think is sealed.
    Plaintext {
        slug: String,
        suite: EncryptionSuite,
    },
    /// The MLS payload failed validation.
    Mls(jig_mls::MlsError),
    /// A restricted `channel-create` whose suite is not operator-confidential
    /// ([`EncryptionSuite::is_operator_confidential`]; today only `mls`).
    /// Content the server can read is open content; a creator who wants
    /// plaintext makes an open channel.
    RestrictedNeedsMls { slug: String },
    /// Content for a restricted channel that was created as plaintext, before
    /// restricted channels were always encrypted. Its history stays readable;
    /// it takes nothing new.
    PlaintextRestricted { slug: String },
}

/// What ingest must do once every gate has passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsPlan {
    /// Not an encrypted-channel block.
    Nothing,
    /// A new encrypted channel: record its group.
    Genesis(StoredMlsGroup),
    /// A commit: advance the group from `from_epoch`, if nobody beat us to it.
    Advance {
        slug: String,
        from_epoch: u64,
        state: Vec<u8>,
        to_epoch: u64,
        group_info: Option<Vec<u8>>,
    },
    /// Encrypted content: store and relay it; nothing to execute.
    Sealed,
}

/// The suite a `channel-create` asks for. Absent means `none`.
pub fn requested_suite(manifest: &BlockManifest) -> Result<EncryptionSuite, SuiteRefusal> {
    match manifest.metadata.get(keys::SUITE).and_then(|v| v.as_str()) {
        None => Ok(EncryptionSuite::Unencrypted),
        Some(s) => s
            .parse::<EncryptionSuite>()
            .map_err(|_| SuiteRefusal::UnknownSuite(s.to_string())),
    }
}

/// Decide what an encrypted channel needs from this block.
///
/// `sender` is the canonical DID the signature verified. `group` is the
/// channel's MLS row, required when the channel is `mls`.
pub fn plan(
    kind: BlockKind,
    sender: &str,
    manifest: &BlockManifest,
    channel: Option<&StoredChannel>,
    group: Option<&StoredMlsGroup>,
) -> Result<MlsPlan, SuiteRefusal> {
    let block_suite = manifest.content_suite();

    if kind == BlockKind::ChannelCreate {
        // The creation block itself is never encrypted; it names the suite
        // the channel's content will be.
        require_plaintext_block(manifest, block_suite)?;
        let suite = requested_suite(manifest)?;
        let slug = meta_str(manifest, "slug").unwrap_or_default().to_string();
        if slug.starts_with(jig_core::dm::DM_PREFIX) {
            check_dm_create(sender, manifest, &slug, suite)?;
        }
        // A restricted channel needs a suite its operator cannot read (D25).
        // Absent visibility is open, as the effect stores it; anything else
        // that is not exactly `open` is restricted (fail closed).
        let visibility = meta_str(manifest, "visibility").unwrap_or("open");
        if !suite.is_operator_confidential() && !crate::visibility::is_open(visibility) {
            return Err(SuiteRefusal::RestrictedNeedsMls { slug });
        }
        if suite != EncryptionSuite::Mls {
            return Ok(MlsPlan::Nothing);
        }
        let info = meta_bytes(manifest, keys::GROUP_INFO)?;
        let tree = meta_bytes(manifest, keys::RATCHET_TREE)?;
        let genesis = delivery::genesis(&info, &tree, sender).map_err(SuiteRefusal::Mls)?;
        return Ok(MlsPlan::Genesis(StoredMlsGroup {
            slug,
            group_id: genesis.group_id,
            state: genesis.state,
            epoch: 0,
            group_info: Some(info),
        }));
    }

    let Some(channel) = channel else {
        // No channel row: nothing to check a suite against, so only plaintext
        // passes. An encrypted block for a channel this server does not hold
        // cannot be validated, and is not carried on trust.
        return if block_suite == EncryptionSuite::Unencrypted {
            Ok(MlsPlan::Nothing)
        } else {
            Err(SuiteRefusal::Mismatch {
                slug: String::new(),
                channel: "unknown".to_string(),
                block: block_suite.to_string(),
            })
        };
    };
    // Fail closed on a suite string this build does not know.
    let channel_suite =
        channel
            .suite
            .parse::<EncryptionSuite>()
            .map_err(|_| SuiteRefusal::Mismatch {
                slug: channel.slug.clone(),
                channel: channel.suite.clone(),
                block: block_suite.to_string(),
            })?;

    match kind {
        BlockKind::MemberAdd
        | BlockKind::MemberRemove
        | BlockKind::ChannelPromote
        | BlockKind::ChannelArchive => {
            require_plaintext_block(manifest, block_suite)?;
            if channel_suite != EncryptionSuite::Mls {
                return Ok(MlsPlan::Nothing);
            }
            let group = group.ok_or(SuiteRefusal::Mls(jig_mls::MlsError::UnknownGroup))?;
            let member = meta_str(manifest, "member_did")
                .map(crate::effect::canonical_did_string)
                .unwrap_or_default();
            let intent = match kind {
                BlockKind::MemberAdd if member == sender => Intent::Join { joiner: sender },
                BlockKind::MemberAdd => {
                    // The new member needs it to join; refuse a commit that
                    // would put them in a group they can never read.
                    meta_bytes(manifest, keys::WELCOME)?;
                    Intent::Add {
                        committer: sender,
                        member: &member,
                    }
                }
                BlockKind::MemberRemove if member == sender => {
                    // Leaving: a member cannot commit its own removal. The
                    // next member online sends that commit.
                    if manifest.metadata.contains_key(keys::COMMIT) {
                        return Err(SuiteRefusal::Mls(jig_mls::MlsError::Rejected(
                            "a member cannot commit its own removal; leave without a commit"
                                .to_string(),
                        )));
                    }
                    return Ok(MlsPlan::Nothing);
                }
                BlockKind::MemberRemove => Intent::Remove {
                    committer: sender,
                    member: &member,
                },
                _ => return Ok(MlsPlan::Nothing),
            };
            let commit = meta_bytes(manifest, keys::COMMIT)?;
            let applied = delivery::apply_commit(&group.state, &group.group_id, &commit, intent)
                .map_err(SuiteRefusal::Mls)?;
            let group_info = match manifest.metadata.get(keys::GROUP_INFO) {
                None => None,
                Some(_) => {
                    let info = meta_bytes(manifest, keys::GROUP_INFO)?;
                    let (gid, epoch) =
                        delivery::group_info_epoch(&info).map_err(SuiteRefusal::Mls)?;
                    if gid != group.group_id || epoch != applied.epoch {
                        return Err(SuiteRefusal::Mls(jig_mls::MlsError::Rejected(format!(
                            "the group info is for epoch {epoch}, the commit makes {}",
                            applied.epoch
                        ))));
                    }
                    Some(info)
                }
            };
            Ok(MlsPlan::Advance {
                slug: channel.slug.clone(),
                from_epoch: group.epoch,
                state: applied.state,
                to_epoch: applied.epoch,
                group_info,
            })
        }
        _ => {
            // Content going into the channel.
            if block_suite != channel_suite {
                return Err(SuiteRefusal::Mismatch {
                    slug: channel.slug.clone(),
                    channel: channel_suite.to_string(),
                    block: block_suite.to_string(),
                });
            }
            let Some(payload_field) = channel_suite.payload_field() else {
                if !crate::visibility::is_open(&channel.visibility) {
                    return Err(SuiteRefusal::PlaintextRestricted {
                        slug: channel.slug.clone(),
                    });
                }
                return Ok(MlsPlan::Nothing);
            };
            // Every encrypted suite: ciphertext in the suite's field, and no
            // plaintext beside it.
            if manifest.metadata.contains_key("body") {
                return Err(SuiteRefusal::Plaintext {
                    slug: channel.slug.clone(),
                    suite: channel_suite,
                });
            }
            let payload = meta_bytes(manifest, payload_field)?;
            if channel_suite == EncryptionSuite::Mls {
                let group = group.ok_or(SuiteRefusal::Mls(jig_mls::MlsError::UnknownGroup))?;
                delivery::check_application(&group.state, &group.group_id, &payload)
                    .map_err(SuiteRefusal::Mls)?;
            }
            Ok(MlsPlan::Sealed)
        }
    }
}

/// Control-plane blocks are read by the server to apply them, so they are
/// never encrypted themselves, whatever their channel's suite.
fn require_plaintext_block(
    manifest: &BlockManifest,
    suite: EncryptionSuite,
) -> Result<(), SuiteRefusal> {
    if suite == EncryptionSuite::Unencrypted {
        Ok(())
    } else {
        Err(SuiteRefusal::Mismatch {
            slug: meta_str(manifest, "channel")
                .or_else(|| meta_str(manifest, "slug"))
                .unwrap_or_default()
                .to_string(),
            channel: "control-plane".to_string(),
            block: suite.to_string(),
        })
    }
}

/// A `#dm/` slug belongs to the pair whose DIDs derive it
/// ([`jig_core::dm::dm_slug`]). Only one of the two may create it, and only as
/// what a DM is: restricted and encrypted. Otherwise anyone could take a
/// pair's slug first, encrypted or not, and since the client refuses a DM
/// channel that is unencrypted or has anyone else in it, the two could then
/// never DM on this server. The whole prefix is reserved: the email bridge
/// opens its mail threads under `#email/`.
fn check_dm_create(
    sender: &str,
    manifest: &BlockManifest,
    slug: &str,
    suite: EncryptionSuite,
) -> Result<(), SuiteRefusal> {
    let peer = meta_str(manifest, "dm_peer").ok_or(SuiteRefusal::Missing { field: "dm_peer" })?;
    let peer = crate::effect::canonical_did_string(peer);
    let restricted =
        !crate::visibility::is_open(meta_str(manifest, "visibility").unwrap_or("open"));
    let refuse = |why: &str| {
        Err(SuiteRefusal::Mls(jig_mls::MlsError::Rejected(format!(
            "{slug} is a direct-message slug: {why}"
        ))))
    };
    if peer == sender {
        return refuse("dm_peer is the sender");
    }
    if jig_core::dm::dm_slug(sender, &peer) != slug {
        return refuse("it is not the sender's and dm_peer's");
    }
    if suite != EncryptionSuite::Mls || !restricted {
        return refuse("a direct message is restricted and encrypted");
    }
    Ok(())
}

fn meta_str<'a>(m: &'a BlockManifest, key: &str) -> Option<&'a str> {
    m.metadata.get(key).and_then(|v| v.as_str())
}

fn meta_bytes(m: &BlockManifest, key: &'static str) -> Result<Vec<u8>, SuiteRefusal> {
    meta_str(m, key)
        .and_then(|s| STANDARD.decode(s).ok())
        .ok_or(SuiteRefusal::Missing { field: key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_core::{Author, Did, Privacy};
    use jig_mls::member::Member;
    use semver::Version;
    use serde_json::{Value, json};

    struct Who {
        did: String,
        member: Member,
    }

    fn who(n: u8) -> Who {
        let seed = [n; 32];
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let did = Did::from_ed25519_pubkey(&key.verifying_key().to_bytes());
        Who {
            did: did.to_did_jig_string(),
            member: Member::new(&seed, &did).unwrap(),
        }
    }

    fn manifest(
        kind: BlockKind,
        sender: &str,
        suite: EncryptionSuite,
        meta: Value,
    ) -> BlockManifest {
        let mut b = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: sender.into(),
                public_key: None,
                roles: vec![],
            });
        if suite != EncryptionSuite::Unencrypted {
            b = b.privacy(Privacy {
                encryption: suite,
                recipients: vec![],
                metadata_visibility: Default::default(),
            });
        }
        if let Value::Object(map) = meta {
            for (k, v) in map {
                b = b.metadata_entry(&k, v);
            }
        }
        b.build().unwrap().with_kind(kind)
    }

    fn chan(suite: &str, owner: &str) -> StoredChannel {
        StoredChannel {
            id: "bafy".to_string(),
            slug: "#sealed".to_string(),
            visibility: "restricted".to_string(),
            created_at: 0,
            owner_did: owner.to_string(),
            suite: suite.to_string(),
        }
    }

    fn b64(b: &[u8]) -> String {
        STANDARD.encode(b)
    }

    /// Create an encrypted channel through the gate and return its group row.
    fn genesis(owner: &Who) -> StoredMlsGroup {
        let created = owner.member.create_group().unwrap();
        let m = manifest(
            BlockKind::ChannelCreate,
            &owner.did,
            EncryptionSuite::Unencrypted,
            json!({"slug": "#sealed", "suite": "mls",
                   "mls_group_info": b64(&created.group_info),
                   "mls_ratchet_tree": b64(&created.ratchet_tree)}),
        );
        match plan(BlockKind::ChannelCreate, &owner.did, &m, None, None).unwrap() {
            MlsPlan::Genesis(g) => g,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_unencrypted_channel_create_needs_nothing() {
        let a = who(1);
        let m = manifest(
            BlockKind::ChannelCreate,
            &a.did,
            EncryptionSuite::Unencrypted,
            json!({"slug": "#plain"}),
        );
        assert_eq!(
            plan(BlockKind::ChannelCreate, &a.did, &m, None, None),
            Ok(MlsPlan::Nothing)
        );
    }

    #[test]
    fn an_unknown_suite_is_refused_at_creation() {
        let a = who(1);
        let m = manifest(
            BlockKind::ChannelCreate,
            &a.did,
            EncryptionSuite::Unencrypted,
            json!({"slug": "#x", "suite": "rot13"}),
        );
        assert_eq!(
            plan(BlockKind::ChannelCreate, &a.did, &m, None, None),
            Err(SuiteRefusal::UnknownSuite("rot13".to_string()))
        );
    }

    /// D25: a restricted channel is always `mls`. Anything but exactly
    /// `open` is restricted, so a misspelt visibility cannot slip through
    /// as plaintext.
    #[test]
    fn a_restricted_channel_create_must_be_mls() {
        let a = who(1);
        for visibility in ["restricted", "Restricted", "private", ""] {
            for suite in [None, Some("none")] {
                let mut meta = json!({"slug": "#private", "visibility": visibility});
                if let Some(s) = suite {
                    meta["suite"] = json!(s);
                }
                let m = manifest(
                    BlockKind::ChannelCreate,
                    &a.did,
                    EncryptionSuite::Unencrypted,
                    meta,
                );
                assert_eq!(
                    plan(BlockKind::ChannelCreate, &a.did, &m, None, None),
                    Err(SuiteRefusal::RestrictedNeedsMls {
                        slug: "#private".to_string()
                    }),
                    "visibility {visibility:?}, suite {suite:?}"
                );
            }
        }
        // Open, said or implied, may still be plaintext.
        for meta in [
            json!({"slug": "#plain", "visibility": "open"}),
            json!({"slug": "#plain", "visibility": "open", "suite": "none"}),
        ] {
            let m = manifest(
                BlockKind::ChannelCreate,
                &a.did,
                EncryptionSuite::Unencrypted,
                meta,
            );
            assert_eq!(
                plan(BlockKind::ChannelCreate, &a.did, &m, None, None),
                Ok(MlsPlan::Nothing)
            );
        }
    }

    #[test]
    fn a_restricted_mls_channel_create_is_accepted() {
        let a = who(1);
        let created = a.member.create_group().unwrap();
        let m = manifest(
            BlockKind::ChannelCreate,
            &a.did,
            EncryptionSuite::Unencrypted,
            json!({"slug": "#sealed", "visibility": "restricted", "suite": "mls",
                   "mls_group_info": b64(&created.group_info),
                   "mls_ratchet_tree": b64(&created.ratchet_tree)}),
        );
        assert!(matches!(
            plan(BlockKind::ChannelCreate, &a.did, &m, None, None),
            Ok(MlsPlan::Genesis(_))
        ));
    }

    /// A restricted channel created plaintext before D25 keeps its history
    /// and its control plane, and takes no new content. Promoted to open it
    /// is an ordinary open channel again.
    #[test]
    fn a_plaintext_restricted_channel_is_frozen() {
        let a = who(1);
        let old = chan("none", &a.did);
        let post = manifest(
            BlockKind::TextRender,
            &a.did,
            EncryptionSuite::Unencrypted,
            json!({"channel": "#sealed", "body": "hi"}),
        );
        assert_eq!(
            plan(BlockKind::TextRender, &a.did, &post, Some(&old), None),
            Err(SuiteRefusal::PlaintextRestricted {
                slug: "#sealed".to_string()
            })
        );
        for kind in [
            BlockKind::MemberAdd,
            BlockKind::MemberRemove,
            BlockKind::ChannelPromote,
            BlockKind::ChannelArchive,
        ] {
            let m = manifest(
                kind,
                &a.did,
                EncryptionSuite::Unencrypted,
                json!({"channel": "#sealed", "member_did": who(2).did}),
            );
            assert_eq!(
                plan(kind, &a.did, &m, Some(&old), None),
                Ok(MlsPlan::Nothing),
                "{kind:?}"
            );
        }
        let promoted = StoredChannel {
            visibility: "open".to_string(),
            ..old
        };
        assert_eq!(
            plan(BlockKind::TextRender, &a.did, &post, Some(&promoted), None),
            Ok(MlsPlan::Nothing)
        );
    }

    #[test]
    fn an_encrypted_channel_create_needs_the_creators_group() {
        let a = who(1);
        let b = who(2);
        let g = genesis(&a);
        assert_eq!(g.epoch, 0);
        let created = a.member.create_group().unwrap();
        let m = manifest(
            BlockKind::ChannelCreate,
            &b.did,
            EncryptionSuite::Unencrypted,
            json!({"slug": "#sealed", "suite": "mls",
                   "mls_group_info": b64(&created.group_info),
                   "mls_ratchet_tree": b64(&created.ratchet_tree)}),
        );
        assert!(matches!(
            plan(BlockKind::ChannelCreate, &b.did, &m, None, None),
            Err(SuiteRefusal::Mls(_))
        ));
        let bare = manifest(
            BlockKind::ChannelCreate,
            &a.did,
            EncryptionSuite::Unencrypted,
            json!({"slug": "#sealed", "suite": "mls"}),
        );
        assert_eq!(
            plan(BlockKind::ChannelCreate, &a.did, &bare, None, None),
            Err(SuiteRefusal::Missing {
                field: keys::GROUP_INFO
            })
        );
    }

    /// Only one of a pair may create the pair's `#dm/` slug, and only as a
    /// restricted, encrypted channel. Anyone else taking it first would leave
    /// the two unable to DM here (the client refuses a DM with a third member).
    #[test]
    fn a_dm_slug_is_the_pairs_to_create() {
        let (a, b, m) = (who(1), who(2), who(3));
        let slug = jig_core::dm::dm_slug(&a.did, &b.did);
        let create = |sender: &Who, meta: Value| {
            let created = sender.member.create_group().unwrap();
            let mut meta = meta;
            meta["slug"] = slug.clone().into();
            meta["mls_group_info"] = b64(&created.group_info).into();
            meta["mls_ratchet_tree"] = b64(&created.ratchet_tree).into();
            let man = manifest(
                BlockKind::ChannelCreate,
                &sender.did,
                EncryptionSuite::Unencrypted,
                meta,
            );
            plan(BlockKind::ChannelCreate, &sender.did, &man, None, None)
        };
        let dm = json!({"suite": "mls", "visibility": "restricted", "dm": true});
        let with_peer = |peer: &str| {
            let mut v = dm.clone();
            v["dm_peer"] = peer.into();
            v
        };

        assert!(matches!(
            create(&a, with_peer(&b.did)),
            Ok(MlsPlan::Genesis(_))
        ));
        assert!(matches!(
            create(&b, with_peer(&a.did)),
            Ok(MlsPlan::Genesis(_))
        ));

        let refused = |r: Result<MlsPlan, SuiteRefusal>| matches!(r, Err(SuiteRefusal::Mls(_)));
        // A third party, whoever it names as the peer.
        assert!(refused(create(&m, with_peer(&a.did))));
        assert!(refused(create(&m, with_peer(&b.did))));
        // One of the pair, but not as a DM: open, or unencrypted.
        let mut open = with_peer(&b.did);
        open["visibility"] = "open".into();
        assert!(refused(create(&a, open)));
        let mut plain = with_peer(&b.did);
        plain["suite"] = "none".into();
        assert!(refused(create(&a, plain)));
        // Encrypted, but no peer named.
        assert_eq!(
            create(&a, dm.clone()),
            Err(SuiteRefusal::Missing { field: "dm_peer" })
        );
        // A plaintext squat naming no peer, on the pair's slug or any other.
        let squat = |slug: &str| {
            let man = manifest(
                BlockKind::ChannelCreate,
                &m.did,
                EncryptionSuite::Unencrypted,
                json!({"slug": slug, "visibility": "restricted"}),
            );
            plan(BlockKind::ChannelCreate, &m.did, &man, None, None)
        };
        assert_eq!(
            squat(&slug),
            Err(SuiteRefusal::Missing { field: "dm_peer" })
        );
        assert_eq!(
            squat("#dm/0011223344556677"),
            Err(SuiteRefusal::Missing { field: "dm_peer" })
        );
        // The rest of the namespace is not a DM; restricted, it still needs
        // `mls` like any other restricted channel.
        assert_eq!(
            squat("#email/0011223344556677"),
            Err(SuiteRefusal::RestrictedNeedsMls {
                slug: "#email/0011223344556677".to_string()
            })
        );
    }

    #[test]
    fn content_must_match_the_channel_suite() {
        let a = who(1);
        let g = genesis(&a);
        let sealed = chan("mls", &a.did);
        let plain = StoredChannel {
            visibility: "open".to_string(),
            ..chan("none", &a.did)
        };

        let text = manifest(
            BlockKind::TextRender,
            &a.did,
            EncryptionSuite::Unencrypted,
            json!({"channel": "#sealed", "body": "oops"}),
        );
        assert!(matches!(
            plan(
                BlockKind::TextRender,
                &a.did,
                &text,
                Some(&sealed),
                Some(&g)
            ),
            Err(SuiteRefusal::Mismatch { .. })
        ));
        assert_eq!(
            plan(BlockKind::TextRender, &a.did, &text, Some(&plain), None),
            Ok(MlsPlan::Nothing)
        );

        let (msg, _) = a.member.encrypt(&g.group_id, b"hi").unwrap();
        let sealed_text = manifest(
            BlockKind::TextRender,
            &a.did,
            EncryptionSuite::Mls,
            json!({"channel": "#sealed", "mls_message": b64(&msg)}),
        );
        assert_eq!(
            plan(
                BlockKind::TextRender,
                &a.did,
                &sealed_text,
                Some(&sealed),
                Some(&g)
            ),
            Ok(MlsPlan::Sealed)
        );
        assert!(matches!(
            plan(
                BlockKind::TextRender,
                &a.did,
                &sealed_text,
                Some(&plain),
                None
            ),
            Err(SuiteRefusal::Mismatch { .. })
        ));

        let leaky = manifest(
            BlockKind::TextRender,
            &a.did,
            EncryptionSuite::Mls,
            json!({"channel": "#sealed", "mls_message": b64(&msg), "body": "hi"}),
        );
        assert_eq!(
            plan(
                BlockKind::TextRender,
                &a.did,
                &leaky,
                Some(&sealed),
                Some(&g)
            ),
            Err(SuiteRefusal::Plaintext {
                slug: "#sealed".to_string(),
                suite: EncryptionSuite::Mls,
            })
        );
    }

    #[test]
    fn an_owner_add_advances_the_group_and_needs_a_welcome() {
        let a = who(1);
        let b = who(2);
        let g = genesis(&a);
        let kp = b.member.key_packages(1, false).unwrap().remove(0);
        let commit = a.member.add(&g.group_id, &kp, &b.did).unwrap();
        let sealed = chan("mls", &a.did);

        let no_welcome = manifest(
            BlockKind::MemberAdd,
            &a.did,
            EncryptionSuite::Unencrypted,
            json!({"channel": "#sealed", "member_did": b.did, "mls_commit": b64(&commit.commit)}),
        );
        assert_eq!(
            plan(
                BlockKind::MemberAdd,
                &a.did,
                &no_welcome,
                Some(&sealed),
                Some(&g)
            ),
            Err(SuiteRefusal::Missing {
                field: keys::WELCOME
            })
        );

        let m = manifest(
            BlockKind::MemberAdd,
            &a.did,
            EncryptionSuite::Unencrypted,
            json!({"channel": "#sealed", "member_did": b.did,
                   "mls_commit": b64(&commit.commit),
                   "mls_welcome": b64(commit.welcome.as_ref().unwrap()),
                   "mls_group_info": b64(commit.group_info.as_ref().unwrap())}),
        );
        match plan(BlockKind::MemberAdd, &a.did, &m, Some(&sealed), Some(&g)).unwrap() {
            MlsPlan::Advance {
                from_epoch,
                to_epoch,
                group_info,
                ..
            } => {
                assert_eq!((from_epoch, to_epoch), (0, 1));
                assert!(group_info.is_some());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn leaving_carries_no_commit() {
        let a = who(1);
        let b = who(2);
        let g = genesis(&a);
        let sealed = chan("mls", &a.did);
        let leave = manifest(
            BlockKind::MemberRemove,
            &b.did,
            EncryptionSuite::Unencrypted,
            json!({"channel": "#sealed", "member_did": b.did}),
        );
        assert_eq!(
            plan(
                BlockKind::MemberRemove,
                &b.did,
                &leave,
                Some(&sealed),
                Some(&g)
            ),
            Ok(MlsPlan::Nothing)
        );
        let kick_without_commit = manifest(
            BlockKind::MemberRemove,
            &a.did,
            EncryptionSuite::Unencrypted,
            json!({"channel": "#sealed", "member_did": b.did}),
        );
        assert_eq!(
            plan(
                BlockKind::MemberRemove,
                &a.did,
                &kick_without_commit,
                Some(&sealed),
                Some(&g)
            ),
            Err(SuiteRefusal::Missing {
                field: keys::COMMIT
            })
        );
    }

    /// A second suite runs through the same gate: open-only, ciphertext in
    /// its own field, no plaintext beside it, a sealed receipt, and no group.
    /// This crate's dev-dependency on jig-core registers the suite.
    mod test_aead {
        use super::*;
        use jig_core::suite::test_aead;

        fn open_chan(owner: &str) -> StoredChannel {
            StoredChannel {
                visibility: "open".to_string(),
                ..chan("test-aead", owner)
            }
        }

        fn post(sender: &str, meta: Value) -> BlockManifest {
            manifest(
                BlockKind::TextRender,
                sender,
                EncryptionSuite::TestAead,
                meta,
            )
        }

        #[test]
        fn create_is_open_only_and_needs_no_group() {
            let a = who(1);
            let open = manifest(
                BlockKind::ChannelCreate,
                &a.did,
                EncryptionSuite::Unencrypted,
                json!({"slug": "#t", "suite": "test-aead"}),
            );
            assert_eq!(
                plan(BlockKind::ChannelCreate, &a.did, &open, None, None),
                Ok(MlsPlan::Nothing)
            );
            let restricted = manifest(
                BlockKind::ChannelCreate,
                &a.did,
                EncryptionSuite::Unencrypted,
                json!({"slug": "#t", "suite": "test-aead", "visibility": "restricted"}),
            );
            assert_eq!(
                plan(BlockKind::ChannelCreate, &a.did, &restricted, None, None),
                Err(SuiteRefusal::RestrictedNeedsMls {
                    slug: "#t".to_string()
                })
            );
        }

        #[test]
        fn content_is_sealed_ciphertext_in_its_own_field() {
            let a = who(1);
            let c = open_chan(&a.did);
            let sealed = test_aead::seal("#sealed", &a.did, &[1; 12], b"hi");
            let ok = post(
                &a.did,
                json!({"channel": "#sealed", "test_ciphertext": b64(&sealed)}),
            );
            assert_eq!(
                plan(BlockKind::TextRender, &a.did, &ok, Some(&c), None),
                Ok(MlsPlan::Sealed)
            );
            let missing = post(&a.did, json!({"channel": "#sealed"}));
            assert_eq!(
                plan(BlockKind::TextRender, &a.did, &missing, Some(&c), None),
                Err(SuiteRefusal::Missing {
                    field: "test_ciphertext"
                })
            );
            let leaky = post(
                &a.did,
                json!({"channel": "#sealed", "test_ciphertext": b64(&sealed), "body": "hi"}),
            );
            assert_eq!(
                plan(BlockKind::TextRender, &a.did, &leaky, Some(&c), None),
                Err(SuiteRefusal::Plaintext {
                    slug: "#sealed".to_string(),
                    suite: EncryptionSuite::TestAead,
                })
            );
            // MLS ciphertext is not this suite's, and neither is plaintext.
            for (suite, meta) in [
                (
                    EncryptionSuite::Mls,
                    json!({"channel": "#sealed", "mls_message": "AA=="}),
                ),
                (
                    EncryptionSuite::Unencrypted,
                    json!({"channel": "#sealed", "body": "hi"}),
                ),
            ] {
                let m = manifest(BlockKind::TextRender, &a.did, suite, meta);
                assert!(matches!(
                    plan(BlockKind::TextRender, &a.did, &m, Some(&c), None),
                    Err(SuiteRefusal::Mismatch { .. })
                ));
            }
        }

        #[test]
        fn membership_is_plain_control() {
            let a = who(1);
            let c = open_chan(&a.did);
            let add = manifest(
                BlockKind::MemberAdd,
                &a.did,
                EncryptionSuite::Unencrypted,
                json!({"channel": "#sealed", "member_did": who(2).did}),
            );
            assert_eq!(
                plan(BlockKind::MemberAdd, &a.did, &add, Some(&c), None),
                Ok(MlsPlan::Nothing)
            );
            let declared = manifest(
                BlockKind::MemberAdd,
                &a.did,
                EncryptionSuite::TestAead,
                json!({"channel": "#sealed", "member_did": who(2).did}),
            );
            assert!(matches!(
                plan(BlockKind::MemberAdd, &a.did, &declared, Some(&c), None),
                Err(SuiteRefusal::Mismatch { .. })
            ));
        }
    }
}
