//! The channel contract's blocks (JEP-0005 rules 7, 10 and 11).
//!
//! A share is driven by blocks in the channel's own log:
//! - `channel-share {to, grant}` and `channel-unshare {to}`, signed by a DID
//!   holding the `share` right, ask the owning server to offer the channel to
//!   `to`, or to end the share it has with `to`;
//! - `contract-accept`, `contract-refuse` and `contract-end` record what came
//!   of it. Only the channel's sequencer writes them, and each carries the
//!   signed contract messages ([`jig_core::contract`]) it records, base64
//!   in metadata, so any member can check them without trusting the
//!   sequencer's word.
//!
//! This module reads and checks those blocks' metadata. Who may sign each one
//! is [`crate::authorize_write`]'s call.

use base64::Engine as _;
use cid::Cid;
use jig_core::BlockManifest;
use jig_core::block_kind::BlockKind;
use jig_core::contract::{
    ContractAccept, ContractEnd, ContractError, ContractOffer, ContractRefuse, Grant, RefuseCode,
};

/// The server a share names: the target of `channel-share` and
/// `channel-unshare`, and the follower a `contract-*` record is about.
pub const TO_KEY: &str = "to";
/// The grant a `channel-share` asks for (rule 7a).
pub const GRANT_KEY: &str = "grant";
/// The signed `contract-offer`, base64.
pub const OFFER_KEY: &str = "offer";
/// The signed `contract-accept`, base64.
pub const ACCEPT_KEY: &str = "accept";
/// The signed `contract-refuse`, base64.
pub const REFUSE_KEY: &str = "refuse";
/// A `contract-refuse`'s code (rule 8), in clear so it reads without
/// decoding the envelope, and present when there is none.
pub const CODE_KEY: &str = "code";
/// The signed `contract-end`, base64.
pub const END_KEY: &str = "end";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContractBlockError {
    #[error("`{0}` is missing")]
    Missing(&'static str),
    #[error("`{0}` is not a canonical did:jig")]
    BadServer(String),
    #[error("`{0}` is not base64")]
    NotBase64(&'static str),
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error("{0}")]
    Mismatch(&'static str),
}

/// What a `channel-share` or `channel-unshare` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareRequest {
    /// The target server's DID, canonical.
    pub to: String,
    /// The grant asked for; `None` for a `channel-unshare`.
    pub grant: Option<Grant>,
}

/// Read a `channel-share` or `channel-unshare`.
pub fn share_request(
    kind: BlockKind,
    manifest: &BlockManifest,
) -> Result<ShareRequest, ContractBlockError> {
    let to = server(manifest)?;
    let grant = match kind {
        BlockKind::ChannelShare => Some(Grant::parse(
            meta_str(manifest, GRANT_KEY).ok_or(ContractBlockError::Missing(GRANT_KEY))?,
        )?),
        _ => None,
    };
    Ok(ShareRequest { to, grant })
}

/// Check a `contract-accept`, `contract-refuse` or `contract-end` record for
/// the channel `channel_id`, whose sequencer is `sequencer`: its envelopes are
/// signed by whom they name, are about this channel, and fit together.
pub fn check_record(
    kind: BlockKind,
    manifest: &BlockManifest,
    channel_id: &Cid,
    sequencer: &str,
) -> Result<(), ContractBlockError> {
    let to = server(manifest)?;
    let same_channel = |cid: &Cid| {
        if cid == channel_id {
            Ok(())
        } else {
            Err(ContractBlockError::Mismatch(
                "the message is for another channel",
            ))
        }
    };
    let owners_offer = |offer: &ContractOffer| {
        same_channel(&offer.channel_id)?;
        if offer.owner != sequencer {
            return Err(ContractBlockError::Mismatch(
                "the offer is not signed by the channel's sequencer",
            ));
        }
        if offer.to != to {
            return Err(ContractBlockError::Mismatch(
                "the offer is to another server",
            ));
        }
        Ok(())
    };
    match kind {
        BlockKind::ContractAccept => {
            let offer = ContractOffer::from_envelope(&envelope(manifest, OFFER_KEY)?)?;
            let accept = ContractAccept::from_envelope(&envelope(manifest, ACCEPT_KEY)?)?;
            owners_offer(&offer)?;
            accept.answers(&offer)?;
            Ok(())
        }
        BlockKind::ContractRefuse => {
            let code = RefuseCode::parse(
                meta_str(manifest, CODE_KEY).ok_or(ContractBlockError::Missing(CODE_KEY))?,
            )?;
            // The owning server's own refusal (a target that is not a peer)
            // has no message from the target to carry.
            if !manifest.metadata.contains_key(REFUSE_KEY) {
                return Ok(());
            }
            let refuse = ContractRefuse::from_envelope(&envelope(manifest, REFUSE_KEY)?)?;
            let offer = ContractOffer::from_envelope(&envelope(manifest, OFFER_KEY)?)?;
            owners_offer(&offer)?;
            refuse.answers(&offer)?;
            if refuse.code != code {
                return Err(ContractBlockError::Mismatch(
                    "`code` is not the refusal's code",
                ));
            }
            Ok(())
        }
        BlockKind::ContractEnd => {
            let end = ContractEnd::from_envelope(&envelope(manifest, END_KEY)?)?;
            same_channel(&end.channel_id)?;
            if end.server != sequencer && end.server != to {
                return Err(ContractBlockError::Mismatch(
                    "the end is signed by neither side of the share",
                ));
            }
            Ok(())
        }
        _ => Err(ContractBlockError::Mismatch("not a contract record")),
    }
}

/// The base64 envelope under `key`, decoded.
pub fn envelope(
    manifest: &BlockManifest,
    key: &'static str,
) -> Result<Vec<u8>, ContractBlockError> {
    let b64 = meta_str(manifest, key).ok_or(ContractBlockError::Missing(key))?;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| ContractBlockError::NotBase64(key))
}

/// `to`, which must be a did:jig in canonical form: a share names a server
/// the way the peer list and the contract messages do, so one server has
/// one spelling.
fn server(manifest: &BlockManifest) -> Result<String, ContractBlockError> {
    let to = meta_str(manifest, TO_KEY).ok_or(ContractBlockError::Missing(TO_KEY))?;
    let canonical = crate::effect::canonical_did_string(to);
    if canonical != to || jig_core::Did::from_did_jig_string(to).is_err() {
        return Err(ContractBlockError::BadServer(to.to_string()));
    }
    Ok(canonical)
}

fn meta_str<'a>(manifest: &'a BlockManifest, key: &str) -> Option<&'a str> {
    manifest.metadata.get(key).and_then(|v| v.as_str())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use jig_core::Author;
    use jig_core::contract::ManifestRef;
    use semver::Version;
    use serde_json::json;

    pub(crate) struct Parties {
        pub owner: SigningKey,
        pub follower: SigningKey,
        pub channel_id: Cid,
    }

    pub(crate) fn did(key: &SigningKey) -> String {
        jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    pub(crate) fn parties() -> Parties {
        Parties {
            owner: SigningKey::from_bytes(&[1; 32]),
            follower: SigningKey::from_bytes(&[2; 32]),
            channel_id: jig_core::canonical_cid::of(b"channel-create"),
        }
    }

    impl Parties {
        pub(crate) fn offer(&self) -> ContractOffer {
            let manifest = ManifestRef {
                cid: jig_core::canonical_cid::of(b"server-manifest"),
                seq: 1,
            };
            ContractOffer::sign(
                &self.owner,
                &did(&self.follower),
                self.channel_id,
                Grant::Write,
                b"creation".to_vec(),
                b"head".to_vec(),
                manifest,
                vec![],
            )
        }

        pub(crate) fn accept(&self, offer: &ContractOffer) -> ContractAccept {
            let manifest = ManifestRef {
                cid: jig_core::canonical_cid::of(b"follower-manifest"),
                seq: 3,
            };
            ContractAccept::sign(&self.follower, offer, manifest, vec![], vec![])
        }
    }

    pub(crate) fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    pub(crate) fn block(
        kind: BlockKind,
        author: &str,
        metadata: serde_json::Value,
    ) -> BlockManifest {
        let mut builder = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: author.into(),
                public_key: None,
                roles: vec![],
            });
        if let serde_json::Value::Object(map) = metadata {
            for (k, v) in map {
                builder = builder.metadata_entry(&k, v);
            }
        }
        builder.build().unwrap().with_kind(kind)
    }

    /// A `contract-accept` record as the sequencer writes it.
    pub(crate) fn accept_record(p: &Parties) -> BlockManifest {
        let offer = p.offer();
        let accept = p.accept(&offer);
        block(
            BlockKind::ContractAccept,
            &did(&p.owner),
            json!({
                "to": did(&p.follower),
                "offer": b64(&offer.envelope),
                "accept": b64(&accept.envelope),
            }),
        )
    }

    fn check(p: &Parties, kind: BlockKind, m: &BlockManifest) -> Result<(), ContractBlockError> {
        check_record(kind, m, &p.channel_id, &did(&p.owner))
    }

    #[test]
    fn a_share_names_a_canonical_server_and_a_grant() {
        let to = did(&parties().follower);
        let share = |meta| {
            share_request(
                BlockKind::ChannelShare,
                &block(BlockKind::ChannelShare, "x", meta),
            )
        };
        assert_eq!(
            share(json!({"to": to, "grant": "member"})),
            Ok(ShareRequest {
                to: to.clone(),
                grant: Some(Grant::Member)
            })
        );
        assert_eq!(
            share(json!({"grant": "read"})),
            Err(ContractBlockError::Missing(TO_KEY))
        );
        assert_eq!(
            share(json!({"to": to})),
            Err(ContractBlockError::Missing(GRANT_KEY))
        );
        assert!(matches!(
            share(json!({"to": to, "grant": "admin"})),
            Err(ContractBlockError::Contract(ContractError::UnknownGrant(_)))
        ));
        // Another spelling of the same key, and something that is no DID.
        let body = to.strip_prefix("did:jig:z").unwrap();
        for bad in [
            format!("did:jig:z{}", body.to_uppercase()),
            "did:jig:zNope".into(),
        ] {
            assert_eq!(
                share(json!({"to": bad, "grant": "read"})),
                Err(ContractBlockError::BadServer(bad.clone()))
            );
        }
        // An unshare needs no grant.
        let unshare = block(BlockKind::ChannelUnshare, "x", json!({"to": to}));
        assert_eq!(
            share_request(BlockKind::ChannelUnshare, &unshare),
            Ok(ShareRequest { to, grant: None })
        );
    }

    #[test]
    fn an_accept_record_carries_the_owners_offer_and_its_answer() {
        let p = parties();
        assert_eq!(
            check(&p, BlockKind::ContractAccept, &accept_record(&p)),
            Ok(())
        );

        // An offer for another channel.
        let elsewhere = Parties {
            channel_id: jig_core::canonical_cid::of(b"another channel"),
            ..parties()
        };
        assert_eq!(
            check(&p, BlockKind::ContractAccept, &accept_record(&elsewhere)),
            Err(ContractBlockError::Mismatch(
                "the message is for another channel"
            ))
        );

        // An offer someone other than the sequencer signed.
        let impostor = Parties {
            owner: SigningKey::from_bytes(&[9; 32]),
            ..parties()
        };
        assert_eq!(
            check(&p, BlockKind::ContractAccept, &accept_record(&impostor)),
            Err(ContractBlockError::Mismatch(
                "the offer is not signed by the channel's sequencer"
            ))
        );

        // An accept of a different offer.
        let offer = p.offer();
        let other = ContractOffer::sign(
            &p.owner,
            &did(&p.follower),
            p.channel_id,
            Grant::Read,
            vec![],
            vec![],
            ManifestRef {
                cid: p.channel_id,
                seq: 0,
            },
            vec![],
        );
        let m = block(
            BlockKind::ContractAccept,
            &did(&p.owner),
            json!({
                "to": did(&p.follower),
                "offer": b64(&offer.envelope),
                "accept": b64(&p.accept(&other).envelope),
            }),
        );
        assert!(matches!(
            check(&p, BlockKind::ContractAccept, &m),
            Err(ContractBlockError::Contract(ContractError::NotAnAnswer(_)))
        ));

        // `to` that is not the server the offer was made to.
        let mut m = accept_record(&p);
        m.metadata.insert("to".into(), json!(did(&p.owner)));
        assert_eq!(
            check(&p, BlockKind::ContractAccept, &m),
            Err(ContractBlockError::Mismatch(
                "the offer is to another server"
            ))
        );

        // A tampered envelope, and one that is not base64.
        let mut m = accept_record(&p);
        let mut bytes = envelope(&m, ACCEPT_KEY).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        m.metadata.insert("accept".into(), json!(b64(&bytes)));
        assert!(matches!(
            check(&p, BlockKind::ContractAccept, &m),
            Err(ContractBlockError::Contract(_))
        ));
        m.metadata.insert("accept".into(), json!("not base64!"));
        assert_eq!(
            check(&p, BlockKind::ContractAccept, &m),
            Err(ContractBlockError::NotBase64(ACCEPT_KEY))
        );
    }

    #[test]
    fn a_refuse_record_carries_the_targets_refusal_or_the_owners_own() {
        let p = parties();
        let offer = p.offer();
        let refuse = ContractRefuse::sign(&p.follower, &offer, RefuseCode::UnsupportedSuite);
        let record = |code: &str| {
            block(
                BlockKind::ContractRefuse,
                &did(&p.owner),
                json!({
                    "to": did(&p.follower),
                    "code": code,
                    "offer": b64(&offer.envelope),
                    "refuse": b64(&refuse.envelope),
                }),
            )
        };
        assert_eq!(
            check(&p, BlockKind::ContractRefuse, &record("UNSUPPORTED_SUITE")),
            Ok(())
        );
        assert_eq!(
            check(&p, BlockKind::ContractRefuse, &record("NOT_A_PEER")),
            Err(ContractBlockError::Mismatch(
                "`code` is not the refusal's code"
            ))
        );
        assert!(matches!(
            check(&p, BlockKind::ContractRefuse, &record("NOPE")),
            Err(ContractBlockError::Contract(ContractError::UnknownCode(_)))
        ));

        // The owning server's own refusal: no offer was sent, so there is no
        // answer to carry.
        let own = block(
            BlockKind::ContractRefuse,
            &did(&p.owner),
            json!({"to": did(&p.follower), "code": "NOT_A_PEER"}),
        );
        assert_eq!(check(&p, BlockKind::ContractRefuse, &own), Ok(()));
    }

    #[test]
    fn an_end_record_is_signed_by_one_side_of_the_share() {
        let p = parties();
        let offer_id = p.offer().offer_id;
        let record = |key: &SigningKey| {
            let end = ContractEnd::sign(key, p.channel_id, offer_id);
            block(
                BlockKind::ContractEnd,
                &did(&p.owner),
                json!({"to": did(&p.follower), "end": b64(&end.envelope)}),
            )
        };
        assert_eq!(check(&p, BlockKind::ContractEnd, &record(&p.owner)), Ok(()));
        assert_eq!(
            check(&p, BlockKind::ContractEnd, &record(&p.follower)),
            Ok(())
        );
        assert_eq!(
            check(
                &p,
                BlockKind::ContractEnd,
                &record(&SigningKey::from_bytes(&[9; 32]))
            ),
            Err(ContractBlockError::Mismatch(
                "the end is signed by neither side of the share"
            ))
        );
    }
}
