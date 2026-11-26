//! `jig channel prune <channel> --via <server-did>`: after a server stops
//! carrying a channel, remove the members who reached it only through that
//! server (JEP-0005 rule 11; F2 Task 7).
//!
//! When a share ends, the follower no longer gets the channel. But its
//! clients' leaves are still in the group, and they still hold the epoch
//! secrets, until a member with the membership right commits their removal.
//! Only clients commit (rule 20), so this is a command a person runs. It is
//! prompted (DJ 2026-11-26): it lists what it would do, and removes no one
//! without `--yes`.
//!
//! Who reached the channel only through the ended server is a judgement from
//! two facts. The owner's server records which server relayed each member's
//! latest write (`last_via`), and a member's reachability record, which the
//! member signed, lists the servers they use. A member is removed when the
//! ended server relayed their latest write, and no record this device can
//! check lists any other server. That is conservative: a member whose record
//! names any other server is kept, even one that does not carry the channel,
//! and can be removed by hand with `jig channel kick`.
//!
//! This module is the judgement. [`crate::cmd::channel::prune`] gathers the
//! facts and commits.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jig_client::open::{Authenticity, OpenedBlock};
use jig_core::BlockKind;
use jig_core::contract::{ContractAccept, ContractEnd};

/// The metadata keys of the owner's contract records (JEP-0005 rules 10, 11).
const TO_KEY: &str = "to";
const ACCEPT_KEY: &str = "accept";
const END_KEY: &str = "end";

/// Where a channel's share with one server stands, by the owner's records
/// in the channel's log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Share {
    /// Accepted, and not ended since.
    Live,
    /// Accepted, then ended.
    Ended,
    /// The log holds no accepted share with that server.
    Never,
}

/// The share of `channel_id` with `to`, from `records` oldest first: the
/// owner's `contract-accept` and `contract-end` blocks, each signed by
/// `sequencer` and naming `to`, with the accept or end inside verifying and
/// naming this channel. An end counts only for the offer last accepted, so an
/// offer withdrawn before it was answered changes nothing. Anything else in
/// `records` is ignored.
pub fn share_with(records: &[OpenedBlock], channel_id: &str, sequencer: &str, to: &str) -> Share {
    let mut accepted: Option<[u8; 32]> = None;
    let mut state = Share::Never;
    for block in records {
        if block.authenticity != Authenticity::Verified
            || block.sender != sequencer
            || block.meta_str(TO_KEY) != Some(to)
        {
            continue;
        }
        let inner = |key| block.meta_str(key).and_then(|b| STANDARD.decode(b).ok());
        match block.manifest.kind {
            Some(BlockKind::ContractAccept) => {
                let Some(accept) = inner(ACCEPT_KEY)
                    .and_then(|e| ContractAccept::from_envelope(&e).ok())
                    .filter(|a| a.server == to && a.channel_id.to_string() == channel_id)
                else {
                    continue;
                };
                accepted = Some(accept.offer_id);
                state = Share::Live;
            }
            Some(BlockKind::ContractEnd) => {
                let Some(end) = inner(END_KEY)
                    .and_then(|e| ContractEnd::from_envelope(&e).ok())
                    .filter(|e| e.channel_id.to_string() == channel_id)
                else {
                    continue;
                };
                // Either side may end a share: the end is signed by the owner
                // or by `to`.
                if (end.server == to || end.server == sequencer) && accepted == Some(end.offer_id) {
                    state = Share::Ended;
                }
            }
            _ => {}
        }
    }
    state
}

/// One member, as the owner's server lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub did: String,
    pub role: String,
    /// The server that relayed the member's latest write, if one did.
    pub last_via: Option<String>,
}

/// What prune does with one member, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Remove(String),
    Keep(String),
}

/// The verdict for each member the ended server `via` relayed for last, in
/// `members`' order. `reach` holds, by DID, the servers each member's
/// reachability record lists, for the records this device could check; a
/// member with none there has no record to go by. `me` is never removed, nor
/// is an owner. Members `via` did not relay for last are left out: they
/// wrote through some other server, or only through the owner's.
pub fn judge(
    members: &[Member],
    via: &str,
    me: &str,
    reach: &HashMap<String, Vec<String>>,
) -> Vec<(String, Verdict)> {
    members
        .iter()
        .filter(|m| m.last_via.as_deref() == Some(via))
        .map(|m| {
            let verdict = if m.did == me {
                Verdict::Keep("you".to_string())
            } else if m.role == "owner" {
                Verdict::Keep("an owner of the channel".to_string())
            } else {
                match reach.get(&m.did) {
                    Some(servers) => match servers.iter().find(|s| s.as_str() != via) {
                        Some(other) => {
                            Verdict::Keep(format!("their reachability record lists {other}"))
                        }
                        None => {
                            Verdict::Remove(format!("their reachability record lists only {via}"))
                        }
                    },
                    None => Verdict::Remove(format!(
                        "their latest write came through {via}, and no record of theirs \
                         lists another server"
                    )),
                }
            };
            (m.did.clone(), verdict)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use jig_core::contract::{ContractOffer, Grant, ManifestRef};

    fn did_of(key: &SigningKey) -> String {
        jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    struct Fixture {
        owner: SigningKey,
        follower: SigningKey,
        channel: cid::Cid,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                owner: SigningKey::from_bytes(&[1; 32]),
                follower: SigningKey::from_bytes(&[2; 32]),
                channel: jig_core::canonical_cid::of(b"channel-create"),
            }
        }

        fn offer(&self) -> ContractOffer {
            self.offer_of(Grant::Write)
        }

        /// An offer of `grant`: one `offer_id` per distinct offer.
        fn offer_of(&self, grant: Grant) -> ContractOffer {
            let manifest = ManifestRef {
                cid: jig_core::canonical_cid::of(b"server-manifest"),
                seq: 1,
            };
            ContractOffer::sign(
                &self.owner,
                &did_of(&self.follower),
                self.channel,
                grant,
                vec![],
                vec![],
                manifest,
                vec![],
            )
        }

        /// A record block as the owner's server writes it, already opened.
        fn record(&self, kind: BlockKind, key: &str, envelope: &[u8]) -> OpenedBlock {
            self.record_by(&did_of(&self.owner), kind, key, envelope)
        }

        fn record_by(
            &self,
            sender: &str,
            kind: BlockKind,
            key: &str,
            envelope: &[u8],
        ) -> OpenedBlock {
            let manifest: jig_core::BlockManifest = serde_json::from_value(serde_json::json!({
                "version": "0.1.0",
                "kind": kind.as_str(),
                "authors": [{"did": sender}],
                "metadata": {
                    TO_KEY: did_of(&self.follower),
                    key: STANDARD.encode(envelope),
                },
            }))
            .unwrap();
            OpenedBlock {
                cid: String::new(),
                manifest,
                sender: sender.to_string(),
                authenticity: Authenticity::Verified,
            }
        }

        fn accept(&self, offer: &ContractOffer) -> OpenedBlock {
            let manifest = ManifestRef {
                cid: jig_core::canonical_cid::of(b"follower-manifest"),
                seq: 1,
            };
            let accept = ContractAccept::sign(&self.follower, offer, manifest, vec![], vec![]);
            self.record(BlockKind::ContractAccept, ACCEPT_KEY, &accept.envelope)
        }

        fn end_by(&self, key: &SigningKey, offer: &ContractOffer) -> OpenedBlock {
            let end = ContractEnd::sign(key, self.channel, offer.offer_id);
            self.record(BlockKind::ContractEnd, END_KEY, &end.envelope)
        }

        fn share(&self, records: &[OpenedBlock]) -> Share {
            share_with(
                records,
                &self.channel.to_string(),
                &did_of(&self.owner),
                &did_of(&self.follower),
            )
        }
    }

    #[test]
    fn a_share_is_ended_by_an_end_of_the_offer_last_accepted() {
        let f = Fixture::new();
        let first = f.offer();
        assert_eq!(f.share(&[]), Share::Never);
        assert_eq!(f.share(&[f.accept(&first)]), Share::Live);
        // Either side's end.
        for ender in [&f.owner, &f.follower] {
            assert_eq!(
                f.share(&[f.accept(&first), f.end_by(ender, &first)]),
                Share::Ended
            );
        }
        // Shared again after the end: live.
        let second = f.offer_of(Grant::Read);
        assert_ne!(first.offer_id, second.offer_id);
        assert_eq!(
            f.share(&[
                f.accept(&first),
                f.end_by(&f.owner, &first),
                f.accept(&second)
            ]),
            Share::Live
        );
        // An end of an earlier offer does not end a later one.
        assert_eq!(
            f.share(&[f.accept(&second), f.end_by(&f.owner, &first)]),
            Share::Live
        );
    }

    #[test]
    fn only_the_owners_verified_records_count() {
        let f = Fixture::new();
        let offer = f.offer();
        let accept = f.accept(&offer);
        let mut end = f.end_by(&f.owner, &offer);
        // Not the sequencer's.
        let forged = {
            let e = ContractEnd::sign(&f.owner, f.channel, offer.offer_id);
            f.record_by(
                &did_of(&f.follower),
                BlockKind::ContractEnd,
                END_KEY,
                &e.envelope,
            )
        };
        assert_eq!(f.share(&[accept.clone(), forged]), Share::Live);
        // Unsigned.
        end.authenticity = Authenticity::Unsigned;
        assert_eq!(f.share(&[accept.clone(), end]), Share::Live);
        // An end signed by a third server.
        let stranger = SigningKey::from_bytes(&[3; 32]);
        assert_eq!(
            f.share(&[accept.clone(), f.end_by(&stranger, &offer)]),
            Share::Live
        );
        // An end for another channel.
        let other = ContractEnd::sign(
            &f.owner,
            jig_core::canonical_cid::of(b"another channel"),
            offer.offer_id,
        );
        assert_eq!(
            f.share(&[
                accept.clone(),
                f.record(BlockKind::ContractEnd, END_KEY, &other.envelope)
            ]),
            Share::Live
        );
        // An end whose envelope is not one.
        assert_eq!(
            f.share(&[accept, f.record(BlockKind::ContractEnd, END_KEY, b"junk")]),
            Share::Live
        );
    }

    fn member(did: &str, role: &str, via: Option<&str>) -> Member {
        Member {
            did: did.to_string(),
            role: role.to_string(),
            last_via: via.map(str::to_string),
        }
    }

    #[test]
    fn a_member_is_removed_only_if_nothing_says_they_reach_it_elsewhere() {
        let (b, a, c) = ("did:jig:zB", "did:jig:zA", "did:jig:zC");
        let members = [
            member("did:jig:zMe", "member", Some(b)),
            member("did:jig:zOwner", "owner", Some(b)),
            member("did:jig:zNoRecord", "member", Some(b)),
            member("did:jig:zOnlyB", "member", Some(b)),
            member("did:jig:zAlsoA", "member", Some(b)),
            member("did:jig:zViaC", "member", Some(c)),
            member("did:jig:zLocal", "member", None),
        ];
        let reach = HashMap::from([
            ("did:jig:zOnlyB".to_string(), vec![b.to_string()]),
            (
                "did:jig:zAlsoA".to_string(),
                vec![b.to_string(), a.to_string()],
            ),
        ]);
        let verdicts = judge(&members, b, "did:jig:zMe", &reach);
        let removed: Vec<&str> = verdicts
            .iter()
            .filter(|(_, v)| matches!(v, Verdict::Remove(_)))
            .map(|(d, _)| d.as_str())
            .collect();
        assert_eq!(removed, ["did:jig:zNoRecord", "did:jig:zOnlyB"]);
        let judged: Vec<&str> = verdicts.iter().map(|(d, _)| d.as_str()).collect();
        assert_eq!(
            judged,
            [
                "did:jig:zMe",
                "did:jig:zOwner",
                "did:jig:zNoRecord",
                "did:jig:zOnlyB",
                "did:jig:zAlsoA"
            ],
            "only those the ended server relayed for last are judged"
        );
        assert_eq!(
            verdicts[4].1,
            Verdict::Keep(format!("their reachability record lists {a}"))
        );
    }
}
