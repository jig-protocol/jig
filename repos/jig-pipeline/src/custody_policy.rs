//! What a custodian keeps of a DID's own release policy, and the requests it
//! holds for the DID's decision (JEP-0005 rules 21b and 21c).
//!
//! - `kp_policies`: each DID's newest release policy for this server, its
//!   own `jig-kp-release-policy-v1`, kept only at a higher `seq`.
//! - `kp_holds`: each request held for the DID, by `request_id`, with its
//!   signed request, its state (`held`, `approved`, `refused`, `expired`)
//!   and the decision that settled it. Kept after it is settled, as the log
//!   of holds and decisions. A request undecided for [`NewHold::ttl`]
//!   expires, so a queue nobody decides drains by itself.
//! - `kp_grants`: what an approval allows: one release to the requester, for
//!   the DID and the channel, until it expires.
//!
//! The custodian's routes (`jig-server`'s `v0_0_2_custody`) verify every
//! signed object before it reaches here; these tables keep what they decided.

use rusqlite::{OptionalExtension, params};

use crate::persist::{Result, SqliteStore};

/// The tables, created by [`SqliteStore`]'s migration.
pub(crate) fn migrate(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        -- `seq` is 8 big-endian bytes, as in `reachability_records`.
        CREATE TABLE IF NOT EXISTS kp_policies (
            did        TEXT PRIMARY KEY,
            seq        BLOB NOT NULL,
            envelope   BLOB NOT NULL,
            stored_at  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS kp_holds (
            request_id BLOB PRIMARY KEY,
            did        TEXT NOT NULL,
            requester  TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            request    BLOB NOT NULL,
            held_at    INTEGER NOT NULL,
            state      TEXT NOT NULL,
            decided_at INTEGER,
            decision   BLOB
        );
        CREATE INDEX IF NOT EXISTS kp_holds_by_did ON kp_holds(did, state, held_at);
        CREATE INDEX IF NOT EXISTS kp_holds_by_requester ON kp_holds(requester, state, held_at);
        CREATE INDEX IF NOT EXISTS kp_holds_by_state ON kp_holds(state, held_at);
        CREATE TABLE IF NOT EXISTS kp_grants (
            did        TEXT NOT NULL,
            requester  TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            request_id BLOB NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (did, requester, channel_id)
        );
        "#,
    )?;
    Ok(())
}

/// A request to hold.
pub struct NewHold<'a> {
    pub request_id: &'a [u8; 32],
    pub did: &'a str,
    pub requester: &'a str,
    pub channel_id: &'a str,
    /// The signed `jig-kp-request-v1`.
    pub request: &'a [u8],
    pub now: i64,
    /// Seconds a request stays held undecided before it expires.
    pub ttl: i64,
    /// Most requests held for one DID at once.
    pub max_per_did: usize,
    /// Most requests held for one requester at once, across every DID.
    pub max_per_requester: usize,
    /// Requests that expired undecided and were held at or before this are
    /// forgotten: no copy of one is fresh enough to be asked again. Decided
    /// requests are the DID's own log and are kept.
    pub forget_expired_before: i64,
}

/// What became of a request to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// Held, under its own id.
    New([u8; 32]),
    /// The same requester already waits on the DID for the same channel:
    /// that request's id. A requester asking again with a fresh request is
    /// not held twice.
    Already([u8; 32]),
    /// As many requests wait on the DID as [`NewHold::max_per_did`]. Not
    /// held; the oldest of them expires at `until`.
    DidFull { until: i64 },
    /// As many of the requester's requests wait, across every DID, as
    /// [`NewHold::max_per_requester`]. Not held; the oldest expires at
    /// `until`.
    RequesterFull { until: i64 },
    /// This very request was held before and has been decided or has
    /// expired. It is not held again; a fresh request is.
    Settled,
}

/// A request held for its DID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldRequest {
    pub request_id: [u8; 32],
    pub requester: String,
    pub channel_id: String,
    pub request: Vec<u8>,
    pub held_at: i64,
}

/// What became of a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decided {
    Approved,
    Refused,
    /// No request with that id is held for that DID.
    NoSuchRequest,
    /// The request was decided already, or expired undecided.
    AlreadyDecided,
}

/// Mark each request held since before `cutoff` expired.
fn expire_on(conn: &rusqlite::Connection, cutoff: i64) -> Result<()> {
    conn.execute(
        "UPDATE kp_holds SET state = 'expired' WHERE state = 'held' AND held_at <= ?1",
        [cutoff],
    )?;
    Ok(())
}

/// A grant taken by a release, to put back if the release did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub request_id: [u8; 32],
    pub expires_at: i64,
}

impl SqliteStore {
    /// Keep `envelope`, `did`'s release policy at `seq`, if `seq` is above
    /// the one kept. Whether it was kept, and the `seq` kept now.
    pub fn put_release_policy(
        &self,
        did: &str,
        seq: u64,
        envelope: &[u8],
        now: i64,
    ) -> Result<(bool, u64)> {
        let conn = self.conn.lock().expect("poisoned");
        let kept: Option<Vec<u8>> = conn
            .query_row("SELECT seq FROM kp_policies WHERE did = ?1", [did], |r| {
                r.get(0)
            })
            .optional()?;
        let kept = kept.map(|b| u64::from_be_bytes(b.try_into().unwrap_or([0; 8])));
        if kept.is_some_and(|k| k >= seq) {
            return Ok((false, kept.unwrap_or(seq)));
        }
        conn.execute(
            "INSERT INTO kp_policies (did, seq, envelope, stored_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(did) DO UPDATE SET seq = ?2, envelope = ?3, stored_at = ?4",
            params![did, seq.to_be_bytes().to_vec(), envelope, now],
        )?;
        Ok((true, seq))
    }

    /// `did`'s release policy as kept, its own envelope.
    pub fn release_policy(&self, did: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().expect("poisoned");
        Ok(conn
            .query_row(
                "SELECT envelope FROM kp_policies WHERE did = ?1",
                [did],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Hold `hold` for its DID's decision, unless the same requester already
    /// waits on the DID for the same channel, or the DID's or the
    /// requester's holds are at their bound. Requests held past their `ttl`
    /// expire first.
    pub fn hold_kp_request(&self, hold: &NewHold<'_>) -> Result<Held> {
        let mut conn = self.conn.lock().expect("poisoned");
        let tx = conn.transaction()?;
        expire_on(&tx, hold.now.saturating_sub(hold.ttl))?;
        tx.execute(
            "DELETE FROM kp_holds WHERE state = 'expired' AND held_at <= ?1",
            [hold.forget_expired_before],
        )?;
        let waiting: Option<Vec<u8>> = tx
            .query_row(
                "SELECT request_id FROM kp_holds
                 WHERE did = ?1 AND requester = ?2 AND channel_id = ?3 AND state = 'held'",
                params![hold.did, hold.requester, hold.channel_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = waiting.and_then(|id| <[u8; 32]>::try_from(id).ok()) {
            tx.commit()?;
            return Ok(Held::Already(id));
        }
        // How many wait on `column = value`, and when the oldest expires.
        let count = |column: &str, value: &str| -> Result<(usize, i64)> {
            let (n, oldest): (i64, Option<i64>) = tx.query_row(
                &format!(
                    "SELECT COUNT(*), MIN(held_at) FROM kp_holds
                     WHERE {column} = ?1 AND state = 'held'"
                ),
                [value],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok((
                usize::try_from(n).unwrap_or(usize::MAX),
                oldest.unwrap_or(hold.now).saturating_add(hold.ttl),
            ))
        };
        let (n, until) = count("did", hold.did)?;
        if n >= hold.max_per_did {
            tx.commit()?;
            return Ok(Held::DidFull { until });
        }
        let (n, until) = count("requester", hold.requester)?;
        if n >= hold.max_per_requester {
            tx.commit()?;
            return Ok(Held::RequesterFull { until });
        }
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO kp_holds
                 (request_id, did, requester, channel_id, request, held_at, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'held')",
            params![
                hold.request_id.to_vec(),
                hold.did,
                hold.requester,
                hold.channel_id,
                hold.request,
                hold.now
            ],
        )?;
        tx.commit()?;
        // Its id is already kept, and not as waiting (that was answered
        // above): it was decided, or expired.
        if inserted == 0 {
            return Ok(Held::Settled);
        }
        Ok(Held::New(*hold.request_id))
    }

    /// The requests held for `did`, oldest first, at most `limit`; those
    /// held since before `cutoff` expire first.
    pub fn held_kp_requests(&self, did: &str, limit: u32, cutoff: i64) -> Result<Vec<HeldRequest>> {
        let conn = self.conn.lock().expect("poisoned");
        expire_on(&conn, cutoff)?;
        let mut stmt = conn.prepare(
            "SELECT request_id, requester, channel_id, request, held_at FROM kp_holds
             WHERE did = ?1 AND state = 'held' ORDER BY held_at, rowid LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![did, limit], |r| {
                let id: Vec<u8> = r.get(0)?;
                Ok(HeldRequest {
                    request_id: id.try_into().unwrap_or([0; 32]),
                    requester: r.get(1)?,
                    channel_id: r.get(2)?,
                    request: r.get(3)?,
                    held_at: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Settle the request `request_id` held for `did` with `decision`, its
    /// signed envelope. An approval grants the requester one release for the
    /// DID and the channel until `grant_until`. Requests held since before
    /// `cutoff` expire first: one expired is no longer decided.
    #[allow(clippy::too_many_arguments)]
    pub fn decide_kp_request(
        &self,
        did: &str,
        request_id: &[u8; 32],
        approve: bool,
        decision: &[u8],
        now: i64,
        grant_until: i64,
        cutoff: i64,
    ) -> Result<Decided> {
        let mut conn = self.conn.lock().expect("poisoned");
        let tx = conn.transaction()?;
        expire_on(&tx, cutoff)?;
        let held: Option<(String, String, String)> = tx
            .query_row(
                "SELECT state, requester, channel_id FROM kp_holds
                 WHERE request_id = ?1 AND did = ?2",
                params![request_id.to_vec(), did],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((state, requester, channel_id)) = held else {
            return Ok(Decided::NoSuchRequest);
        };
        if state != "held" {
            return Ok(Decided::AlreadyDecided);
        }
        tx.execute(
            "UPDATE kp_holds SET state = ?3, decided_at = ?4, decision = ?5
             WHERE request_id = ?1 AND did = ?2",
            params![
                request_id.to_vec(),
                did,
                if approve { "approved" } else { "refused" },
                now,
                decision
            ],
        )?;
        if approve {
            tx.execute(
                "INSERT INTO kp_grants (did, requester, channel_id, request_id, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(did, requester, channel_id)
                 DO UPDATE SET request_id = ?4, expires_at = ?5",
                params![did, requester, channel_id, request_id.to_vec(), grant_until],
            )?;
        }
        tx.commit()?;
        Ok(if approve {
            Decided::Approved
        } else {
            Decided::Refused
        })
    }

    /// Take the grant an approval left for `requester`, for `did` and
    /// `channel_id`, if one is unexpired at `now`: it is gone once taken, so
    /// two requests cannot both use it. [`Self::restore_kp_grant`] puts it
    /// back if no release follows.
    pub fn take_kp_grant(
        &self,
        did: &str,
        requester: &str,
        channel_id: &str,
        now: i64,
    ) -> Result<Option<Grant>> {
        let conn = self.conn.lock().expect("poisoned");
        let grant: Option<(Vec<u8>, i64)> = conn
            .query_row(
                "DELETE FROM kp_grants
                 WHERE did = ?1 AND requester = ?2 AND channel_id = ?3
                 RETURNING request_id, expires_at",
                params![did, requester, channel_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(grant
            .filter(|(_, expires_at)| *expires_at > now)
            .and_then(|(id, expires_at)| {
                Some(Grant {
                    request_id: id.try_into().ok()?,
                    expires_at,
                })
            }))
    }

    /// Put back a grant [`Self::take_kp_grant`] took, unless another has
    /// been made since.
    pub fn restore_kp_grant(
        &self,
        did: &str,
        requester: &str,
        channel_id: &str,
        grant: &Grant,
    ) -> Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT OR IGNORE INTO kp_grants (did, requester, channel_id, request_id, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                did,
                requester,
                channel_id,
                grant.request_id.to_vec(),
                grant.expires_at
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: i64 = 1_000;
    const D: &str = "did:jig:zD";

    fn store() -> SqliteStore {
        SqliteStore::open_in_memory().unwrap()
    }

    fn hold<'a>(id: &'a [u8; 32], requester: &'a str, channel: &'a str) -> NewHold<'a> {
        NewHold {
            request_id: id,
            did: D,
            requester,
            channel_id: channel,
            request: b"signed request",
            now: 100,
            ttl: TTL,
            max_per_did: 8,
            max_per_requester: 8,
            forget_expired_before: 0,
        }
    }

    fn decide(s: &SqliteStore, did: &str, id: [u8; 32], approve: bool, now: i64) -> Decided {
        s.decide_kp_request(did, &id, approve, b"d", now, 200, now - TTL)
            .unwrap()
    }

    #[test]
    fn a_policy_is_kept_only_at_a_higher_seq() {
        let s = store();
        assert_eq!(s.put_release_policy(D, 2, b"two", 1).unwrap(), (true, 2));
        assert_eq!(s.put_release_policy(D, 2, b"again", 1).unwrap(), (false, 2));
        assert_eq!(s.put_release_policy(D, 1, b"one", 1).unwrap(), (false, 2));
        assert_eq!(s.release_policy(D).unwrap().unwrap(), b"two");
        assert_eq!(s.put_release_policy(D, 3, b"three", 1).unwrap(), (true, 3));
        assert_eq!(s.release_policy(D).unwrap().unwrap(), b"three");
        assert!(s.release_policy("did:jig:zE").unwrap().is_none());
    }

    #[test]
    fn a_requester_waits_once_per_did_and_channel_and_holds_are_bounded() {
        let s = store();
        let h = |id, r, c| NewHold {
            max_per_did: 2,
            ..hold(id, r, c)
        };
        assert_eq!(
            s.hold_kp_request(&h(&[1; 32], "did:jig:zR", "c1")).unwrap(),
            Held::New([1; 32])
        );
        // The same requester, a fresh request, the same channel.
        assert_eq!(
            s.hold_kp_request(&h(&[2; 32], "did:jig:zR", "c1")).unwrap(),
            Held::Already([1; 32])
        );
        assert_eq!(
            s.hold_kp_request(&h(&[3; 32], "did:jig:zR", "c2")).unwrap(),
            Held::New([3; 32])
        );
        // The DID's queue is full: not held, with when its oldest expires.
        assert_eq!(
            s.hold_kp_request(&h(&[4; 32], "did:jig:zS", "c1")).unwrap(),
            Held::DidFull { until: 100 + TTL }
        );
        let held = s.held_kp_requests(D, 10, 0).unwrap();
        assert_eq!(held.len(), 2);
        assert_eq!(held[0].request_id, [1; 32]);
        assert!(s.held_kp_requests("did:jig:zE", 10, 0).unwrap().is_empty());
    }

    /// One requester cannot fill every DID's queue on the custodian.
    #[test]
    fn a_requesters_holds_are_bounded_across_dids() {
        let s = store();
        let dids = ["did:jig:zD1", "did:jig:zD2", "did:jig:zD3"];
        for (i, did) in dids.iter().enumerate() {
            let id = [i as u8 + 1; 32];
            let h = NewHold {
                did,
                max_per_requester: 2,
                ..hold(&id, "did:jig:zR", "c1")
            };
            let got = s.hold_kp_request(&h).unwrap();
            if i < 2 {
                assert_eq!(got, Held::New(id));
            } else {
                assert_eq!(got, Held::RequesterFull { until: 100 + TTL });
            }
        }
        // Another requester is not held up by it.
        let h = NewHold {
            did: dids[2],
            max_per_requester: 2,
            ..hold(&[9; 32], "did:jig:zS", "c1")
        };
        assert_eq!(s.hold_kp_request(&h).unwrap(), Held::New([9; 32]));
    }

    /// A request nobody decides expires: the queue drains by itself, and an
    /// expired request is no longer decided.
    #[test]
    fn an_undecided_request_expires() {
        let s = store();
        let full = |id, r, now| NewHold {
            max_per_did: 1,
            now,
            ..hold(id, r, "c1")
        };
        s.hold_kp_request(&full(&[1; 32], "did:jig:zR", 100))
            .unwrap();
        assert_eq!(
            s.hold_kp_request(&full(&[2; 32], "did:jig:zS", 101))
                .unwrap(),
            Held::DidFull { until: 100 + TTL }
        );
        let later = 100 + TTL;
        assert_eq!(
            s.hold_kp_request(&full(&[2; 32], "did:jig:zS", later))
                .unwrap(),
            Held::New([2; 32])
        );
        let held = s.held_kp_requests(D, 10, later - TTL).unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].request_id, [2; 32]);
        assert_eq!(decide(&s, D, [1; 32], true, later), Decided::AlreadyDecided);
        assert!(
            s.take_kp_grant(D, "did:jig:zR", "c1", later)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn an_approval_grants_one_release_until_it_expires() {
        let s = store();
        s.hold_kp_request(&hold(&[1; 32], "did:jig:zR", "c1"))
            .unwrap();
        // Not this DID's request.
        assert_eq!(
            decide(&s, "did:jig:zE", [1; 32], true, 110),
            Decided::NoSuchRequest
        );
        assert_eq!(decide(&s, D, [9; 32], true, 110), Decided::NoSuchRequest);
        assert_eq!(decide(&s, D, [1; 32], true, 110), Decided::Approved);
        assert_eq!(decide(&s, D, [1; 32], false, 111), Decided::AlreadyDecided);
        assert!(s.held_kp_requests(D, 10, 0).unwrap().is_empty());
        // Another requester, another channel: nothing.
        assert!(
            s.take_kp_grant(D, "did:jig:zS", "c1", 150)
                .unwrap()
                .is_none()
        );
        assert!(
            s.take_kp_grant(D, "did:jig:zR", "c2", 150)
                .unwrap()
                .is_none()
        );
        // Taken once.
        let grant = s
            .take_kp_grant(D, "did:jig:zR", "c1", 150)
            .unwrap()
            .unwrap();
        assert!(
            s.take_kp_grant(D, "did:jig:zR", "c1", 150)
                .unwrap()
                .is_none()
        );
        // Put back when no release followed, then expired.
        s.restore_kp_grant(D, "did:jig:zR", "c1", &grant).unwrap();
        assert!(
            s.take_kp_grant(D, "did:jig:zR", "c1", 200)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_refusal_grants_nothing_and_a_new_request_is_held_again() {
        let s = store();
        s.hold_kp_request(&hold(&[1; 32], "did:jig:zR", "c1"))
            .unwrap();
        assert_eq!(decide(&s, D, [1; 32], false, 110), Decided::Refused);
        assert!(
            s.take_kp_grant(D, "did:jig:zR", "c1", 150)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            s.hold_kp_request(&hold(&[2; 32], "did:jig:zR", "c1"))
                .unwrap(),
            Held::New([2; 32])
        );
    }

    #[test]
    fn a_settled_request_is_not_held_again() {
        let s = store();
        s.hold_kp_request(&hold(&[1; 32], "did:jig:zR", "c1"))
            .unwrap();
        assert_eq!(decide(&s, D, [1; 32], false, 110), Decided::Refused);
        // The same signed request, sent again, is not reported as held.
        assert_eq!(
            s.hold_kp_request(&hold(&[1; 32], "did:jig:zR", "c1"))
                .unwrap(),
            Held::Settled
        );
        assert!(s.held_kp_requests(D, 10, 0).unwrap().is_empty());
        // Nor is one that expired.
        s.hold_kp_request(&hold(&[3; 32], "did:jig:zS", "c1"))
            .unwrap();
        let late = NewHold {
            now: 100 + TTL,
            ..hold(&[3; 32], "did:jig:zS", "c1")
        };
        assert_eq!(s.hold_kp_request(&late).unwrap(), Held::Settled);
    }

    #[test]
    fn an_expired_request_is_forgotten_and_a_decided_one_kept() {
        let s = store();
        let rows = |s: &SqliteStore| -> Vec<(Vec<u8>, String)> {
            let conn = s.conn.lock().unwrap();
            let mut stmt = conn
                .prepare("SELECT request_id, state FROM kp_holds ORDER BY held_at, rowid")
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        s.hold_kp_request(&hold(&[1; 32], "did:jig:zR", "c1"))
            .unwrap();
        s.hold_kp_request(&hold(&[2; 32], "did:jig:zS", "c1"))
            .unwrap();
        assert_eq!(decide(&s, D, [1; 32], false, 110), Decided::Refused);
        // [2] expires undecided; a hold past the window forgets it.
        let later = NewHold {
            now: 100 + TTL + 50,
            forget_expired_before: 100,
            ..hold(&[3; 32], "did:jig:zT", "c1")
        };
        assert_eq!(s.hold_kp_request(&later).unwrap(), Held::New([3; 32]));
        assert_eq!(
            rows(&s),
            vec![
                (vec![1; 32], "refused".to_string()),
                (vec![3; 32], "held".to_string())
            ]
        );
    }
}
