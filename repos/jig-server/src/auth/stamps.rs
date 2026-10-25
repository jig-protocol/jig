//! Stamp-mode proof of work: epoch salts and the replay set (JEP-0008 rules
//! 13–14), for the `post` stamps strangers owe while the stranger pool is
//! loaded (rule 29).
//!
//! - **Epoch salts.** 32 random bytes, replaced every `epoch_secs` on this
//!   server's clock. An epoch's number is its `salt_id`, from 1 at boot. A
//!   stamp under the current or the previous epoch is accepted, no other.
//!   After two or more epochs with no call, the previous salt is gone too.
//! - **Replay.** An accepted stamp's digest is kept until its epoch is two
//!   behind, and a stamp whose digest is held is refused. The set is bounded:
//!   when it is full a new stamp is refused, never an old digest dropped, so
//!   a flood can only refuse stamps, not replay them.
//! - **The salts live in memory.** A restart starts a new epoch and refuses
//!   stamps under the old ones, which is safe. A server run as several
//!   instances behind one DID needs shared salt state, and a shared replay
//!   set; this module does not provide them.
//!
//! The check costs one digest, before any signature (rule 10). No clock is
//! read here: every call takes `now`.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use jig_core::pow::{Action, PowError, Proof, Puzzle};
use rand::Rng as _;

/// Why a stamp was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StampError {
    #[error("the stamp names epoch {got}; this server accepts {current} and {previous}")]
    OtherEpoch {
        got: u64,
        current: u64,
        previous: u64,
    },
    #[error(transparent)]
    Work(#[from] PowError),
    #[error("this stamp was already spent")]
    Replayed,
    #[error("this server holds as many recent stamps as it can; try again next epoch")]
    ReplaySetFull,
}

/// The salt a stamp must use now, as the offer states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSalt {
    pub epoch: u64,
    pub salt: [u8; 32],
    /// When this epoch ends; the previous epoch's stamps are accepted for one
    /// more epoch after that.
    pub ends: Instant,
}

pub struct StampVerifier {
    epoch_len: Duration,
    max_held: usize,
    inner: Mutex<Inner>,
}

struct Inner {
    epoch: u64,
    current: [u8; 32],
    previous: Option<[u8; 32]>,
    epoch_start: Instant,
    /// Accepted digests, with the epoch they were made under.
    spent: HashMap<[u8; 32], u64>,
}

impl StampVerifier {
    /// Epochs of `epoch_len`, holding at most `max_held` spent digests.
    pub fn new(epoch_len: Duration, max_held: usize, now: Instant) -> Self {
        Self {
            epoch_len: epoch_len.max(Duration::from_secs(1)),
            max_held: max_held.max(1),
            inner: Mutex::new(Inner {
                epoch: 1,
                current: fresh_salt(),
                previous: None,
                epoch_start: now,
                spent: HashMap::new(),
            }),
        }
    }

    /// Tests only: the first epoch's salt is `salt`, so a check against the
    /// wrong puzzle fails the same way every run.
    #[cfg(test)]
    fn with_first_salt(epoch_len: Duration, max_held: usize, now: Instant, salt: [u8; 32]) -> Self {
        let v = Self::new(epoch_len, max_held, now);
        v.lock().current = salt;
        v
    }

    /// The salt to offer at `now`.
    pub fn current(&self, now: Instant) -> EpochSalt {
        let mut inner = self.lock();
        self.roll(&mut inner, now);
        EpochSalt {
            epoch: inner.epoch,
            salt: inner.current,
            ends: inner.epoch_start + self.epoch_len,
        }
    }

    /// Check `proof` as a stamp by `subject` for `action` over `binding`,
    /// requiring `required`, at `now`; accepted, its digest is spent.
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        verifier: &str,
        subject: &str,
        action: Action,
        binding: &[u8],
        proof: &Proof,
        required: NonZeroU64,
        now: Instant,
    ) -> Result<(), StampError> {
        let mut inner = self.lock();
        self.roll(&mut inner, now);
        let salt = if proof.salt_id == inner.epoch {
            inner.current
        } else if proof.salt_id.checked_add(1) == Some(inner.epoch)
            && let Some(previous) = inner.previous
        {
            previous
        } else {
            return Err(StampError::OtherEpoch {
                got: proof.salt_id,
                current: inner.epoch,
                previous: inner.epoch - 1,
            });
        };
        let puzzle = Puzzle::stamp(verifier, subject, action, binding, &salt, proof.salt_id)?;
        puzzle.check(proof, required)?;
        let digest = puzzle.digest(&proof.nonce);
        if inner.spent.contains_key(&digest) {
            return Err(StampError::Replayed);
        }
        if inner.spent.len() >= self.max_held {
            return Err(StampError::ReplaySetFull);
        }
        inner.spent.insert(digest, proof.salt_id);
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("stamp verifier lock poisoned")
    }

    /// Start every epoch that began by `now`, and forget digests whose epoch
    /// can no longer be presented.
    fn roll(&self, inner: &mut Inner, now: Instant) {
        let elapsed = now.saturating_duration_since(inner.epoch_start);
        let ended = elapsed.as_secs() / self.epoch_len.as_secs().max(1);
        if ended == 0 {
            return;
        }
        inner.previous = (ended == 1).then_some(inner.current);
        inner.current = fresh_salt();
        inner.epoch += ended;
        inner.epoch_start += self.epoch_len * u32::try_from(ended).unwrap_or(u32::MAX);
        let oldest = inner.epoch - 1;
        inner.spent.retain(|_, epoch| *epoch >= oldest);
    }
}

fn fresh_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "did:jig:zServer";
    const ALICE: &str = "did:jig:zAlice";
    const EPOCH: Duration = Duration::from_secs(600);

    fn effort(e: u64) -> NonZeroU64 {
        NonZeroU64::new(e).unwrap()
    }

    fn stamp(salt: &EpochSalt, binding: &[u8]) -> Proof {
        Puzzle::stamp(SERVER, ALICE, Action::Post, binding, &salt.salt, salt.epoch)
            .unwrap()
            .solve(effort(16))
    }

    fn check(
        v: &StampVerifier,
        proof: &Proof,
        binding: &[u8],
        now: Instant,
    ) -> Result<(), StampError> {
        v.check(SERVER, ALICE, Action::Post, binding, proof, effort(16), now)
    }

    #[test]
    fn a_stamp_under_the_current_epoch_is_accepted_once() {
        let t0 = Instant::now();
        let v = StampVerifier::new(EPOCH, 100, t0);
        let salt = v.current(t0);
        assert_eq!(salt.epoch, 1, "epochs start at 1");
        let proof = stamp(&salt, b"cid-1");
        assert_eq!(check(&v, &proof, b"cid-1", t0), Ok(()));
        assert_eq!(check(&v, &proof, b"cid-1", t0), Err(StampError::Replayed));
    }

    #[test]
    fn the_previous_epoch_is_accepted_and_no_older_one() {
        let t0 = Instant::now();
        let v = StampVerifier::new(EPOCH, 100, t0);
        let first = v.current(t0);
        let proof = stamp(&first, b"cid-1");
        let next = t0 + EPOCH;
        assert_eq!(v.current(next).epoch, 2);
        assert_ne!(v.current(next).salt, first.salt, "a new salt each epoch");
        assert_eq!(check(&v, &proof, b"cid-1", next), Ok(()), "previous epoch");
        let later = stamp(&first, b"cid-2");
        assert_eq!(
            check(&v, &later, b"cid-2", t0 + 2 * EPOCH),
            Err(StampError::OtherEpoch {
                got: 1,
                current: 3,
                previous: 2
            })
        );
    }

    /// After a long quiet spell, even the epoch just before the current one
    /// was never offered with its salt still live: nothing old is accepted.
    #[test]
    fn a_long_gap_forgets_the_previous_salt() {
        let t0 = Instant::now();
        let v = StampVerifier::new(EPOCH, 100, t0);
        let first = v.current(t0);
        let proof = stamp(&first, b"cid-1");
        let much_later = t0 + 5 * EPOCH;
        assert_eq!(v.current(much_later).epoch, 6);
        assert!(matches!(
            check(&v, &proof, b"cid-1", much_later),
            Err(StampError::OtherEpoch { .. })
        ));
    }

    /// With a fixed salt the nonce is fixed, so whether a wrong puzzle's
    /// digest happens to meet effort 16 (one chance in 16) is decided once,
    /// not per run; the salt below is one where none of the three does.
    #[test]
    fn a_stamp_binds_its_block_subject_and_action() {
        let t0 = Instant::now();
        let v = StampVerifier::with_first_salt(EPOCH, 100, t0, [7; 32]);
        let proof = stamp(&v.current(t0), b"cid-1");
        assert!(matches!(
            check(&v, &proof, b"cid-2", t0),
            Err(StampError::Work(PowError::Invalid))
        ));
        assert!(matches!(
            v.check(
                SERVER,
                "did:jig:zMallory",
                Action::Post,
                b"cid-1",
                &proof,
                effort(16),
                t0
            ),
            Err(StampError::Work(PowError::Invalid))
        ));
        assert!(matches!(
            v.check(
                SERVER,
                ALICE,
                Action::Dial,
                b"cid-1",
                &proof,
                effort(16),
                t0
            ),
            Err(StampError::Work(PowError::Invalid))
        ));
        // A refused stamp is not spent: the right block still takes it.
        assert_eq!(check(&v, &proof, b"cid-1", t0), Ok(()));
    }

    #[test]
    fn too_little_work_is_refused() {
        let t0 = Instant::now();
        let v = StampVerifier::new(EPOCH, 100, t0);
        let proof = stamp(&v.current(t0), b"cid-1");
        assert!(matches!(
            v.check(
                SERVER,
                ALICE,
                Action::Post,
                b"cid-1",
                &proof,
                effort(1 << 20),
                t0
            ),
            Err(StampError::Work(PowError::Insufficient { .. }))
        ));
    }

    /// A full set refuses new stamps rather than forgetting a spent one,
    /// and empties as epochs pass.
    #[test]
    fn a_full_replay_set_refuses_and_never_forgets_early() {
        let t0 = Instant::now();
        let v = StampVerifier::new(EPOCH, 2, t0);
        let salt = v.current(t0);
        for cid in [b"cid-1", b"cid-2"] {
            assert_eq!(check(&v, &stamp(&salt, cid), cid, t0), Ok(()));
        }
        let third = stamp(&salt, b"cid-3");
        assert_eq!(
            check(&v, &third, b"cid-3", t0),
            Err(StampError::ReplaySetFull)
        );
        // Epoch 1's digests are kept through epoch 2, when its stamps still
        // count, and dropped in epoch 3.
        let next = t0 + EPOCH;
        assert_eq!(
            check(&v, &third, b"cid-3", next),
            Err(StampError::ReplaySetFull)
        );
        let after = t0 + 2 * EPOCH;
        let fresh = stamp(&v.current(after), b"cid-4");
        assert_eq!(check(&v, &fresh, b"cid-4", after), Ok(()));
    }
}
