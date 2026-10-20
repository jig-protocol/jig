//! A nameserver's proof-of-work, from the client's side (JEP-0008 rules 16
//! and 20).
//!
//! `GET /v1/challenge?action=&did=&name=` answers with the challenge and,
//! when the suffix asks for work, a [`PowOffer`] the nameserver signed: the
//! effort it will check the proof against. [`verify_offer`] accepts an offer
//! only if the nameserver the client is talking to signed it, for exactly
//! this challenge, action, name and DID. An unsigned or wrongly signed effort
//! is never solved. Whether the offer has expired is the nameserver's call:
//! this machine's clock may be off.
//!
//! [`Cap`] is how much work this client will do: what its measured rate
//! solves in `max_solve_secs`, never above [`pow::MAX_EFFORT`], and
//! ([`Cap::within`]) no more than fits in what is left of the challenge's
//! life, timed by the nameserver's own clock. An offer above it is refused
//! before any work, with both numbers in the message.
//!
//! [`solve`] splits the nonce space across the machine's cores on blocking
//! threads and reports progress, so a long solve is visible and the async
//! runtime keeps running.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jig_core::naming::PowOffer;
use jig_core::pow::{self, Action, Alg, Proof};

/// How long a client spends on one solve unless configured otherwise.
pub const DEFAULT_MAX_SOLVE_SECS: u64 = 60;

/// Solves expected to take longer than this get progress reports.
pub const PROGRESS_AFTER: Duration = Duration::from_secs(2);

/// What a solve leaves of the challenge's life for sending the proof.
pub const SEND_MARGIN: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum PowClientError {
    #[error("the nameserver's proof-of-work offer is not unpadded base64url")]
    BadEncoding,
    #[error("the nameserver's proof-of-work offer does not verify: {0}")]
    BadOffer(String),
    #[error(
        "the proof-of-work offer is signed by {signer}, not by this nameserver ({expected}); \
         nothing was solved"
    )]
    OtherSigner { signer: String, expected: String },
    #[error("the proof-of-work offer is for {field} `{got}`, not `{want}`; nothing was solved")]
    Mismatch {
        field: &'static str,
        got: String,
        want: String,
    },
    #[error("the proof-of-work offer names algorithm {0}; this client solves only BLAKE3 (1)")]
    UnknownAlg(u32),
    #[error(
        "the nameserver asks for proof-of-work at effort {asked}, more than this client will \
         do ({cap}: about {secs} s at this machine's measured rate{why})",
        why = if *.by_challenge { ", all the challenge has left" } else { "" }
    )]
    AboveCap {
        asked: u64,
        cap: u64,
        secs: u64,
        by_challenge: bool,
    },
}

/// Verify `offer_b64u`, the `pow_offer` a nameserver returned for
/// `challenge`, and return the effort it promises. The offer must be signed
/// by `ns_did`, the nameserver the client is talking to, and name exactly
/// this challenge, `action`, `name` (the full lowercased `alias@suffix`) and
/// `did` (the subject; for rotate, the old DID). Expiry is not checked here
/// (see [`deadline`]).
pub fn verify_offer(
    offer_b64u: &str,
    ns_did: &str,
    challenge: &str,
    action: Action,
    name: &str,
    did: &str,
) -> Result<PowOffer, PowClientError> {
    let envelope = URL_SAFE_NO_PAD
        .decode(offer_b64u.as_bytes())
        .map_err(|_| PowClientError::BadEncoding)?;
    let offer =
        PowOffer::from_envelope(&envelope).map_err(|e| PowClientError::BadOffer(e.to_string()))?;
    if offer.ns_did != ns_did {
        return Err(PowClientError::OtherSigner {
            signer: offer.ns_did,
            expected: ns_did.to_string(),
        });
    }
    let mismatch = |field, got: &str, want: &str| PowClientError::Mismatch {
        field,
        got: got.to_string(),
        want: want.to_string(),
    };
    if offer.challenge != challenge {
        return Err(mismatch("challenge", &offer.challenge, challenge));
    }
    if offer.action != action {
        return Err(mismatch("action", offer.action.label(), action.label()));
    }
    if offer.name != name {
        return Err(mismatch("name", &offer.name, name));
    }
    if offer.did != did {
        return Err(mismatch("did", &offer.did, did));
    }
    if offer.alg != u32::from(Alg::Blake3.id()) {
        return Err(PowClientError::UnknownAlg(offer.alg));
    }
    if u64::from(offer.salt_id) != pow::EMPTY_SALT_ID {
        return Err(mismatch(
            "salt_id",
            &offer.salt_id.to_string(),
            &pow::EMPTY_SALT_ID.to_string(),
        ));
    }
    Ok(offer)
}

/// When an offer expiring at `expires_at` runs out, on this machine's
/// monotonic clock: `server_now` is the nameserver's clock (its `Date`
/// header) at `received`. Comparing the server's two times keeps this
/// machine's wall clock, which may be off by minutes, out of it. `None`
/// without a server time.
pub fn deadline(expires_at: i64, server_now: Option<i64>, received: Instant) -> Option<Instant> {
    let left = u64::try_from(expires_at.saturating_sub(server_now?)).unwrap_or(0);
    Some(received + Duration::from_secs(left))
}

/// The most work this client will do for one request.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cap {
    /// Digests per second across every core, as measured.
    pub rate: f64,
    pub max_solve_secs: u64,
    /// `rate × max_solve_secs`, at least 1, at most [`pow::MAX_EFFORT`].
    pub effort: u64,
    /// Whether the challenge's remaining life, not `max_solve_secs` as
    /// configured, set this cap.
    pub by_challenge: bool,
}

impl Cap {
    /// Measure this machine's rate and cap at what it solves in
    /// `max_solve_secs`.
    pub fn measure(max_solve_secs: u64) -> Self {
        Self::from_rate(measure_rate(), max_solve_secs)
    }

    pub fn from_rate(rate: f64, max_solve_secs: u64) -> Self {
        let effort = (rate * max_solve_secs as f64).clamp(1.0, pow::MAX_EFFORT as f64) as u64;
        Self {
            rate,
            max_solve_secs,
            effort,
            by_challenge: false,
        }
    }

    /// This cap, lowered to what fits before `deadline` with
    /// [`SEND_MARGIN`] to spare. A solve that outlives its challenge is
    /// wasted: the nameserver refuses the proof.
    pub fn within(self, deadline: Option<Instant>) -> Self {
        let Some(deadline) = deadline else {
            return self;
        };
        let left = deadline
            .saturating_duration_since(Instant::now())
            .saturating_sub(SEND_MARGIN)
            .as_secs();
        if left >= self.max_solve_secs {
            return self;
        }
        Self {
            by_challenge: true,
            ..Self::from_rate(self.rate, left)
        }
    }

    /// Refuse `asked` above the cap.
    pub fn allow(&self, asked: u64) -> Result<(), PowClientError> {
        if asked > self.effort {
            return Err(PowClientError::AboveCap {
                asked,
                cap: self.effort,
                secs: self.max_solve_secs,
                by_challenge: self.by_challenge,
            });
        }
        Ok(())
    }

    /// How long `effort` is expected to take here.
    pub fn estimate(&self, effort: u64) -> Duration {
        Duration::from_secs_f64(effort as f64 / self.rate.max(1.0))
    }
}

/// What to bid on the one retry after a refusal (rule 20): at least the new
/// offer, at least twice the last bid, at most the cap.
pub fn retry_bid(new_offer: u64, previous_bid: u64, cap: u64) -> u64 {
    new_offer.max(previous_bid.saturating_mul(2)).min(cap)
}

/// Digests per second across every core: a short run of a puzzle no nonce
/// solves on all of them at once, timed. Running them together counts what
/// shared cores (SMT) and a lower all-core clock really deliver.
pub fn measure_rate() -> f64 {
    let impossible = NonZeroU64::new(u64::MAX).expect("non-zero");
    let puzzle = Puzzle::new(
        "did:jig:calibration",
        "did:jig:calibration",
        Action::NsRegister,
        [0; 32],
    );
    let done = AtomicU64::new(0);
    let start = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..cores() {
            let (puzzle, done) = (&puzzle, &done);
            s.spawn(move || {
                let p = puzzle.borrow().expect("ns-register is a challenge action");
                let mut nonce = 0u64;
                // About 100 ms, a little more on a slow core.
                while start.elapsed() < Duration::from_millis(100) {
                    let _ = p.try_solve(impossible, nonce, 4096);
                    nonce += 4096;
                }
                done.fetch_add(nonce, Ordering::Relaxed);
            });
        }
    });
    done.into_inner() as f64 / start.elapsed().as_secs_f64()
}

fn cores() -> u64 {
    std::thread::available_parallelism().map_or(1, |n| n.get() as u64)
}

/// A puzzle with owned parts, to move onto worker threads.
#[derive(Debug, Clone)]
pub struct Puzzle {
    pub verifier: String,
    pub subject: String,
    pub action: Action,
    pub binding: [u8; 32],
}

impl Puzzle {
    pub fn new(verifier: &str, subject: &str, action: Action, binding: [u8; 32]) -> Self {
        Self {
            verifier: verifier.to_string(),
            subject: subject.to_string(),
            action,
            binding,
        }
    }

    pub fn borrow(&self) -> Result<pow::Puzzle<'_>, pow::PowError> {
        pow::Puzzle::new(&self.verifier, &self.subject, self.action, &self.binding)
    }
}

/// Solve `puzzle` at `effort` on every core. `progress` is called about once
/// a second with the digests computed so far.
pub async fn solve(
    puzzle: Puzzle,
    effort: NonZeroU64,
    progress: impl Fn(u64) + Send + 'static,
) -> Result<Proof, pow::PowError> {
    puzzle.borrow()?;
    tokio::task::spawn_blocking(move || solve_blocking(&puzzle, effort, progress))
        .await
        .expect("the solver does not panic")
}

fn solve_blocking(
    puzzle: &Puzzle,
    effort: NonZeroU64,
    progress: impl Fn(u64),
) -> Result<Proof, pow::PowError> {
    const CHUNK: u64 = 1 << 14;
    let next = AtomicU64::new(0);
    let found = AtomicBool::new(false);
    let done = AtomicU64::new(0);
    let answer = std::sync::Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..cores() {
            let (next, found, done, answer) = (&next, &found, &done, &answer);
            s.spawn(move || {
                let p = puzzle.borrow().expect("checked before spawning");
                while !found.load(Ordering::Relaxed) {
                    let start = next.fetch_add(CHUNK, Ordering::Relaxed);
                    if let Some(proof) = p.try_solve(effort, start, CHUNK) {
                        found.store(true, Ordering::Relaxed);
                        answer.lock().expect("solver lock").get_or_insert(proof);
                    }
                    done.fetch_add(CHUNK, Ordering::Relaxed);
                }
            });
        }
        let mut last = Instant::now();
        while !found.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(50));
            if last.elapsed() >= Duration::from_secs(1) {
                progress(done.load(Ordering::Relaxed));
                last = Instant::now();
            }
        }
    });
    Ok(answer
        .into_inner()
        .expect("solver lock")
        .expect("a worker found a proof"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const NOW: i64 = 1_800_000_000;

    fn ns() -> SigningKey {
        SigningKey::from_bytes(&[1; 32])
    }

    fn did_of(k: &SigningKey) -> String {
        jig_core::Did::from_ed25519_pubkey(k.verifying_key().as_bytes()).to_did_jig_string()
    }

    fn me() -> String {
        did_of(&SigningKey::from_bytes(&[3; 32]))
    }

    fn you() -> String {
        did_of(&SigningKey::from_bytes(&[4; 32]))
    }

    fn offer(signer: &SigningKey, effort: u32) -> String {
        let signed = PowOffer::sign(
            signer,
            PowOffer {
                challenge: "c0ffee".into(),
                action: Action::NsRegister,
                name: "dj@dj.jig".into(),
                did: me(),
                ns_did: String::new(),
                alg: 1,
                effort,
                salt_id: 0,
                expires_at: NOW + 60,
                envelope: Vec::new(),
            },
        )
        .unwrap();
        URL_SAFE_NO_PAD.encode(&signed.envelope)
    }

    fn check(b64: &str, ns_did: &str) -> Result<PowOffer, PowClientError> {
        verify_offer(
            b64,
            ns_did,
            "c0ffee",
            Action::NsRegister,
            "dj@dj.jig",
            &me(),
        )
    }

    #[test]
    fn an_offer_signed_by_this_nameserver_for_this_request_verifies() {
        let got = check(&offer(&ns(), 1 << 10), &did_of(&ns())).unwrap();
        assert_eq!(got.effort, 1 << 10);
    }

    #[test]
    fn an_offer_signed_by_another_key_is_refused_before_solving() {
        let stranger = SigningKey::from_bytes(&[2; 32]);
        let err = check(&offer(&stranger, 1), &did_of(&ns())).unwrap_err();
        assert!(matches!(err, PowClientError::OtherSigner { .. }), "{err}");
    }

    #[test]
    fn an_offer_for_another_request_is_refused() {
        let b64 = offer(&ns(), 1);
        let ns_did = did_of(&ns());
        let (me, you) = (me(), you());
        let other = |challenge, action, name, did: &str| {
            verify_offer(&b64, &ns_did, challenge, action, name, did).unwrap_err()
        };
        for err in [
            other("beef", Action::NsRegister, "dj@dj.jig", &me),
            other("c0ffee", Action::NsRenew, "dj@dj.jig", &me),
            other("c0ffee", Action::NsRegister, "dk@dj.jig", &me),
            other("c0ffee", Action::NsRegister, "dj@dj.jig", &you),
        ] {
            assert!(matches!(err, PowClientError::Mismatch { .. }), "{err}");
        }
        assert!(matches!(
            check("not base64!", &ns_did),
            Err(PowClientError::BadEncoding)
        ));
    }

    #[test]
    fn the_cap_follows_the_measured_rate_and_refuses_above_it() {
        let cap = Cap::from_rate(1000.0, 10);
        assert_eq!(cap.effort, 10_000);
        cap.allow(10_000).unwrap();
        let err = cap.allow(10_001).unwrap_err().to_string();
        assert!(err.contains("10001") && err.contains("10000"), "{err}");
        assert_eq!(
            Cap::from_rate(f64::MAX, 10).effort,
            pow::MAX_EFFORT,
            "never above rule 19's ceiling"
        );
        assert!(Cap::measure(1).effort >= 1);
    }

    #[test]
    fn the_deadline_comes_from_the_nameservers_clock_not_this_machines() {
        let received = Instant::now();
        // The offer's 60 s are counted from the server's Date, however far
        // this machine's own clock is off.
        assert_eq!(
            deadline(NOW + 60, Some(NOW), received),
            Some(received + Duration::from_secs(60))
        );
        assert_eq!(deadline(NOW, Some(NOW + 5), received), Some(received));
        assert_eq!(deadline(NOW + 60, None, received), None);
    }

    #[test]
    fn the_cap_fits_in_what_is_left_of_the_challenge() {
        let cap = Cap::from_rate(1000.0, 60);
        assert_eq!(cap.within(None), cap, "no server time, no change");
        let far = Instant::now() + Duration::from_secs(3600);
        assert_eq!(cap.within(Some(far)), cap, "the configured cap is lower");
        // 30 s left, less the margin to send: at most about 25 s of work.
        let soon = cap.within(Some(Instant::now() + Duration::from_secs(30)));
        assert!(soon.by_challenge);
        assert!((24..=25).contains(&soon.max_solve_secs), "{soon:?}");
        assert_eq!(soon.effort, soon.max_solve_secs * 1000);
        let err = soon.allow(30_000).unwrap_err().to_string();
        assert!(err.contains("all the challenge has left"), "{err}");
        // Already over: only the least work is left to try.
        assert_eq!(cap.within(Some(Instant::now())).effort, 1);
    }

    #[test]
    fn the_retry_doubles_the_bid_even_when_the_offer_is_unchanged() {
        assert_eq!(retry_bid(100, 100, 1000), 200);
        assert_eq!(retry_bid(500, 100, 1000), 500);
        assert_eq!(retry_bid(100, 800, 1000), 1000, "never above the cap");
    }

    #[tokio::test]
    async fn a_solved_proof_checks_against_its_puzzle() {
        let puzzle = Puzzle::new("did:jig:zNs", "did:jig:zMe", Action::NsRenew, [7; 32]);
        let effort = NonZeroU64::new(1 << 10).unwrap();
        let proof = solve(puzzle.clone(), effort, |_| {}).await.unwrap();
        puzzle.borrow().unwrap().check(&proof, effort).unwrap();
        // The same work does not count for another subject.
        let other = Puzzle::new("did:jig:zNs", "did:jig:zYou", Action::NsRenew, [7; 32]);
        assert!(other.borrow().unwrap().check(&proof, effort).is_err());
    }
}
