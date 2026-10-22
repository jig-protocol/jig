//! Proof-of-work for `jig init --request-alias`, `jig keys renew` and `jig
//! keys rotate` (JEP-0008 rules 16 and 20; R1 slice 2).
//!
//! Each fetches a challenge for its action, solves the work the nameserver's
//! signed offer asks for, and sends it. An offer above what this machine
//! solves in `JIG_POW_MAX_SOLVE_SECS` (default
//! [`jig_client::pow::DEFAULT_MAX_SOLVE_SECS`]) is refused before any work.
//! A `428 POW_REQUIRED`, `400 POW_INSUFFICIENT` or `503 REGISTRATION_BUSY`
//! gets one retry on a fresh challenge, bidding at least twice the last bid;
//! a second refusal stops with the nameserver named as under load. Before
//! retrying a busy refusal the client waits out its `Retry-After`, up to
//! [`MAX_BUSY_WAIT_SECS`]; a longer wait is left to the user.
//!
//! The work is a lottery, so an unlucky solve can outlive its challenge. It
//! stops before the challenge expires, and so does a proof the nameserver
//! answers `CHALLENGE_UNKNOWN` for when it was sent with less than
//! [`SEND_MARGIN`] to spare. Either way the one retry fetches a fresh
//! challenge and bids what its offer asks: doubling would only make another
//! expiry likelier.

use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use jig_client::pow::{Cap, PROGRESS_AFTER, PowClientError, Puzzle, SEND_MARGIN, retry_bid};
use jig_core::naming::Name;
use jig_core::pow::{Action, Proof};

use crate::cmd::ns::{Challenge, Nameserver, Refusal};

/// The longest this client waits on a full registration pool before one
/// retry. Past it, the user is told when to try again.
pub(crate) const MAX_BUSY_WAIT_SECS: u64 = 60;

/// What one request proves work for.
pub(crate) struct Work<'a> {
    pub action: Action,
    /// The DID the work is bound to: the requester, or for rotate the old DID.
    pub subject: &'a str,
    pub name: &'a Name,
    /// The puzzle's binding for a challenge.
    pub binding: &'a dyn Fn(&str) -> Result<[u8; 32]>,
}

/// Fetch a challenge for `work`, solve what its offer asks, and `send` the
/// challenge with the proof. `send`'s `Err` is the nameserver's refusal; on
/// a proof-of-work refusal, or a challenge that expired on the way, the whole
/// round runs once more.
pub(crate) async fn with_pow<T>(
    ns: &Nameserver,
    work: Work<'_>,
    send: impl AsyncFn(String, Option<Proof>) -> Result<T>,
) -> Result<T> {
    let mut cap: Option<Cap> = None;
    let mut cap = || *cap.get_or_insert_with(|| Cap::measure(max_solve_secs()));
    let mut bid = 0;
    // Why the first round failed: the challenge expired, or the nameserver
    // asked for more work.
    let mut expired = false;
    for attempt in 0..2 {
        let Challenge {
            challenge,
            offer,
            deadline,
        } = ns
            .challenge_for(work.action, work.subject, work.name)
            .await?;
        let asked = offer.as_ref().map_or(0, |o| u64::from(o.effort));
        let proof = if asked == 0 && attempt == 0 {
            None
        } else {
            let cap = cap().within(deadline);
            cap.allow(asked).context(if cap.by_challenge {
                "the challenge would expire before this machine finishes; try again later"
            } else {
                "set JIG_POW_MAX_SOLVE_SECS to allow this machine more time, if you mean to"
            })?;
            bid = next_bid(attempt, expired, asked, bid, cap.effort);
            if bid == 0 {
                // A retry with no offer to bid on: there is nothing to solve.
                None
            } else {
                let puzzle = Puzzle::new(
                    ns.ns_did(),
                    work.subject,
                    work.action,
                    (work.binding)(&challenge)?,
                );
                match solve(puzzle, bid, deadline, &cap).await {
                    Ok(proof) => Some(proof),
                    Err(PowClientError::Expired) if attempt == 0 => {
                        eprintln!(
                            "note: the challenge expired before this machine finished; trying \
                             once more on a fresh one"
                        );
                        expired = true;
                        continue;
                    }
                    Err(PowClientError::Expired) => anyhow::bail!(OUTLIVED),
                    Err(e) => return Err(e.into()),
                }
            }
        };
        let sent_at = Instant::now();
        match send(challenge, proof).await {
            Err(e) if busy(&e).is_some() => {
                let secs = busy(&e).expect("checked");
                if attempt > 0 || secs > MAX_BUSY_WAIT_SECS {
                    return Err(e.context(format!(
                        "the nameserver is taking no more new names for now; try again in \
                         about {secs}s"
                    )));
                }
                eprintln!(
                    "the nameserver is taking no more new names for now; waiting {secs}s, then \
                     trying once more"
                );
                tokio::time::sleep(Duration::from_secs(secs)).await;
                expired = false;
            }
            Err(e) if expired_in_flight(&e, sent_at, deadline) => {
                if attempt == 0 {
                    eprintln!(
                        "note: the challenge expired as the proof was sent; trying once more on \
                         a fresh one"
                    );
                    expired = true;
                } else {
                    return Err(e.context(OUTLIVED));
                }
            }
            Err(e) if pow_refusal(&e) && attempt == 0 => {
                eprintln!("note: the nameserver asked for more proof-of-work; retrying once");
                expired = false;
            }
            Err(e) if pow_refusal(&e) => {
                return Err(e.context(
                    "the nameserver refused this proof-of-work twice; it is likely under load. \
                     Try again later",
                ));
            }
            other => return other,
        }
    }
    unreachable!("the second attempt always returns")
}

/// The seconds to wait when `e` is the registration pool's `503
/// REGISTRATION_BUSY`, from its `Retry-After` (a few if it sent none).
fn busy(e: &anyhow::Error) -> Option<u64> {
    let r = e.downcast_ref::<Refusal>()?;
    (r.code().as_deref() == Some("REGISTRATION_BUSY")).then(|| r.retry_after.unwrap_or(5))
}

/// What to bid on `attempt`: the offer, except on the retry after a refusal
/// (not an expiry), which bids [`retry_bid`].
fn next_bid(attempt: usize, expired: bool, asked: u64, previous: u64, cap: u64) -> u64 {
    if attempt == 0 || expired {
        asked
    } else {
        retry_bid(asked, previous, cap)
    }
}

const OUTLIVED: &str =
    "this machine couldn't finish the proof-of-work within the challenge's life; try again later";

/// A `CHALLENGE_UNKNOWN` for a proof sent with less than [`SEND_MARGIN`] of
/// its challenge left: the challenge most likely expired on the way, which a
/// fresh one gets past. Sent earlier, it is something else (a challenge
/// claimed twice, a restarted nameserver) and is not retried.
fn expired_in_flight(e: &anyhow::Error, sent_at: Instant, deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| sent_at + SEND_MARGIN >= d)
        && e.downcast_ref::<Refusal>()
            .is_some_and(|r| r.code().as_deref() == Some("CHALLENGE_UNKNOWN"))
}

/// A refusal that one more round, at more work, may get past.
fn pow_refusal(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Refusal>().is_some_and(|r| {
        let code = r.code();
        r.status == reqwest::StatusCode::PRECONDITION_REQUIRED
            || code.as_deref() == Some("POW_REQUIRED")
            || code.as_deref() == Some("POW_INSUFFICIENT")
    })
}

fn max_solve_secs() -> u64 {
    std::env::var("JIG_POW_MAX_SOLVE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&s| s > 0)
        .unwrap_or(jig_client::pow::DEFAULT_MAX_SOLVE_SECS)
}

/// Solve at `bid`, saying how long it should take and how it is going when
/// that is more than a moment, and stopping before `deadline`.
async fn solve(
    puzzle: Puzzle,
    bid: u64,
    deadline: Option<Instant>,
    cap: &Cap,
) -> Result<Proof, PowClientError> {
    let effort = NonZeroU64::new(bid).expect("a bid of 0 is never solved");
    let estimate = cap.estimate(bid);
    let report = estimate > PROGRESS_AFTER;
    if report {
        eprintln!(
            "solving the nameserver's proof-of-work (effort {bid}): about {}s on this machine",
            estimate.as_secs().max(1)
        );
    }
    jig_client::pow::solve(puzzle, effort, deadline, move |done| {
        if report {
            eprintln!(
                "  … {}% of the expected work",
                (done.saturating_mul(100) / bid).min(999)
            );
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey;
    use jig_client::naming::Delegations;
    use jig_core::naming::{self, Attestation, PowOffer, Root, SuffixDelegation};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const DAY: i64 = 86_400;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn did_of(k: &SigningKey) -> String {
        jig_core::Did::from_ed25519_pubkey(k.verifying_key().as_bytes()).to_did_jig_string()
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn refusal(status: u16, code: &str) -> anyhow::Error {
        Refusal {
            url: "https://ns.example/v1/register".into(),
            status: reqwest::StatusCode::from_u16(status).unwrap(),
            body: serde_json::json!({ "code": code, "message": "m" }).to_string(),
            retry_after: None,
        }
        .into()
    }

    #[test]
    fn a_busy_pool_says_how_long_to_wait() {
        let mut busy_503: anyhow::Error = Refusal {
            url: "u".into(),
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            body: r#"{"code":"REGISTRATION_BUSY","message":"m","retry_after":7}"#.into(),
            retry_after: Some(7),
        }
        .into();
        assert_eq!(busy(&busy_503), Some(7));
        busy_503 = Refusal {
            url: "u".into(),
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            body: r#"{"code":"REGISTRATION_BUSY","message":"m"}"#.into(),
            retry_after: None,
        }
        .into();
        assert_eq!(busy(&busy_503), Some(5), "a few seconds when none is given");
        assert_eq!(busy(&refusal(428, "POW_REQUIRED")), None);
    }

    #[test]
    fn only_proof_of_work_refusals_are_retried() {
        assert!(pow_refusal(&refusal(428, "POW_REQUIRED")));
        assert!(pow_refusal(&refusal(400, "POW_INSUFFICIENT")));
        assert!(
            !pow_refusal(&refusal(400, "POW_INVALID")),
            "a bug, not load"
        );
        assert!(!pow_refusal(&refusal(409, "ALIAS_TAKEN")));
        assert!(!pow_refusal(&anyhow::anyhow!("connection refused")));
    }

    /// No delegations of our own, and the stub's `http://` allowed: it
    /// serves plaintext on loopback.
    fn plaintext() -> Delegations {
        Delegations {
            dangerously_allow_plaintext_nameservers: true,
            ..Delegations::default()
        }
    }

    /// Every request the stub saw: method, path and body.
    type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

    /// The stub's clock: how far it is ahead of this machine's (`skew`, s),
    /// and how long its offers live (`ttl`, s). It sends its time as `Date`.
    #[derive(Clone, Copy)]
    struct Clock {
        skew: i64,
        ttl: i64,
    }

    const TRUE_CLOCK: Clock = Clock { skew: 0, ttl: 60 };

    /// A nameserver for `dj.jig` signing as `ns`. Each challenge is fresh and
    /// carries an offer at `effort` signed by `offer_signer`, for the action,
    /// DID and name the query names. `post` answers each POST from its path
    /// and body.
    async fn stub(
        ns: SigningKey,
        offer_signer: SigningKey,
        effort: u32,
        clock: Clock,
        post: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
    ) -> (String, Seen) {
        stub_with(ns, offer_signer, vec![(effort, clock.ttl)], clock, post).await
    }

    /// [`stub`], whose `n`th challenge (the last one from then on) offers
    /// `offers[n]`: an effort, and how long the offer lives (s).
    async fn stub_with(
        ns: SigningKey,
        offer_signer: SigningKey,
        efforts: Vec<(u32, i64)>,
        clock: Clock,
        post: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
    ) -> (String, Seen) {
        let efforts = Arc::new(efforts);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen: Seen = Arc::default();
        let log = seen.clone();
        let post = Arc::new(post);
        let deleg = serde_json::json!({
            "envelopes": SuffixDelegation::sign(&[&ns], "dj.jig", Root::Dns, "dj.jig",
                chrono::Utc::now().timestamp() + DAY)
                .envelopes.iter().map(|e| b64(e)).collect::<Vec<_>>(),
        })
        .to_string();
        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let (log, post, deleg, signer, counter, efforts) = (
                    log.clone(),
                    post.clone(),
                    deleg.clone(),
                    offer_signer.clone(),
                    counter.clone(),
                    efforts.clone(),
                );
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 8192];
                    let (head, body) = loop {
                        let n = sock.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf).to_string();
                        if let Some((head, body)) = text.split_once("\r\n\r\n") {
                            let len = head
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().ok())?
                                })
                                .unwrap_or(0);
                            if body.len() >= len || n == 0 {
                                break (head.to_string(), body.to_string());
                            }
                        }
                    };
                    let mut words = head.split_whitespace();
                    let (method, path) = (words.next().unwrap(), words.next().unwrap());
                    log.lock()
                        .unwrap()
                        .push((method.into(), path.into(), body.clone()));
                    let (status, out) = match (method, path) {
                        ("GET", "/.well-known/jig-ns-delegation") => (200, deleg),
                        ("GET", p) if p.starts_with("/v1/challenge?") => {
                            let query: std::collections::HashMap<String, String> = p
                                .split_once('?')
                                .unwrap()
                                .1
                                .split('&')
                                .filter_map(|kv| kv.split_once('='))
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .collect();
                            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let challenge = format!("c{n}");
                            let (effort, ttl) = efforts[(n as usize).min(efforts.len() - 1)];
                            let offer = PowOffer::sign(
                                &signer,
                                PowOffer {
                                    challenge: challenge.clone(),
                                    action: match query["action"].as_str() {
                                        "register" => Action::NsRegister,
                                        "renew" => Action::NsRenew,
                                        "rotate" => Action::NsRotate,
                                        other => panic!("action {other}"),
                                    },
                                    name: query["name"].clone(),
                                    did: query["did"].clone(),
                                    ns_did: String::new(),
                                    alg: 1,
                                    effort,
                                    salt_id: 0,
                                    expires_at: chrono::Utc::now().timestamp() + clock.skew + ttl,
                                    envelope: Vec::new(),
                                },
                            )
                            .unwrap();
                            let out = serde_json::json!({
                                "challenge": challenge,
                                "pow_offer": b64(&offer.envelope),
                            });
                            (200, out.to_string())
                        }
                        ("POST", p) => post(p, &body),
                        _ => (404, "{}".into()),
                    };
                    let date = (chrono::Utc::now() + chrono::Duration::seconds(clock.skew))
                        .format("%a, %d %b %Y %H:%M:%S GMT");
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                         date: {date}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}",
                        out.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        (base, seen)
    }

    /// The stub's POST: check the request's `pow` against the puzzle the
    /// nameserver `ns` would build, then attest `alias` to the DID asked.
    fn checking(ns: SigningKey, alias: &'static str) -> impl Fn(&str, &str) -> (u16, String) {
        move |path, body| {
            let req: serde_json::Value = serde_json::from_str(body).unwrap();
            let proof: Proof = serde_json::from_value(req["pow"].clone()).expect("a pow");
            let ns_did = did_of(&ns);
            let challenge = req["challenge"].as_str().unwrap();
            let (action, subject, binding) = match path {
                "/v1/register" => (
                    Action::NsRegister,
                    req["did"].as_str().unwrap().to_string(),
                    naming::proof_hash(naming::Action::Register, &ns_did, alias, challenge),
                ),
                "/v1/renew" => (
                    Action::NsRenew,
                    req["did"].as_str().unwrap().to_string(),
                    naming::proof_hash(naming::Action::Renew, &ns_did, alias, challenge),
                ),
                "/v1/rotate" => (
                    Action::NsRotate,
                    req["old_did"].as_str().unwrap().to_string(),
                    naming::rotate_pow_binding(
                        &ns_did,
                        alias,
                        req["old_did"].as_str().unwrap(),
                        req["new_did"].as_str().unwrap(),
                        challenge,
                    )
                    .unwrap(),
                ),
                other => panic!("unexpected POST {other}"),
            };
            jig_core::pow::Puzzle::new(&ns_did, &subject, action, &binding)
                .unwrap()
                .check(&proof, proof.effort)
                .expect("the proof verifies for its binding");
            let did = req["did"]
                .as_str()
                .or(req["new_did"].as_str())
                .unwrap()
                .to_string();
            let now = chrono::Utc::now().timestamp();
            let att = Attestation::sign(&ns, &did, alias, now - 1, now + DAY);
            (
                200,
                serde_json::json!({ "attestation": b64(&att.envelope) }).to_string(),
            )
        }
    }

    fn posts(seen: &Seen) -> Vec<serde_json::Value> {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|(m, _, _)| m == "POST")
            .map(|(_, _, b)| serde_json::from_str(b).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn register_renew_and_rotate_send_work_that_verifies_for_their_binding() {
        let ns = key(1);
        let (base, seen) = stub(
            ns.clone(),
            ns.clone(),
            1 << 8,
            TRUE_CLOCK,
            checking(ns, "dj@dj.jig"),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let (me, next) = (
            jig_client::Identity::generate_for_tests(dir.path()),
            jig_client::Identity::generate_for_tests(dir.path()),
        );

        crate::cmd::init::register_with_nameserver(&me, "DJ", &base, &plaintext())
            .await
            .expect("registers with work");
        crate::cmd::keys::renew_with_nameserver(&me, "dj@dj.jig", &base, &plaintext())
            .await
            .expect("renews with work");
        crate::cmd::keys::rotate_with_nameserver(&me, &next, "dj@dj.jig", &base, &plaintext())
            .await
            .expect("accepted")
            .expect("verifies");
        let sent = posts(&seen);
        assert_eq!(sent.len(), 3);
        for body in &sent {
            assert_eq!(body["pow"]["effort"], 1 << 8, "{body}");
        }
        assert!(
            seen.lock().unwrap().iter().any(|(_, p, _)| p
                .starts_with("/v1/challenge?action=rotate&did=did:jig:")
                && p.contains(&me.did_string())),
            "a rotation's challenge names the old DID"
        );
    }

    #[tokio::test]
    async fn an_offer_signed_by_another_key_is_refused_before_any_work() {
        let ns = key(1);
        let (base, seen) = stub(
            ns.clone(),
            key(9),
            1 << 8,
            TRUE_CLOCK,
            checking(ns, "dj@dj.jig"),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());
        let err = crate::cmd::init::register_with_nameserver(&me, "dj", &base, &plaintext())
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("not by this nameserver"),
            "{err:#}"
        );
        assert!(posts(&seen).is_empty(), "nothing was sent");
    }

    #[tokio::test]
    async fn an_offer_above_the_cap_is_refused_with_the_cap_in_the_message() {
        let ns = key(1);
        // Above rule 19's ceiling, so above any cap.
        let asked = u32::try_from(jig_core::pow::MAX_EFFORT + 1).unwrap();
        let (base, seen) = stub(
            ns.clone(),
            ns.clone(),
            asked,
            TRUE_CLOCK,
            checking(ns, "dj@dj.jig"),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());
        let err = crate::cmd::init::register_with_nameserver(&me, "dj", &base, &plaintext())
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&asked.to_string()) && msg.contains("more than this client will do"),
            "{msg}"
        );
        assert!(posts(&seen).is_empty(), "nothing was solved or sent");
    }

    #[tokio::test]
    async fn a_refusal_gets_one_retry_at_twice_the_bid_then_a_clear_error() {
        let ns = key(1);
        let required = |_: &str, _: &str| {
            (
                428,
                r#"{"code":"POW_REQUIRED","message":"more"}"#.to_string(),
            )
        };
        let (base, seen) = stub(ns.clone(), ns, 1 << 6, TRUE_CLOCK, required).await;
        let dir = tempfile::tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());
        let err = crate::cmd::init::register_with_nameserver(&me, "dj", &base, &plaintext())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("under load"), "{err:#}");
        let bids: Vec<_> = posts(&seen)
            .iter()
            .map(|b| b["pow"]["effort"].as_u64().unwrap())
            .collect();
        assert_eq!(bids, [1 << 6, 1 << 7], "the same offer, bid twice as high");
    }

    #[tokio::test]
    async fn an_offer_is_timed_by_the_nameservers_clock_not_this_machines() {
        // The nameserver's clock is an hour behind: by this machine's clock
        // every offer has long expired, by the nameserver's it has 60 s.
        let ns = key(1);
        let behind = Clock {
            skew: -3600,
            ttl: 60,
        };
        let (base, seen) = stub(
            ns.clone(),
            ns.clone(),
            1 << 8,
            behind,
            checking(ns, "dj@dj.jig"),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());
        crate::cmd::init::register_with_nameserver(&me, "dj", &base, &plaintext())
            .await
            .expect("registers: the offer is live where it is checked");
        assert_eq!(posts(&seen).len(), 1);
    }

    #[tokio::test]
    async fn work_that_would_outlive_its_challenge_is_refused_before_solving() {
        // Two seconds left, less than the margin to send: no solve can land.
        let ns = key(1);
        let short = Clock { skew: 0, ttl: 2 };
        let (base, seen) = stub(
            ns.clone(),
            ns.clone(),
            1 << 8,
            short,
            checking(ns, "dj@dj.jig"),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());
        let err = crate::cmd::init::register_with_nameserver(&me, "dj", &base, &plaintext())
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("would expire before this machine finishes")
                && msg.contains("all the challenge has left"),
            "{msg}"
        );
        assert!(posts(&seen).is_empty(), "nothing was solved or sent");
    }

    #[test]
    fn only_a_challenge_unknown_near_the_deadline_counts_as_expired() {
        let unknown = refusal(401, "CHALLENGE_UNKNOWN");
        let now = Instant::now();
        let close = Some(now + SEND_MARGIN - std::time::Duration::from_secs(1));
        let far = Some(now + SEND_MARGIN * 4);
        assert!(expired_in_flight(&unknown, now, close));
        assert!(
            !expired_in_flight(&unknown, now, far),
            "a claimed challenge, not expiry"
        );
        assert!(!expired_in_flight(&unknown, now, None));
        assert!(!expired_in_flight(
            &refusal(428, "POW_REQUIRED"),
            now,
            close
        ));
    }

    #[test]
    fn after_an_expiry_the_retry_bids_the_offer_not_double() {
        assert_eq!(
            next_bid(0, false, 100, 0, 1000),
            100,
            "the first bid is the offer"
        );
        assert_eq!(
            next_bid(1, false, 100, 100, 1000),
            200,
            "after a refusal, double"
        );
        assert_eq!(
            next_bid(1, true, 100, 100, 1000),
            100,
            "after an expiry, the offer"
        );
    }

    #[tokio::test]
    async fn a_challenge_that_expired_in_flight_is_retried_once_on_a_fresh_one() {
        // The first offer lives 5 s: all of it is the margin to send, so the
        // nameserver's CHALLENGE_UNKNOWN for its proof is an expiry. The
        // retry asks a fresh challenge and bids what its offer asks.
        let ns = key(1);
        let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let check = checking(ns.clone(), "dj@dj.jig");
        let post = move |path: &str, body: &str| {
            if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                (
                    401,
                    r#"{"code":"CHALLENGE_UNKNOWN","message":"expired"}"#.to_string(),
                )
            } else {
                check(path, body)
            }
        };
        let (base, seen) =
            stub_with(ns.clone(), ns, vec![(1, 5), (1 << 6, 60)], TRUE_CLOCK, post).await;
        let dir = tempfile::tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());
        crate::cmd::init::register_with_nameserver(&me, "dj", &base, &plaintext())
            .await
            .expect("registers on the second challenge");
        let bids: Vec<_> = posts(&seen)
            .iter()
            .map(|b| b["pow"]["effort"].as_u64().unwrap())
            .collect();
        assert_eq!(bids, [1, 1 << 6]);
    }

    #[tokio::test]
    async fn a_second_expiry_says_this_machine_could_not_finish_in_time() {
        let ns = key(1);
        let unknown = |_: &str, _: &str| {
            (
                401,
                r#"{"code":"CHALLENGE_UNKNOWN","message":"expired"}"#.to_string(),
            )
        };
        let (base, seen) = stub_with(ns.clone(), ns, vec![(1, 5)], TRUE_CLOCK, unknown).await;
        let dir = tempfile::tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());
        let err = crate::cmd::init::register_with_nameserver(&me, "dj", &base, &plaintext())
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}")
                .contains("couldn't finish the proof-of-work within the challenge's life"),
            "{err:#}"
        );
        assert_eq!(posts(&seen).len(), 2, "one retry, no more");
    }
}
