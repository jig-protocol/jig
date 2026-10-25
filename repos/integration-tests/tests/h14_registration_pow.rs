//! H14: registration proof-of-work and the stranger pool, end to end
//! (JEP-0008, R1 slice 6).
//!
//! Each test stands up the real `jig-nameserver` app on a socket and drives
//! it the way `jig init --request-alias` does: a signed offer from
//! `GET /v1/challenge`, the work solved against it, then `POST /v1/register`.
//!
//! 1. A flood of solved registrations past the pool gets
//!    `503 REGISTRATION_BUSY` with `Retry-After`, the controller doubles the
//!    effort asked after the window it filled, and an allowlisted DID still
//!    registers, at `min_effort`.
//! 2. A closed suffix refuses strangers before any work, and admits the DID
//!    its allowlist names, for that name only.
//! 3. Short names cost more: 4x per letter under five, 1-2 letters and
//!    reserved names are refused before any work, a taken name is refused
//!    before any work, and work that does not verify doubles what its
//!    address is asked next.

use std::time::{Duration, Instant};

use integration_tests::harness::*;
use jig_config::v0_0_2_server::{AllowEntry, PoolPolicy, Registration, SuffixConfig};
use reqwest::StatusCode;

/// Low enough to solve dozens of times in a debug build.
const FLOOR: u64 = 1 << 12;

fn did_of(key: &ed25519_dalek::SigningKey) -> String {
    jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
}

/// `GET /v1/challenge` for registering `alias_local` as `did`.
async fn register_challenge(
    ns: &TestNameserver,
    did: &str,
    alias_local: &str,
) -> (StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/challenge", ns.http_url()))
        .query(&[
            ("action", "register"),
            ("did", did),
            ("name", &format!("{alias_local}@{}", ns.alias_suffix)),
        ])
        .send()
        .await
        .expect("GET /v1/challenge");
    let status = resp.status();
    (status, resp.json().await.expect("challenge body is JSON"))
}

/// The effort a fresh stranger registering `alias_local` is asked for.
async fn effort_for(ns: &TestNameserver, alias_local: &str) -> u64 {
    let key = jig_core::crypto::ed25519::generate_signing_key();
    let (status, body) = register_challenge(ns, &did_of(&key), alias_local).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "challenge for {alias_local}: {body}"
    );
    body["pow"]["effort"]
        .as_u64()
        .expect("pow.effort is a number")
}

fn pow(min_effort: u64, short_name_factor: u64) -> PowPolicy {
    PowPolicy {
        min_effort,
        short_name_factor,
        ..PowPolicy::recommended()
    }
}

#[tokio::test]
async fn flood_past_the_pool_is_busy_and_raises_the_price() {
    const WINDOW: u64 = 4;
    let insider = jig_core::crypto::ed25519::generate_signing_key();
    let mut suffix = SuffixConfig::new("flood.jig");
    suffix.pow = pow(FLOOR, 1);
    suffix.pool = PoolPolicy {
        // Two tokens, none more within the test.
        strangers_per_hour: 1,
        burst: 2,
        controller_window_secs: WINDOW,
        queue_len: 2,
        queue_wait_secs: 1,
        ..PoolPolicy::recommended()
    };
    suffix.registration_allow = vec![AllowEntry {
        did: did_of(&insider),
        aliases: vec!["insider".to_string()],
    }];
    let ns = TestNameserver::start_with_suffix_config(suffix)
        .await
        .expect("start ns");
    // The controller's first window opened when the app was built, before
    // this.
    let booted = Instant::now();

    // Solve every registration first, so they all reach the pool together.
    let mut bodies = Vec::new();
    for i in 0..8 {
        let key = jig_core::crypto::ed25519::generate_signing_key();
        bodies.push(
            ns.prepare_registration(&format!("flood{i}"), &key)
                .await
                .expect("prepare"),
        );
    }
    let attempts =
        futures_util::future::join_all(bodies.iter().map(|body| ns.submit_registration(body)))
            .await;

    let mut admitted = 0;
    let mut busy = 0;
    for attempt in attempts {
        let attempt = attempt.expect("submit");
        if attempt.status.is_success() {
            admitted += 1;
            continue;
        }
        assert_eq!(
            attempt.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{attempt:?}"
        );
        assert_eq!(attempt.body["code"], "REGISTRATION_BUSY", "{attempt:?}");
        // One token an hour: the next is most of an hour away.
        let retry_after = attempt.retry_after.expect("Retry-After header");
        assert!(retry_after > 60, "Retry-After {retry_after}");
        assert_eq!(attempt.body["retry_after"], retry_after);
        busy += 1;
    }
    assert_eq!(
        (admitted, busy),
        (2, 6),
        "the burst admits two; the rest wait or are refused"
    );

    // The queue filled in the first window, so the second asks twice the
    // floor. Read inside the second window: one with nothing queued halves it.
    tokio::time::sleep_until((booted + Duration::from_secs(WINDOW + 1)).into()).await;
    assert_eq!(effort_for(&ns, "latecomer").await, 2 * FLOOR);

    // The allowlist skips the pool and the controller: it pays the floor and
    // registers while strangers cannot.
    let (status, body) = register_challenge(&ns, &did_of(&insider), "insider").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pow"]["effort"], FLOOR);
    ns.register_with_key("insider", &insider)
        .await
        .expect("allowlisted registration with the pool empty");
}

#[tokio::test]
async fn closed_suffix_admits_only_its_allowlist() {
    let insider = jig_core::crypto::ed25519::generate_signing_key();
    let mut suffix = SuffixConfig::new("closed.jig");
    suffix.registration = Registration::Closed;
    suffix.pow = pow(FLOOR, 4);
    suffix.pool = PoolPolicy::recommended();
    // Two letters: the allowlist is exempt from the minimum length.
    suffix.registration_allow = vec![AllowEntry {
        did: did_of(&insider),
        aliases: vec!["dj".to_string()],
    }];
    let ns = TestNameserver::start_with_suffix_config(suffix)
        .await
        .expect("start ns");

    // A stranger is refused before it is offered any work.
    let stranger = jig_core::crypto::ed25519::generate_signing_key();
    let (status, body) = register_challenge(&ns, &did_of(&stranger), "stranger").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "REGISTRATION_CLOSED");
    assert!(body.get("pow_offer").is_none(), "{body}");

    // So is the insider, for any name the allowlist does not give it.
    let (status, body) = register_challenge(&ns, &did_of(&insider), "other").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "REGISTRATION_CLOSED");

    // Its own name costs the floor, with no length multiplier.
    let (status, body) = register_challenge(&ns, &did_of(&insider), "dj").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pow"]["effort"], FLOOR);
    let registered = ns
        .register_with_key("dj", &insider)
        .await
        .expect("allowlisted registration");
    assert_eq!(registered["did"], did_of(&insider), "{registered}");

    // Nobody else can then ask for it.
    let (status, body) = register_challenge(&ns, &did_of(&stranger), "dj").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn short_names_cost_more_and_squatting_is_refused_before_work() {
    let mut suffix = SuffixConfig::new("short.jig");
    suffix.pow = pow(FLOOR, 4);
    suffix.pool = PoolPolicy::recommended();
    let ns = TestNameserver::start_with_suffix_config(suffix)
        .await
        .expect("start ns");

    // 4x for each letter under five.
    assert_eq!(effort_for(&ns, "abcdef").await, FLOOR);
    assert_eq!(effort_for(&ns, "abcde").await, FLOOR);
    assert_eq!(effort_for(&ns, "abcd").await, 4 * FLOOR);
    assert_eq!(effort_for(&ns, "abc").await, 16 * FLOOR);

    // One and two letters, and reserved words, are not for sale at any price.
    let anyone = did_of(&jig_core::crypto::ed25519::generate_signing_key());
    for alias in ["a", "ab"] {
        let (status, body) = register_challenge(&ns, &anyone, alias).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{alias}: {body}");
        assert_eq!(body["code"], "ALIAS_TOO_SHORT", "{alias}: {body}");
        assert!(body.get("pow_offer").is_none(), "{body}");
    }
    let (status, body) = register_challenge(&ns, &anyone, "admin").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "ALIAS_RESERVED");

    // The first to pay 16x holds the name; a second DID is refused before
    // it is offered any work.
    let holder = jig_core::crypto::ed25519::generate_signing_key();
    ns.register_with_key("abc", &holder)
        .await
        .expect("register a three-letter name");
    let (status, body) = register_challenge(&ns, &anyone, "abc").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "ALIAS_TAKEN");
    assert!(body.get("pow_offer").is_none(), "{body}");

    // Work solved for one registration does not pay for another, and the
    // address that sent it is asked twice as much next time.
    let a = jig_core::crypto::ed25519::generate_signing_key();
    let b = jig_core::crypto::ed25519::generate_signing_key();
    let paid = ns.prepare_registration("paidfor", &a).await.expect("a");
    let mut forged = ns.prepare_registration("freeride", &b).await.expect("b");
    forged["pow"] = paid["pow"].clone();
    let attempt = ns.submit_registration(&forged).await.expect("submit");
    assert_eq!(attempt.status, StatusCode::BAD_REQUEST, "{attempt:?}");
    assert_eq!(attempt.body["code"], "POW_INVALID", "{attempt:?}");
    assert_eq!(effort_for(&ns, "abcdef").await, 2 * FLOOR);
}
