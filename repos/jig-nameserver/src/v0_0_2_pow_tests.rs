//! Route-level tests for JEP-0008 proof-of-work on register, renew and rotate
//! (R1 slice 1): the signed offer, the order of checks, and what a refusal
//! leaves usable.

use std::num::NonZeroU64;
use std::sync::Arc;

use axum::{Router, body::Body, http::Request, http::StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use jig_config::v0_0_2_server::{AllowEntry, PowPolicy, Registration, SuffixConfig};
use jig_core::naming::{self, Action, PowOffer};
use jig_core::pow::{Action as PowAction, Proof, Puzzle};
use tower::ServiceExt;

use crate::v0_0_2::{AppState, PendingChallenge};
use crate::v0_0_2_register::build_register_router;
use crate::v0_0_2_register::test_support::{fresh_did_and_key, naming_did, proof};
use crate::v0_0_2_rotate_renew::build_rotate_renew_router;

const A: &str = "a.example.org";
const B: &str = "b.example.org";

/// Where a test asserts work is refused, its effort is at least this: work
/// for the wrong binding meets effort E by chance once in E tries.
const SURE: u64 = 1 << 16;

/// Small efforts, so tests solve in milliseconds.
fn pow_policy(min_effort: u64) -> PowPolicy {
    PowPolicy {
        min_effort,
        max_effort: 1 << 20,
        renew_effort: SURE,
        ..PowPolicy::recommended()
    }
}

fn suffix(name: &str, min_effort: u64) -> SuffixConfig {
    let mut cfg = SuffixConfig::new(name);
    cfg.pow = pow_policy(min_effort);
    cfg
}

fn state_with(suffixes: Vec<SuffixConfig>) -> Arc<AppState> {
    Arc::new(AppState::for_test_with_suffixes(suffixes).unwrap())
}

fn router(state: &Arc<AppState>) -> Router {
    build_register_router(state.clone()).merge(build_rotate_renew_router(state.clone()))
}

async fn send(router: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

async fn get(router: &Router, path: &str) -> (StatusCode, serde_json::Value) {
    send(router, Request::get(path).body(Body::empty()).unwrap()).await
}

async fn post(
    router: &Router,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::post(path)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    send(router, req).await
}

/// `GET /v1/challenge?action=&did=&name=`.
async fn offer(
    router: &Router,
    action: &str,
    did: &str,
    name: &str,
) -> (StatusCode, serde_json::Value) {
    get(
        router,
        &format!("/v1/challenge?action={action}&did={did}&name={name}"),
    )
    .await
}

/// The challenge and the effort its offer promised, checking the offer is the
/// nameserver's signature over exactly what the reply says.
async fn challenge_for(
    router: &Router,
    state: &AppState,
    action: &str,
    did: &str,
    name: &str,
) -> (String, u64) {
    let (status, body) = offer(router, action, did, name).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let offer = PowOffer::from_envelope(
        &URL_SAFE_NO_PAD
            .decode(body["pow_offer"].as_str().expect("a signed offer"))
            .unwrap(),
    )
    .expect("the offer verifies");
    assert_eq!(offer.ns_did, state.ns_did_string());
    assert_eq!(offer.challenge, body["challenge"].as_str().unwrap());
    assert_eq!(
        u64::from(offer.effort),
        body["pow"]["effort"].as_u64().unwrap()
    );
    assert_eq!((offer.did.as_str(), offer.name.as_str()), (did, name));
    (offer.challenge, u64::from(offer.effort))
}

fn solve(state: &AppState, action: PowAction, subject: &str, binding: &[u8], effort: u64) -> Proof {
    let ns_did = state.ns_did_string();
    Puzzle::new(&ns_did, subject, action, binding)
        .unwrap()
        .solve(NonZeroU64::new(effort).unwrap())
}

fn register_binding(state: &AppState, alias: &str, challenge: &str) -> [u8; 32] {
    naming::proof_hash(Action::Register, &state.ns_did_string(), alias, challenge)
}

fn register_body(
    state: &AppState,
    key: &SigningKey,
    local: &str,
    suffix: &str,
    challenge: &str,
    pow: Option<&Proof>,
) -> serde_json::Value {
    let alias = format!("{local}@{suffix}");
    let mut body = serde_json::json!({
        "did": naming_did(key),
        "requested_alias": local,
        "suffix": suffix,
        "proof_of_control": proof(key, state, Action::Register, &alias, challenge),
        "challenge": challenge,
    });
    if let Some(pow) = pow {
        body["pow"] = serde_json::to_value(pow).unwrap();
    }
    body
}

/// Register `local@suffix` for `key`, solving the offer.
async fn register(
    router: &Router,
    state: &AppState,
    key: &SigningKey,
    local: &str,
    suffix: &str,
) -> (StatusCode, serde_json::Value) {
    let (did, name) = (naming_did(key), format!("{local}@{suffix}"));
    let (ch, effort) = challenge_for(router, state, "register", &did, &name).await;
    let pow = solve(
        state,
        PowAction::NsRegister,
        &did,
        &register_binding(state, &name, &ch),
        effort,
    );
    let body = register_body(state, key, local, suffix, &ch, Some(&pow));
    post(router, "/v1/register", body).await
}

#[tokio::test]
async fn a_registration_without_work_is_told_the_signed_effort() {
    let state = state_with(vec![suffix(A, 16)]);
    let r = router(&state);
    let (did, key) = fresh_did_and_key();
    let name = format!("alice@{A}");
    let (ch, effort) = challenge_for(&r, &state, "register", &did, &name).await;
    assert_eq!(effort, 16);

    let (status, body) = post(
        &r,
        "/v1/register",
        register_body(&state, &key, "alice", A, &ch, None),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "{body}");
    assert_eq!(body["code"], "POW_REQUIRED");
    let restated = PowOffer::from_envelope(
        &URL_SAFE_NO_PAD
            .decode(body["pow_offer"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!((restated.challenge, restated.effort), (ch.clone(), 16));

    // The challenge is still good: solve the offer and register.
    let pow = solve(
        &state,
        PowAction::NsRegister,
        &did,
        &register_binding(&state, &name, &ch),
        effort,
    );
    let (status, body) = post(
        &r,
        "/v1/register",
        register_body(&state, &key, "alice", A, &ch, Some(&pow)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn too_little_work_is_refused_and_leaves_the_challenge_usable() {
    let state = state_with(vec![suffix(A, 64)]);
    let r = router(&state);
    let (did, key) = fresh_did_and_key();
    let name = format!("alice@{A}");
    let (ch, effort) = challenge_for(&r, &state, "register", &did, &name).await;
    let binding = register_binding(&state, &name, &ch);

    let cheap = solve(&state, PowAction::NsRegister, &did, &binding, effort / 4);
    let (status, body) = post(
        &r,
        "/v1/register",
        register_body(&state, &key, "alice", A, &ch, Some(&cheap)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "POW_INSUFFICIENT");

    let enough = solve(&state, PowAction::NsRegister, &did, &binding, effort);
    let (status, body) = post(
        &r,
        "/v1/register",
        register_body(&state, &key, "alice", A, &ch, Some(&enough)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn work_for_another_challenge_or_action_is_invalid() {
    let state = state_with(vec![suffix(A, SURE)]);
    let r = router(&state);
    let (did, key) = fresh_did_and_key();
    let name = format!("alice@{A}");
    let (first, effort) = challenge_for(&r, &state, "register", &did, &name).await;
    let (second, _) = challenge_for(&r, &state, "register", &did, &name).await;

    // Work for the first challenge, sent with the second.
    let pow = solve(
        &state,
        PowAction::NsRegister,
        &did,
        &register_binding(&state, &name, &first),
        effort,
    );
    let (status, body) = post(
        &r,
        "/v1/register",
        register_body(&state, &key, "alice", A, &second, Some(&pow)),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("POW_INVALID"))
    );

    // Register for real, then replay register work on a renew challenge.
    let (status, _) = register(&r, &state, &key, "alice", A).await;
    assert_eq!(status, StatusCode::OK);
    let (renew_ch, renew_effort) = challenge_for(&r, &state, "renew", &did, &name).await;
    let replayed = solve(
        &state,
        PowAction::NsRegister,
        &did,
        &register_binding(&state, &name, &renew_ch),
        renew_effort.max(effort),
    );
    let (status, body) = post(
        &r,
        "/v1/renew",
        serde_json::json!({
            "alias": name, "did": did, "challenge": renew_ch,
            "proof_of_control": proof(&key, &state, Action::Renew, &name, &renew_ch),
            "pow": replayed,
        }),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("POW_INVALID"))
    );
}

#[tokio::test]
async fn bad_work_is_refused_before_the_signature_is_looked_at() {
    let state = state_with(vec![suffix(A, SURE)]);
    let r = router(&state);
    let (did, key) = fresh_did_and_key();
    let name = format!("alice@{A}");
    let (ch, effort) = challenge_for(&r, &state, "register", &did, &name).await;
    let wrong = solve(&state, PowAction::NsRegister, &did, &[0; 32], effort);
    let mut body = register_body(&state, &key, "alice", A, &ch, Some(&wrong));
    body["proof_of_control"] = "AAAA".into(); // not even a COSE envelope

    let (status, body) = post(&r, "/v1/register", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["code"], "POW_INVALID",
        "the work fails first, not PROOF_FAILED"
    );
}

#[tokio::test]
async fn a_challenge_for_one_name_or_action_does_not_serve_another() {
    let state = state_with(vec![suffix(A, 16)]);
    let r = router(&state);
    let (did, key) = fresh_did_and_key();
    let (ch, effort) = challenge_for(&r, &state, "register", &did, &format!("alice@{A}")).await;

    let other = format!("bobby@{A}");
    let pow = solve(
        &state,
        PowAction::NsRegister,
        &did,
        &register_binding(&state, &other, &ch),
        effort,
    );
    let (status, body) = post(
        &r,
        "/v1/register",
        register_body(&state, &key, "bobby", A, &ch, Some(&pow)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["code"], "CHALLENGE_UNKNOWN");
}

#[tokio::test]
async fn a_challenge_without_an_action_leads_only_to_pow_required() {
    let state = state_with(vec![suffix(A, 16)]);
    let r = router(&state);
    let (_, key) = fresh_did_and_key();
    let (_, body) = get(&r, "/v1/challenge").await;
    let ch = body["challenge"].as_str().unwrap();
    assert!(body.get("pow").is_none());

    let (status, body) = post(
        &r,
        "/v1/register",
        register_body(&state, &key, "alice", A, ch, None),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "{body}");
    assert_eq!(body["code"], "POW_REQUIRED");
}

#[tokio::test]
async fn the_challenge_refuses_what_register_would() {
    let mut closed = suffix(A, 16);
    closed.registration = Registration::Closed;
    let (listed, listed_key) = fresh_did_and_key();
    closed.registration_allow = vec![AllowEntry {
        did: listed.clone(),
        aliases: vec!["dj".into()],
    }];
    let state = state_with(vec![closed, suffix(B, 16)]);
    let r = router(&state);
    let (stranger, key) = fresh_did_and_key();

    let refused = |status, code| (status, Some(code));
    let code =
        |(s, b): (StatusCode, serde_json::Value)| (s, b["code"].as_str().map(str::to_string));
    let (s, c) = code(offer(&r, "register", &stranger, &format!("alice@{A}")).await);
    assert_eq!(
        (s, c.as_deref()),
        refused(StatusCode::FORBIDDEN, "REGISTRATION_CLOSED")
    );
    let (s, c) = code(offer(&r, "register", &listed, &format!("other@{A}")).await);
    assert_eq!(
        (s, c.as_deref()),
        refused(StatusCode::FORBIDDEN, "REGISTRATION_CLOSED")
    );
    // The listed (DID, alias) pays min_effort, not the short-name multiplier.
    let (_, effort) = challenge_for(&r, &state, "register", &listed, &format!("dj@{A}")).await;
    assert_eq!(effort, 16);

    for (local, status, want) in [
        ("ab", StatusCode::BAD_REQUEST, "ALIAS_TOO_SHORT"),
        ("admin", StatusCode::FORBIDDEN, "ALIAS_RESERVED"),
        ("4dm1n-x", StatusCode::FORBIDDEN, "ALIAS_RESERVED"),
    ] {
        let (s, c) = code(offer(&r, "register", &stranger, &format!("{local}@{B}")).await);
        assert_eq!((s, c.as_deref()), refused(status, want), "{local}");
    }

    // A DID that holds a name on B is offered a challenge for a second: the
    // refusal would name the alias it holds before any proof. Register,
    // signed by that DID, refuses it.
    let (status, _) = register(&r, &state, &key, "alice", B).await;
    assert_eq!(status, StatusCode::OK);
    let (s, body) = offer(&r, "register", &stranger, &format!("carol@{B}")).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(!body.to_string().contains("alice"), "{body}");
    let (status, body) = register(&r, &state, &key, "carol", B).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("DID_HOLDS_NAME"))
    );
    // ...and someone else is refused the name taken.
    let (_, other_key) = fresh_did_and_key();
    let (s, c) = code(
        offer(
            &r,
            "register",
            &naming_did(&other_key),
            &format!("alice@{B}"),
        )
        .await,
    );
    assert_eq!(
        (s, c.as_deref()),
        refused(StatusCode::CONFLICT, "ALIAS_TAKEN")
    );
    let _ = listed_key;
}

#[tokio::test]
async fn effort_follows_the_suffix_and_the_name_length() {
    let state = state_with(vec![suffix(A, 16), suffix(B, 32)]);
    let r = router(&state);
    let (did, _) = fresh_did_and_key();
    let effort = |name: String| {
        let (r, state, did) = (r.clone(), state.clone(), did.clone());
        async move { challenge_for(&r, &state, "register", &did, &name).await.1 }
    };
    assert_eq!(effort(format!("alice@{A}")).await, 16);
    assert_eq!(effort(format!("alice@{B}")).await, 32);
    // short_name_len 5, factor 4: 4 letters pay 4×, 3 letters 16×.
    assert_eq!(effort(format!("abcd@{A}")).await, 64);
    assert_eq!(effort(format!("abc@{A}")).await, 256);
    // Renew and rotate pay renew_effort.
    let (_, body) = offer(&r, "renew", &did, &format!("alice@{A}")).await;
    assert_eq!(body["pow"]["effort"], SURE);
}

#[tokio::test]
async fn renew_asks_for_work_at_renew_effort() {
    let state = state_with(vec![suffix(A, 16)]);
    let r = router(&state);
    let (did, key) = fresh_did_and_key();
    let name = format!("alice@{A}");
    assert_eq!(
        register(&r, &state, &key, "alice", A).await.0,
        StatusCode::OK
    );

    let (ch, effort) = challenge_for(&r, &state, "renew", &did, &name).await;
    let body = |pow: Option<&Proof>| {
        let mut b = serde_json::json!({
            "alias": name, "did": did, "challenge": ch,
            "proof_of_control": proof(&key, &state, Action::Renew, &name, &ch),
        });
        if let Some(pow) = pow {
            b["pow"] = serde_json::to_value(pow).unwrap();
        }
        b
    };
    let (status, _) = post(&r, "/v1/renew", body(None)).await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    let pow = solve(
        &state,
        PowAction::NsRenew,
        &did,
        &naming::proof_hash(Action::Renew, &state.ns_did_string(), &name, &ch),
        effort,
    );
    let (status, resp) = post(&r, "/v1/renew", body(Some(&pow))).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
}

#[tokio::test]
async fn a_rotation_with_bad_work_leaves_the_holders_challenge_usable() {
    let state = state_with(vec![suffix(A, 16)]);
    let r = router(&state);
    let (old_did, old_key) = fresh_did_and_key();
    let (new_did, new_key) = fresh_did_and_key();
    let name = format!("alice@{A}");
    assert_eq!(
        register(&r, &state, &old_key, "alice", A).await.0,
        StatusCode::OK
    );

    let (ch, effort) = challenge_for(&r, &state, "rotate", &old_did, &name).await;
    let rotate = |pow: &Proof| {
        serde_json::json!({
            "alias": name, "old_did": old_did, "new_did": new_did, "challenge": ch,
            "sig_by_old": STANDARD.encode(old_key.sign(ch.as_bytes()).to_bytes()),
            "sig_by_new": STANDARD.encode(new_key.sign(ch.as_bytes()).to_bytes()),
            "pow": pow,
        })
    };
    let binding =
        naming::rotate_pow_binding(&state.ns_did_string(), &name, &old_did, &new_did, &ch).unwrap();
    let bad = solve(&state, PowAction::NsRotate, &old_did, &[1; 32], effort);
    let (status, body) = post(&r, "/v1/rotate", rotate(&bad)).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("POW_INVALID"))
    );

    let good = solve(&state, PowAction::NsRotate, &old_did, &binding, effort);
    let (status, body) = post(&r, "/v1/rotate", rotate(&good)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn at_the_cap_new_challenges_are_refused_and_live_ones_still_work() {
    let mut state = AppState::for_test_with_suffixes(vec![suffix(A, 16)]).unwrap();
    state.max_pending_challenges = 1;
    let state = Arc::new(state);
    let r = router(&state);
    let (did, key) = fresh_did_and_key();
    let name = format!("alice@{A}");
    let (ch, effort) = challenge_for(&r, &state, "register", &did, &name).await;

    let (status, body) = offer(&r, "register", &did, &name).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("BUSY"))
    );
    assert!(
        !state
            .remember_challenge(
                &hex::encode(rand::random::<[u8; 32]>()),
                PendingChallenge::unbound()
            )
            .await
    );

    let pow = solve(
        &state,
        PowAction::NsRegister,
        &did,
        &register_binding(&state, &name, &ch),
        effort,
    );
    let (status, body) = post(
        &r,
        "/v1/register",
        register_body(&state, &key, "alice", A, &ch, Some(&pow)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A registration flood fills the map only to nine tenths; renew and rotate
/// still get challenges.
#[tokio::test]
async fn a_registration_flood_leaves_room_to_renew() {
    let mut state = AppState::for_test_with_suffixes(vec![suffix(A, 16)]).unwrap();
    state.max_pending_challenges = 10;
    let state = Arc::new(state);
    let r = router(&state);
    let (did, key) = fresh_did_and_key();
    let name = format!("alice@{A}");
    assert_eq!(
        register(&r, &state, &key, "alice", A).await.0,
        StatusCode::OK
    );

    let (flooder, _) = fresh_did_and_key();
    for i in 0..9 {
        let (status, body) = offer(&r, "register", &flooder, &format!("name{i}@{A}")).await;
        assert_eq!(status, StatusCode::OK, "{i}: {body}");
    }
    let (status, _) = offer(&r, "register", &flooder, &format!("other@{A}")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, body) = offer(&r, "renew", &did, &name).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_action_challenge_names_its_did_and_name() {
    let state = state_with(vec![suffix(A, 16)]);
    let r = router(&state);
    let (status, body) = get(&r, "/v1/challenge?action=register").await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("BINDING_REQUIRED"))
    );
    let (status, body) = get(&r, "/v1/challenge?action=transfer").await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("BAD_ACTION"))
    );
}

// ---- the stranger pool and penalties (R1 task 3) ----

fn pooled(name: &str, min_effort: u64, per_hour: u32, burst: u32) -> SuffixConfig {
    let mut cfg = suffix(name, min_effort);
    cfg.pool = jig_config::v0_0_2_server::PoolPolicy {
        strangers_per_hour: per_hour,
        burst,
        queue_wait_secs: 0,
        ..jig_config::v0_0_2_server::PoolPolicy::recommended()
    };
    cfg
}

/// A state whose client addresses come from `x-forwarded-for`.
fn behind_proxy(suffixes: Vec<SuffixConfig>) -> Arc<AppState> {
    let mut state = AppState::for_test_with_suffixes(suffixes).unwrap();
    state.network.trust_proxy = true;
    Arc::new(state)
}

async fn effort_from(router: &Router, did: &str, name: &str, ip: &str) -> u64 {
    let req = Request::get(format!(
        "/v1/challenge?action=register&did={did}&name={name}"
    ))
    .header("x-forwarded-for", ip)
    .body(Body::empty())
    .unwrap();
    let (status, body) = send(router, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["pow"]["effort"].as_u64().unwrap()
}

#[tokio::test]
async fn past_the_pool_a_stranger_is_told_to_come_back() {
    let state = state_with(vec![pooled(A, 16, 1, 1)]);
    let r = router(&state);
    let (_, alice) = fresh_did_and_key();
    let (_, bob) = fresh_did_and_key();
    assert_eq!(
        register(&r, &state, &alice, "alice", A).await.0,
        StatusCode::OK
    );

    // Bob's work and signature are good, but the hour's token is gone.
    let (did, name) = (naming_did(&bob), format!("bobby@{A}"));
    let (ch, effort) = challenge_for(&r, &state, "register", &did, &name).await;
    let pow = solve(
        &state,
        PowAction::NsRegister,
        &did,
        &register_binding(&state, &name, &ch),
        effort,
    );
    let req = Request::post("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&register_body(&state, &bob, "bobby", A, &ch, Some(&pow))).unwrap(),
        ))
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let retry: u64 = resp.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry > 0);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["code"], "REGISTRATION_BUSY");
    assert_eq!(body["retry_after"], retry);
    // Refused before the consume: the challenge is still Bob's to use.
    assert!(
        state
            .peek_challenge(&ch, &did, &name, PowAction::NsRegister)
            .await
            .is_some()
    );
}

#[tokio::test]
async fn an_allowlisted_name_skips_an_empty_pool() {
    let mut cfg = pooled(A, 16, 1, 1);
    let (listed, listed_key) = fresh_did_and_key();
    cfg.registration_allow = vec![AllowEntry {
        did: listed,
        aliases: vec!["dj".into()],
    }];
    let state = state_with(vec![cfg]);
    let r = router(&state);
    let (_, stranger) = fresh_did_and_key();
    assert_eq!(
        register(&r, &state, &stranger, "alice", A).await.0,
        StatusCode::OK
    );
    let (status, body) = register(&r, &state, &listed_key, "dj", A).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn bad_work_in_another_dids_name_costs_only_the_sender() {
    let state = behind_proxy(vec![suffix(A, SURE)]);
    let r = router(&state);
    let (victim, victim_key) = fresh_did_and_key();
    let name = format!("alice@{A}");
    let before = effort_from(&r, &victim, &name, "10.0.0.2").await;

    // Mallory, at 10.0.0.1, sends bad work naming the victim's DID.
    let ch = {
        let req = Request::get(format!(
            "/v1/challenge?action=register&did={victim}&name={name}"
        ))
        .header("x-forwarded-for", "10.0.0.1")
        .body(Body::empty())
        .unwrap();
        send(&r, req).await.1["challenge"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let bad = solve(&state, PowAction::NsRegister, &victim, &[0; 32], SURE);
    let req = Request::post("/v1/register")
        .header("Content-Type", "application/json")
        .header("x-forwarded-for", "10.0.0.1")
        .body(Body::from(
            serde_json::to_vec(&register_body(
                &state,
                &victim_key,
                "alice",
                A,
                &ch,
                Some(&bad),
            ))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(send(&r, req).await.1["code"], "POW_INVALID");

    assert_eq!(effort_from(&r, &victim, &name, "10.0.0.2").await, before);
    assert_eq!(
        effort_from(&r, &victim, &name, "10.0.0.1").await,
        before * 2
    );
}

#[tokio::test]
async fn reaching_for_a_held_name_costs_that_did_on_that_name_only() {
    let state = behind_proxy(vec![suffix(A, 16)]);
    let r = router(&state);
    let (_, holder) = fresh_did_and_key();
    let (mallory, mallory_key) = fresh_did_and_key();
    let (bob, _) = fresh_did_and_key();
    let name = format!("alice@{A}");
    assert_eq!(
        register(&r, &state, &holder, "alice", A).await.0,
        StatusCode::OK
    );

    // Mallory signs for the held name; the challenge refuses it up front, so
    // send the register directly with an unbound challenge's worth of work.
    let mut pending = PendingChallenge::bound(Some(mallory.clone()), Some(name.clone()));
    pending.action = Some(PowAction::NsRegister);
    pending.effort = 16;
    let ch = hex::encode(rand::random::<[u8; 32]>());
    assert!(state.remember_challenge(&ch, pending).await);
    let pow = solve(
        &state,
        PowAction::NsRegister,
        &mallory,
        &register_binding(&state, &name, &ch),
        16,
    );
    let (status, body) = post(
        &r,
        "/v1/register",
        register_body(&state, &mallory_key, "alice", A, &ch, Some(&pow)),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("ALIAS_TAKEN"))
    );

    // Mallory's price for `alice` doubled; Bob's, and Mallory's for another
    // name, did not.
    let other = format!("carol@{A}");
    let m = state.suffixes.get(A).unwrap().market();
    assert_eq!(m.register_effort("alice", &mallory, "ip:x"), 32);
    assert_eq!(m.register_effort("alice", &bob, "ip:x"), 16);
    assert_eq!(effort_from(&r, &mallory, &other, "10.0.0.3").await, 16);
}
