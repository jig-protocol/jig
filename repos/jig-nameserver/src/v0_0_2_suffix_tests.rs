//! Route-level tests for serving several suffixes: choosing a suffix,
//! registration policy, one name per DID per suffix, and which delegation a
//! request gets.

use std::sync::Arc;

use axum::{Router, body::Body, http::Request, http::StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use jig_config::v0_0_2_server::{AllowEntry, Registration, SuffixConfig};
use jig_core::naming::{self, Action, SuffixDelegation};
use tower::ServiceExt;

use crate::v0_0_2::AppState;
use crate::v0_0_2_register::build_register_router;
use crate::v0_0_2_register::test_support::{fresh_did_and_key, naming_did, proof};
use crate::v0_0_2_resolve::build_resolve_router;
use crate::v0_0_2_rotate_renew::build_rotate_renew_router;

const A: &str = "a.example.org";
const B: &str = "b.example.org";

fn state_with(suffixes: Vec<SuffixConfig>) -> Arc<AppState> {
    Arc::new(AppState::for_test_with_suffixes(suffixes).unwrap())
}

fn open(suffix: &str) -> SuffixConfig {
    SuffixConfig::new(suffix)
}

fn router(state: &Arc<AppState>) -> Router {
    build_register_router(state.clone())
        .merge(build_resolve_router(state.clone()))
        .merge(build_rotate_renew_router(state.clone()))
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

async fn challenge(router: &Router) -> String {
    get(router, "/v1/challenge").await.1["challenge"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Register `local` under `suffix` (or under no named suffix) with `key`.
async fn register(
    router: &Router,
    state: &AppState,
    key: &SigningKey,
    local: &str,
    suffix: Option<&str>,
    proof_suffix: &str,
) -> (StatusCode, serde_json::Value, String) {
    let ch = challenge(router).await;
    let alias = format!("{local}@{proof_suffix}").to_ascii_lowercase();
    let mut body = serde_json::json!({
        "did": naming_did(key),
        "requested_alias": local,
        "proof_of_control": proof(key, state, Action::Register, &alias, &ch),
        "challenge": ch,
    });
    if let Some(s) = suffix {
        body["suffix"] = s.into();
    }
    let (status, body) = post(router, "/v1/register", body).await;
    (status, body, ch)
}

fn attested(body: &serde_json::Value) -> naming::Attestation {
    let env = URL_SAFE_NO_PAD
        .decode(body["attestation"].as_str().unwrap())
        .unwrap();
    naming::Attestation::from_envelope(&env).unwrap()
}

#[tokio::test]
async fn with_several_suffixes_a_registration_names_one() {
    let state = state_with(vec![open(A), open(B)]);
    let r = router(&state);
    let (_, key) = fresh_did_and_key();

    let (status, body, _) = register(&r, &state, &key, "alice", None, A).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "SUFFIX_REQUIRED");

    let (status, body, _) = register(
        &r,
        &state,
        &key,
        "alice",
        Some("c.example.org"),
        "c.example.org",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "UNKNOWN_SUFFIX");

    let (status, body, _) = register(&r, &state, &key, "alice", Some("B.example.org"), B).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(attested(&body).alias, "alice@b.example.org");
}

#[tokio::test]
async fn with_one_suffix_a_registration_may_leave_it_out() {
    let state = state_with(vec![open(A)]);
    let r = router(&state);
    let (_, key) = fresh_did_and_key();
    let (status, body, _) = register(&r, &state, &key, "alice", None, A).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn one_did_holds_one_name_per_suffix_and_names_in_several() {
    let state = state_with(vec![open(A), open(B)]);
    let r = router(&state);
    let (did, key) = fresh_did_and_key();

    assert_eq!(
        register(&r, &state, &key, "alice", Some(A), A).await.0,
        StatusCode::OK
    );
    assert_eq!(
        register(&r, &state, &key, "alice", Some(B), B).await.0,
        StatusCode::OK
    );
    // Re-registering the same name is a refresh, not a second name.
    assert_eq!(
        register(&r, &state, &key, "alice", Some(A), A).await.0,
        StatusCode::OK
    );

    let (status, body, _) = register(&r, &state, &key, "alicia", Some(A), A).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DID_HOLDS_NAME");

    for name in ["alice@a.example.org", "alice@b.example.org"] {
        let (status, body) = get(&r, &format!("/v1/resolve/{name}")).await;
        assert_eq!(status, StatusCode::OK, "{name}: {body}");
        assert_eq!(attested(&body).did, did);
    }
}

#[tokio::test]
async fn policy_refusals_leave_the_challenge_usable() {
    let mut closed = open(B);
    closed.registration = Registration::Closed;
    let state = state_with(vec![open(A), closed]);
    let r = router(&state);
    let (_, key) = fresh_did_and_key();

    for (local, suffix, status, code) in [
        ("alice", B, StatusCode::FORBIDDEN, "REGISTRATION_CLOSED"),
        ("al", A, StatusCode::BAD_REQUEST, "ALIAS_TOO_SHORT"),
        ("adm1n", A, StatusCode::FORBIDDEN, "ALIAS_RESERVED"),
        ("jig-official", A, StatusCode::FORBIDDEN, "ALIAS_RESERVED"),
    ] {
        let (got, body, ch) = register(&r, &state, &key, local, Some(suffix), suffix).await;
        assert_eq!(
            (got, body["code"].as_str()),
            (status, Some(code)),
            "{local}@{suffix}"
        );
        assert!(
            state
                .take_challenge(&ch, &naming_did(&key), &format!("{local}@{suffix}"))
                .await,
            "{local}: the challenge was not consumed"
        );
    }
}

#[tokio::test]
async fn the_allowlist_admits_its_did_to_its_names_on_a_closed_suffix() {
    let (dj_did, dj) = fresh_did_and_key();
    let (help_did, help) = fresh_did_and_key();
    let (_, other) = fresh_did_and_key();
    let mut team = SuffixConfig::new("jig");
    team.single_label_authority = true;
    team.registration = Registration::Closed;
    team.registration_allow = vec![
        AllowEntry {
            did: dj_did,
            aliases: vec!["dj".to_string()],
        },
        AllowEntry {
            did: help_did,
            aliases: vec!["support".to_string()],
        },
    ];
    let state = state_with(vec![team]);
    let r = router(&state);

    // Too short and reserved, but listed for these DIDs.
    for (key, local) in [(&dj, "dj"), (&help, "support")] {
        let (status, body, _) = register(&r, &state, key, local, None, "jig").await;
        assert_eq!(status, StatusCode::OK, "{local}: {body}");
    }
    // Another DID, even for a listed name, and a listed DID for an unlisted
    // name, are both refused.
    for (key, local) in [(&other, "dj"), (&dj, "alice")] {
        let (status, body, _) = register(&r, &state, key, local, None, "jig").await;
        assert_eq!(
            (status, body["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("REGISTRATION_CLOSED")),
            "{local}"
        );
    }
}

#[tokio::test]
async fn a_closed_suffix_still_resolves_and_renews() {
    let (did, key) = fresh_did_and_key();
    let mut cfg = open(A);
    cfg.registration_allow = vec![AllowEntry {
        did: did.clone(),
        aliases: vec!["alice".to_string()],
    }];
    cfg.registration = Registration::Closed;
    let state = state_with(vec![cfg]);
    let r = router(&state);
    assert_eq!(
        register(&r, &state, &key, "alice", None, A).await.0,
        StatusCode::OK
    );

    let ch = challenge(&r).await;
    let name = "alice@a.example.org";
    let (status, body) = post(
        &r,
        "/v1/renew",
        serde_json::json!({
            "alias": name, "did": did, "challenge": ch,
            "proof_of_control": proof(&key, &state, Action::Renew, name, &ch),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        get(&r, &format!("/v1/resolve/{name}")).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn names_under_an_unserved_suffix_are_unknown() {
    let state = state_with(vec![open(A)]);
    let r = router(&state);
    let (status, body) = get(&r, "/v1/resolve/alice@b.example.org").await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("UNKNOWN_SUFFIX"))
    );

    let (did, key) = fresh_did_and_key();
    let ch = challenge(&r).await;
    let name = "alice@b.example.org";
    let (status, body) = post(
        &r,
        "/v1/renew",
        serde_json::json!({
            "alias": name, "did": did, "challenge": ch,
            "proof_of_control": proof(&key, &state, Action::Renew, name, &ch),
        }),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("UNKNOWN_SUFFIX"))
    );
}

fn bare(key: &SigningKey, challenge: &str) -> String {
    STANDARD.encode(key.sign(challenge.as_bytes()).to_bytes())
}

#[tokio::test]
async fn rotating_one_name_leaves_the_did_s_other_suffixes() {
    let state = state_with(vec![open(A), open(B)]);
    let r = router(&state);
    let (old_did, old) = fresh_did_and_key();
    let (new_did, new) = fresh_did_and_key();
    register(&r, &state, &old, "alice", Some(A), A).await;
    register(&r, &state, &old, "alice", Some(B), B).await;

    let ch = challenge(&r).await;
    let (status, body) = post(
        &r,
        "/v1/rotate",
        serde_json::json!({
            "alias": "alice@a.example.org", "old_did": old_did, "new_did": new_did,
            "challenge": ch, "sig_by_old": bare(&old, &ch), "sig_by_new": bare(&new, &ch),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let holder = |body: serde_json::Value| attested(&body).did;
    assert_eq!(
        holder(get(&r, "/v1/resolve/alice@a.example.org").await.1),
        new_did
    );
    assert_eq!(
        holder(get(&r, "/v1/resolve/alice@b.example.org").await.1),
        old_did
    );
}

#[tokio::test]
async fn rotating_into_a_did_with_another_name_there_is_refused() {
    let state = state_with(vec![open(A)]);
    let r = router(&state);
    let (old_did, old) = fresh_did_and_key();
    let (bob_did, bob) = fresh_did_and_key();
    register(&r, &state, &old, "alice", None, A).await;
    register(&r, &state, &bob, "bobby", None, A).await;

    let ch = challenge(&r).await;
    let (status, body) = post(
        &r,
        "/v1/rotate",
        serde_json::json!({
            "alias": "alice@a.example.org", "old_did": old_did, "new_did": bob_did,
            "challenge": ch, "sig_by_old": bare(&old, &ch), "sig_by_new": bare(&bob, &ch),
        }),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("DID_HOLDS_NAME"))
    );
    assert_eq!(
        attested(&get(&r, "/v1/resolve/bobby@a.example.org").await.1).did,
        bob_did
    );
}

async fn delegation(
    router: &Router,
    query: &str,
    host: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::get(format!("/.well-known/jig-ns-delegation{query}"));
    if let Some(h) = host {
        req = req.header("Host", h);
    }
    send(router, req.body(Body::empty()).unwrap()).await
}

fn delegated_suffix(body: &serde_json::Value) -> String {
    let envs: Vec<Vec<u8>> = body["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| URL_SAFE_NO_PAD.decode(e.as_str().unwrap()).unwrap())
        .collect();
    SuffixDelegation::from_envelopes(&envs).unwrap().suffix
}

#[tokio::test]
async fn the_delegation_served_follows_the_query_then_the_host() {
    let mut jig = SuffixConfig::new("jig");
    jig.single_label_authority = true;
    let state = state_with(vec![open(A), open(B), jig]);
    let r = router(&state);

    let (status, body) = delegation(&r, "", None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("NO_DELEGATION"))
    );
    assert_eq!(
        delegated_suffix(&delegation(&r, "?suffix=B.example.org", None).await.1),
        B
    );
    assert_eq!(
        delegated_suffix(&delegation(&r, "", Some("a.example.org:443")).await.1),
        A
    );
    // A single-label suffix has no DNS delegation, by query or by host.
    assert_eq!(
        delegation(&r, "?suffix=jig", None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delegation(&r, "", Some("jig")).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_only_dns_rooted_suffix_is_the_default_delegation() {
    let mut jig = SuffixConfig::new("jig");
    jig.single_label_authority = true;
    let state = state_with(vec![jig, open(A)]);
    let r = router(&state);
    assert_eq!(
        delegated_suffix(&delegation(&r, "", Some("127.0.0.1:8070")).await.1),
        A
    );

    let mut jig = SuffixConfig::new("jig");
    jig.single_label_authority = true;
    let only_jig = state_with(vec![jig]);
    assert_eq!(
        delegation(&router(&only_jig), "", None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn suffixes_lists_what_is_served() {
    let mut jig = SuffixConfig::new("jig");
    jig.single_label_authority = true;
    jig.registration = Registration::Closed;
    let state = state_with(vec![open(A), jig]);
    let (status, body) = get(&router(&state), "/v1/suffixes").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({
            "ns_did": state.ns_did_string(),
            "suffixes": [
                {"suffix": A, "registration": "open", "dns_delegation": true},
                {"suffix": "jig", "registration": "closed", "dns_delegation": false},
            ],
        })
    );
}

#[tokio::test]
async fn a_refused_rotation_leaves_the_challenge_usable() {
    let state = state_with(vec![open(A)]);
    let r = router(&state);
    let (old_did, old) = fresh_did_and_key();
    let (new_did, new) = fresh_did_and_key();
    register(&r, &state, &old, "alice", None, A).await;

    let ch = challenge(&r).await;
    let (_, stranger) = fresh_did_and_key();
    let (status, _) = post(
        &r,
        "/v1/rotate",
        serde_json::json!({
            "alias": "alice@a.example.org", "old_did": old_did, "new_did": new_did,
            "challenge": ch, "sig_by_old": bare(&stranger, &ch), "sig_by_new": bare(&new, &ch),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = post(
        &r,
        "/v1/rotate",
        serde_json::json!({
            "alias": "alice@a.example.org", "old_did": old_did, "new_did": new_did,
            "challenge": ch, "sig_by_old": bare(&old, &ch), "sig_by_new": bare(&new, &ch),
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same challenge still works: {body}"
    );
}

#[tokio::test]
async fn a_challenge_bound_to_a_did_and_name_serves_only_them() {
    let state = state_with(vec![open(A)]);
    let r = router(&state);
    let (did, key) = fresh_did_and_key();
    let (_, other) = fresh_did_and_key();

    let (status, body) = get(&r, "/v1/challenge?name=no-suffix").await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("INVALID_NAME"))
    );
    let (status, body) = get(&r, "/v1/challenge?did=not-a-did").await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("BAD_DID"))
    );

    let (_, body) = get(
        &r,
        &format!("/v1/challenge?did={did}&name=Alice@A.example.org"),
    )
    .await;
    let ch = body["challenge"].as_str().unwrap().to_string();
    let attempt = |key: &SigningKey, local: &str| {
        let alias = format!("{local}@{A}");
        serde_json::json!({
            "did": naming_did(key),
            "requested_alias": local,
            "proof_of_control": proof(key, &state, Action::Register, &alias, &ch),
            "challenge": ch,
        })
    };
    for (key, local) in [(&other, "alice"), (&key, "alicia")] {
        let (status, body) = post(&r, "/v1/register", attempt(key, local)).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("CHALLENGE_UNKNOWN")),
            "{local}"
        );
    }
    let (status, body) = post(&r, "/v1/register", attempt(&key, "alice")).await;
    assert_eq!(status, StatusCode::OK, "the bound DID and name: {body}");
}
