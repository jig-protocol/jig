//! Gate 2: a server may refuse a caller before asking what they want.
//!
//! Every request here carries a genuine proof, so gate 1 passes and the
//! refusal is admission's — the convention that a refusal test proves nothing
//! if it fails at the wrong gate.

use axum::http::StatusCode;
use jig_config::v0_0_2_server::{
    AdmissionFloor, AdmissionSection, ReputationRecord, UnknownDidsPolicy,
};

mod support;
use support::ws::WsClient;
use support::{Identity, TestServer, history_path};

fn banning(who: &Identity) -> AdmissionSection {
    AdmissionSection {
        banned_dids: vec![who.did().to_did_jig_string()],
        ..AdmissionSection::default()
    }
}

fn record(who: &Identity, ruleset: &str, score: i64) -> ReputationRecord {
    ReputationRecord {
        did: who.did().to_did_jig_string(),
        ruleset_key: ruleset.to_string(),
        score,
    }
}

#[tokio::test]
async fn a_banned_did_is_refused_on_every_read_surface() {
    let owner = Identity::new(1);
    let banned = Identity::new(2);
    let server = TestServer::with_admission(banning(&banned));
    server.create_channel(&owner, "#open", "open").await;

    for path in [
        "/api/v1/channels".to_string(),
        history_path("#open"),
        "/api/v1/blocks/bafy_anything".to_string(),
    ] {
        let (status, body) = server.send(&server.sign_get(&banned, &path)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: body={body}");
        assert_eq!(body["code"], "NOT_ADMITTED", "{path}");
    }

    // And the same key is fine on a server that has not banned it.
    let open_server = TestServer::authenticated();
    let (status, _) = open_server
        .send(&open_server.sign_get(&banned, "/api/v1/channels"))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the ban is this server's, not the key's"
    );
}

/// THE ordering test. Admission runs before authorization, so a banned DID
/// asking about a restricted channel it is not a member of is told
/// NOT_ADMITTED — never NOT_A_MEMBER, which would confirm the channel exists.
#[tokio::test]
async fn admission_is_decided_before_authorization() {
    let owner = Identity::new(1);
    let banned = Identity::new(2);
    let server = TestServer::with_admission(banning(&banned));
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    let (status, body) = server
        .send(&server.sign_get(&banned, &history_path("#private")))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_ADMITTED", "not NOT_A_MEMBER: {body}");

    // Nor is an unknown slug read back as an empty 200 to a refused caller.
    let (status, body) = server
        .send(&server.sign_get(&banned, &history_path("#nowhere")))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_ADMITTED");
}

#[tokio::test]
async fn a_banned_did_cannot_subscribe() {
    let owner = Identity::new(1);
    let banned = Identity::new(2);
    let server = TestServer::with_admission(banning(&banned));
    server.create_channel(&owner, "#open", "open").await;

    let url = server.serve_ws().await;
    let mut ws = WsClient::connect(&url).await;
    match ws.subscribe(&banned, "#open").await {
        Some(jig_pipeline::Frame::Error { status, code, .. }) => {
            assert_eq!(status, Some(403));
            assert_eq!(code, "NOT_ADMITTED");
        }
        other => panic!("expected a 403 error frame, got {other:?}"),
    }
}

/// `unknown_dids = "refuse"` with seeded records is a members-only server:
/// the seeded key reads, a fresh key does not.
#[tokio::test]
async fn a_members_only_server_admits_seeded_dids_and_refuses_strangers() {
    let owner = Identity::new(1);
    let member = Identity::new(2);
    let stranger = Identity::new(3);
    let server = TestServer::with_admission(AdmissionSection {
        unknown_dids: UnknownDidsPolicy::Refuse,
        records: vec![record(&owner, "club", 1), record(&member, "club", 1)],
        ..AdmissionSection::default()
    });
    server.create_channel(&owner, "#open", "open").await;

    let (status, body) = server
        .send(&server.sign_get(&member, &history_path("#open")))
        .await;
    assert_eq!(status, StatusCode::OK, "member: {body}");

    let (status, body) = server
        .send(&server.sign_get(&stranger, &history_path("#open")))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "stranger: {body}");
    assert_eq!(body["code"], "NOT_ADMITTED");
}

/// A floor refuses a scored-below DID and must NOT refuse a DID with no
/// score under its ruleset while unknowns are admitted.
#[tokio::test]
async fn a_floor_refuses_low_scores_and_leaves_unknowns_to_the_unknown_choice() {
    let owner = Identity::new(1);
    let low = Identity::new(2);
    let unscored = Identity::new(3);
    let server = TestServer::with_admission(AdmissionSection {
        unknown_dids: UnknownDidsPolicy::Admit,
        floors: vec![AdmissionFloor {
            ruleset_key: "club".to_string(),
            minimum: 0,
        }],
        records: vec![record(&low, "club", -5)],
        ..AdmissionSection::default()
    });
    server.create_channel(&owner, "#open", "open").await;

    let (status, body) = server
        .send(&server.sign_get(&low, &history_path("#open")))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "low: {body}");
    assert_eq!(body["code"], "NOT_ADMITTED");

    let (status, body) = server
        .send(&server.sign_get(&unscored, &history_path("#open")))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unscored must not be compared against the floor: {body}"
    );
}

/// With reads unauthenticated there is nobody to admit: the escape hatch
/// disables gate 2 along with the rest, exactly as documented.
#[tokio::test]
async fn the_escape_hatch_skips_admission() {
    let owner = Identity::new(1);
    let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
    config.auth.require_authenticated_reads = false;
    config.auth.admission.unknown_dids = UnknownDidsPolicy::Refuse;
    let server = TestServer::with_full_config(config);
    server.create_channel(&owner, "#open", "open").await;

    let (status, body) = server.send_unsigned(&history_path("#open")).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}
