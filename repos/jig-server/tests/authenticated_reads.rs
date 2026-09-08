//! Reads require proof of possession when the server is configured to demand it.
//!
//! These drive the real router over a real store, and the signatures are real
//! ed25519 signatures — a 200 here means the server actually verified one.

use axum::http::StatusCode;

mod support;
use support::{Identity, TestServer};

#[tokio::test]
async fn an_unsigned_read_is_refused() {
    let server = TestServer::authenticated();
    let (status, body) = server.send_unsigned("/api/v1/channels").await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body}");
    assert_eq!(body["code"], "AUTH_REQUIRED");
}

#[tokio::test]
async fn a_correctly_signed_read_succeeds() {
    let server = TestServer::authenticated();
    let caller = Identity::new(1);

    let (status, body) = server
        .send(&server.sign_get(&caller, "/api/v1/channels"))
        .await;

    assert_eq!(status, StatusCode::OK, "body={body}");
}

/// The same signed request twice. The signature is genuine both times — the
/// second must still be refused, which is the whole point of the nonce record.
#[tokio::test]
async fn a_replayed_read_is_refused_the_second_time() {
    let server = TestServer::authenticated();
    let caller = Identity::new(1);
    let req = server.sign_get(&caller, "/api/v1/channels");

    let (first, body) = server.send(&req).await;
    assert_eq!(first, StatusCode::OK, "precondition failed: body={body}");

    let (second, body) = server.send(&req).await;
    assert_eq!(second, StatusCode::UNAUTHORIZED, "body={body}");
    assert_eq!(body["code"], "REPLAYED");
}

/// A signature bound to one path must not authenticate another. This is the
/// attack the canonical hash exists to stop: capture a signed read of a public
/// resource, replay it against a private one.
#[tokio::test]
async fn a_signature_for_another_path_is_refused() {
    let server = TestServer::authenticated();
    let caller = Identity::new(1);

    let mut req = server.sign_get(&caller, "/api/v1/channels");
    req.path = "/api/v1/channels/%23secret/blocks".to_string();

    let (status, body) = server.send(&req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body}");
    assert_eq!(body["code"], "INVALID_SIG");
}

/// Claiming an identity you cannot sign for must fail. The signature is
/// well-formed and verifies against the ATTACKER's key — just not the claimed
/// one.
#[tokio::test]
async fn a_read_claiming_another_did_is_refused() {
    let server = TestServer::authenticated();
    let attacker = Identity::new(1);
    let victim = Identity::new(2);

    let mut req = server.sign_get(&attacker, "/api/v1/channels");
    req.did = victim.did().to_did_jig_string();

    let (status, body) = server.send(&req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body}");
    assert_eq!(body["code"], "INVALID_SIG");
}

/// Channel history is gated too, not just the listing.
#[tokio::test]
async fn channel_history_requires_a_proof() {
    let server = TestServer::authenticated();
    let (status, body) = server
        .send_unsigned("/api/v1/channels/%23hello/blocks")
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body}");
    assert_eq!(body["code"], "AUTH_REQUIRED");
}

#[tokio::test]
async fn channel_history_accepts_a_correctly_signed_read() {
    let server = TestServer::authenticated();
    let caller = Identity::new(1);

    let (status, body) = server
        .send(&server.sign_get(&caller, "/api/v1/channels/%23hello/blocks"))
        .await;

    assert_eq!(status, StatusCode::OK, "body={body}");
}

/// The migration escape hatch restores the pre-authentication behaviour, and
/// only when explicitly set.
#[tokio::test]
async fn unsigned_reads_still_work_when_the_escape_hatch_is_set() {
    let server = TestServer::unauthenticated();
    let (status, body) = server.send_unsigned("/api/v1/channels").await;

    assert_eq!(status, StatusCode::OK, "body={body}");
}
