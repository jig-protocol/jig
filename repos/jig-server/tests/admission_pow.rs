//! `[auth.admission] unknown_dids = "proof-of-work"`: a DID this server has
//! never seen does some work, once, before the server deals with it.

mod support;

use axum::http::StatusCode;
use jig_client::admission::AdmissionProof;
use jig_client::blocks::build_text_render;
use jig_config::v0_0_2_server::{AdmissionSection, UnknownDidsPolicy};
use jig_core::{HlcTimestamp, admission_pow};
use support::ws::WsClient;
use support::{Identity, TestServer};

/// Cheap enough for a debug build; the mechanism is the same at 20.
const BITS: u8 = 8;

fn pow_server(banned: &[&Identity]) -> TestServer {
    TestServer::with_admission(AdmissionSection {
        unknown_dids: UnknownDidsPolicy::ProofOfWork,
        pow_bits: BITS,
        banned_dids: banned
            .iter()
            .map(|who| who.did().to_did_jig_string())
            .collect(),
        ..AdmissionSection::default()
    })
}

fn proof_json(proof: &AdmissionProof) -> serde_json::Value {
    serde_json::to_value(proof).unwrap()
}

async fn prove(server: &TestServer, who: &Identity) {
    let proof = AdmissionProof::solve(&who.as_client(), &server.server_did(), BITS);
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&proof))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["proven"], true);
}

#[tokio::test]
async fn a_new_did_owes_the_work_and_is_known_once_it_has_done_it() {
    let server = pow_server(&[]);
    let alice = Identity::new(1);

    let (status, body) = server
        .send(&server.sign_get(&alice, "/api/v1/channels"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "PROOF_OF_WORK_REQUIRED");

    let id = alice.as_client();
    let block = build_text_render(&id, "#town", "hi", HlcTimestamp::now_wall(id.did().clone()));
    let (status, body) = server.post_block(&block).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "PROOF_OF_WORK_REQUIRED");

    // Gate 1 only: a DID that owes work can ask whether it does.
    let (status, body) = server
        .send_full(&server.sign_get(&alice, "/api/v1/admission"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["did"], alice.did().to_did_jig_string());
    assert_eq!(body["proven"], false);
    assert_eq!(body["pow_bits"], BITS);

    prove(&server, &alice).await;

    let (status, body) = server
        .send(&server.sign_get(&alice, "/api/v1/channels"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = server
        .send_full(&server.sign_get(&alice, "/api/v1/admission"))
        .await;
    assert_eq!(body["proven"], true);
}

#[tokio::test]
async fn an_unproven_did_cannot_subscribe() {
    let server = pow_server(&[]);
    let (owner, stranger) = (Identity::new(1), Identity::new(2));
    prove(&server, &owner).await;
    server.create_channel(&owner, "#open", "open").await;

    let url = server.serve_ws().await;
    let mut ws = WsClient::connect(&url).await;
    match ws.subscribe(&stranger, "#open").await {
        Some(jig_pipeline::Frame::Error { status, code, .. }) => {
            assert_eq!(status, Some(403));
            assert_eq!(code, "PROOF_OF_WORK_REQUIRED");
        }
        other => panic!("expected a 403 error frame, got {other:?}"),
    }
}

/// Work done for another server, or under another key, proves nothing here.
#[tokio::test]
async fn work_is_bound_to_this_server_and_to_the_key_holder() {
    let server = pow_server(&[]);
    let (alice, mallory) = (Identity::new(1), Identity::new(2));
    let alice_did = alice.did().to_did_jig_string();

    // A nonce that is work for some other server and, as found, not for this
    // one.
    let other = "did:jig:z6MkOtherServerOtherServerOtherServerOtherServer";
    let nonce = (0u64..)
        .map(|n| format!("{n:x}"))
        .find(|n| {
            admission_pow::meets(other, &alice_did, n, BITS)
                && !admission_pow::meets(&server.server_did(), &alice_did, n, BITS)
        })
        .unwrap();
    let proof = AdmissionProof::sign(&alice.as_client(), other, nonce.clone());
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&proof))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        body["code"], "BAD_SIGNATURE",
        "signed for the other server, so not for this one"
    );
    let proof = AdmissionProof::sign(&alice.as_client(), &server.server_did(), nonce);
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&proof))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "PROOF_OF_WORK_INSUFFICIENT");

    // Valid work for alice, signed by mallory: nobody admits a key they do
    // not hold.
    let mut forged = AdmissionProof::solve(&alice.as_client(), &server.server_did(), BITS);
    forged.sig_b64 = AdmissionProof::sign(
        &mallory.as_client(),
        &server.server_did(),
        forged.nonce.clone(),
    )
    .sig_b64;
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&forged))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["code"], "BAD_SIGNATURE");

    let (status, _) = server
        .send(&server.sign_get(&alice, "/api/v1/channels"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "alice is still unproven");
}

#[tokio::test]
async fn a_banned_did_cannot_work_its_way_in() {
    let banned = Identity::new(1);
    let server = pow_server(&[&banned]);
    let proof = AdmissionProof::solve(&banned.as_client(), &server.server_did(), BITS);
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&proof))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "NOT_ADMITTED");
}

/// The status endpoint answers only for the DID that signed; there is no way
/// to ask it about anyone else.
#[tokio::test]
async fn the_status_is_never_about_anyone_but_the_caller() {
    let server = pow_server(&[]);
    let (status, body) = server.send_unsigned_full("/api/v1/admission").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn an_oversized_nonce_is_refused_before_it_is_hashed() {
    let server = pow_server(&[]);
    let alice = Identity::new(1);
    let proof = AdmissionProof::sign(&alice.as_client(), &server.server_did(), "0".repeat(65));
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&proof))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "BAD_NONCE");
}

/// A server that asks for no work does not record any, and says so.
#[tokio::test]
async fn an_open_server_asks_for_nothing() {
    let server = TestServer::authenticated();
    let alice = Identity::new(1);
    let (status, body) = server
        .send_full(&server.sign_get(&alice, "/api/v1/admission"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("pow_bits").is_none(), "{body}");
    assert_eq!(body["proven"], false);
}
