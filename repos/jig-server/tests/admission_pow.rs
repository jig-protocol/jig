//! `[auth.admission] unknown_dids = "proof-of-work"`: a DID this server has
//! never seen does some work, once, before the server deals with it.

mod support;

use axum::http::StatusCode;
use jig_client::admission::{AdmissionProof, PowAdmissionProof};
use jig_client::blocks::build_text_render;
use jig_config::v0_0_2_server::{AdmissionSection, ReputationRecord, UnknownDidsPolicy};
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

fn effort() -> std::num::NonZeroU64 {
    admission_pow::effort_for_bits(BITS)
}

fn proof_json(proof: &impl serde::Serialize) -> serde_json::Value {
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

    // Not refused for owing work: a DID that owes it can ask whether it does.
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
    // Work for the other server, signed for it: the work is checked first
    // (JEP-0008 rule 10), so it fails as work before the signature is read.
    let proof = AdmissionProof::sign(&alice.as_client(), other, nonce.clone());
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&proof))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "PROOF_OF_WORK_INSUFFICIENT");
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

/// A server that asks for no work does not record any, and says the caller
/// owes none.
#[tokio::test]
async fn an_open_server_asks_for_nothing() {
    let server = TestServer::authenticated();
    let alice = Identity::new(1);
    let (status, body) = server
        .send_full(&server.sign_get(&alice, "/api/v1/admission"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("pow_bits").is_none(), "{body}");
    assert_eq!(body["proven"], true);
}

/// A DID the operator has a record for is known, so it owes no work, and
/// the status says so rather than sending the client off to do it.
#[tokio::test]
async fn a_did_with_a_record_owes_no_work() {
    let alice = Identity::new(1);
    let server = TestServer::with_admission(AdmissionSection {
        unknown_dids: UnknownDidsPolicy::ProofOfWork,
        pow_bits: BITS,
        records: vec![ReputationRecord {
            did: alice.did().to_did_jig_string(),
            ruleset_key: "r".to_string(),
            score: 1,
        }],
        ..AdmissionSection::default()
    });
    let (status, body) = server
        .send_full(&server.sign_get(&alice, "/api/v1/admission"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["proven"], true);
    let (status, body) = server
        .send(&server.sign_get(&alice, "/api/v1/channels"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A banned DID asking its standing gets the refusal, not "owes work".
#[tokio::test]
async fn a_banned_did_is_told_it_is_refused() {
    let banned = Identity::new(1);
    let server = pow_server(&[&banned]);
    let (status, body) = server
        .send_full(&server.sign_get(&banned, "/api/v1/admission"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "NOT_ADMITTED");
}

/// JEP-0008's `admit` proof admits, and the status says what it costs as an
/// effort.
#[tokio::test]
async fn a_jep_0008_admit_proof_admits() {
    let server = pow_server(&[]);
    let alice = Identity::new(1);

    let (_, body) = server
        .send_full(&server.sign_get(&alice, "/api/v1/admission"))
        .await;
    assert_eq!(body["effort"], effort().get(), "{body}");

    let proof = PowAdmissionProof::solve(&alice.as_client(), &server.server_did(), effort());
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&proof))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["proven"], true);
    let (status, body) = server
        .send(&server.sign_get(&alice, "/api/v1/channels"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Less than the asked effort, or work for another server, is refused as work.
#[tokio::test]
async fn too_little_or_misdirected_admit_work_is_refused() {
    let server = pow_server(&[]);
    let alice = Identity::new(1);
    let half = std::num::NonZeroU64::new(effort().get() / 2).unwrap();
    let proof = PowAdmissionProof::solve(&alice.as_client(), &server.server_did(), half);
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&proof))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "PROOF_OF_WORK_INSUFFICIENT");

    let other = "did:jig:z6MkOtherServerOtherServerOtherServerOtherServer";
    let mut found = None;
    let alice_did = alice.did().to_did_jig_string();
    let mut start = 0;
    while found.is_none() {
        let pow = admission_pow::puzzle(other, &alice_did)
            .try_solve(effort(), start, u64::MAX - start)
            .unwrap();
        start = u64::from_be_bytes(pow.nonce[..].try_into().unwrap()) + 1;
        if admission_pow::puzzle(&server.server_did(), &alice_did)
            .check(&pow, effort())
            .is_err()
        {
            found = Some(pow);
        }
    }
    let proof = PowAdmissionProof::sign(&alice.as_client(), &server.server_did(), found.unwrap());
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&proof))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "PROOF_OF_WORK_INSUFFICIENT");
}

/// Bad work under a bad signature fails on the work: the signature is never
/// checked for a request whose work is wrong (JEP-0008 rule 10).
#[tokio::test]
async fn the_work_is_checked_before_the_signature() {
    let server = pow_server(&[]);
    let (alice, mallory) = (Identity::new(1), Identity::new(2));
    let half = std::num::NonZeroU64::new(effort().get() / 2).unwrap();
    let mut proof = PowAdmissionProof::solve(&alice.as_client(), &server.server_did(), half);
    proof.sig_b64 = PowAdmissionProof::sign(
        &mallory.as_client(),
        &server.server_did(),
        proof.pow.clone(),
    )
    .sig_b64;
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&proof))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "PROOF_OF_WORK_INSUFFICIENT");

    // Good work, signed by someone else: refused on the signature.
    let mut proof = PowAdmissionProof::solve(&alice.as_client(), &server.server_did(), effort());
    proof.sig_b64 = PowAdmissionProof::sign(
        &mallory.as_client(),
        &server.server_did(),
        proof.pow.clone(),
    )
    .sig_b64;
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&proof))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["code"], "BAD_SIGNATURE");
}

/// The signed welcome states the effort a new DID owes (JEP-0008 rule 15),
/// and work at that effort admits.
#[tokio::test]
async fn the_welcome_states_the_effort_that_admits() {
    let server = pow_server(&[]);
    let alice = Identity::new(1);
    let url = server.serve_ws().await;
    let client = jig_client::Client::connect(&url, alice.as_client())
        .await
        .unwrap();
    let welcome = client.welcome().expect("welcome");
    assert_eq!(welcome.server_did, server.server_did());
    let admit = welcome.admit.expect("the welcome asks admission work");
    assert_eq!(admit.alg(), Some(jig_core::pow::Alg::Blake3));
    assert_eq!(admit.effort(), Some(effort()));

    let proof = PowAdmissionProof::solve(
        &alice.as_client(),
        &welcome.server_did,
        admit.effort().unwrap(),
    );
    let (status, body) = server
        .post_json("/api/v1/admission", &proof_json(&proof))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["proven"], true);
}
