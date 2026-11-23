//! H11: the client-side read proof works against a real server over real HTTP.
//!
//! `jig channel list`, `jig chat` and `jig tail` all read over REST through
//! `jig_client::ReadProof`. The server-side gate has its own tests; this one
//! proves the two halves agree on the wire — the canonical hash, the header
//! names, the percent-encoded path — by driving a real listener with
//! `reqwest`, exactly as the CLI does.

use integration_tests::harness::*;
use jig_client::read_auth::{ReadProof, signable_path};

async fn signed_get(who: &jig_client::Identity, url: &str) -> (u16, serde_json::Value) {
    let audience = integration_tests::harness::audience_for(url).await;
    let proof = ReadProof::sign(who, &audience, "GET", signable_path(url));
    let mut req = reqwest::Client::new().get(url);
    for (name, value) in proof.headers() {
        req = req.header(name, value);
    }
    let resp = req.send().await.expect("GET");
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

#[tokio::test]
async fn a_client_signed_read_is_accepted_by_a_real_server() {
    let server = TestJigServer::start_with_full_kinds()
        .await
        .expect("server");
    let (alice, _dir) = test_identity_with_dir();
    server
        .create_channel(&alice, "#hello", "open")
        .await
        .expect("create");

    // The listing, as `jig channel list` fetches it.
    let (status, body) =
        signed_get(&alice, &format!("{}/api/v1/channels", server.http_url())).await;
    assert_eq!(status, 200, "body={body}");
    let slugs: Vec<&str> = body["channels"]
        .as_array()
        .expect("channels")
        .iter()
        .filter_map(|c| c["slug"].as_str())
        .collect();
    assert_eq!(slugs, ["#hello"]);

    // The history, as `jig chat` backfills it: percent-encoded slug, query
    // string present on the wire and absent from the signature.
    let url = format!(
        "{}/api/v1/channels/%23hello/blocks?limit=10",
        server.http_url()
    );
    let (status, body) = signed_get(&alice, &url).await;
    assert_eq!(status, 200, "body={body}");
    assert!(body.is_array(), "timeline: {body}");
}

/// The negative half: without the proof the same server refuses the same
/// reads. Otherwise the test above would pass against a server that checks
/// nothing.
#[tokio::test]
async fn an_unsigned_read_is_refused_by_a_real_server() {
    let server = TestJigServer::start_with_full_kinds()
        .await
        .expect("server");
    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/channels", server.http_url()))
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status().as_u16(), 401);
}

/// A restricted channel's listing entry and history are served to a member
/// and withheld from a stranger, end to end.
#[tokio::test]
async fn restricted_channels_are_gated_end_to_end() {
    let server = TestJigServer::start_with_full_kinds()
        .await
        .expect("server");
    let (alice, a) = test_identity_with_dir();
    let (bob, b) = test_identity_with_dir();
    let (carol, _c) = test_identity_with_dir();
    let mls = tempfile::tempdir().unwrap();
    let alice_mls =
        jig_client::secure::Session::open(mls.path(), load_identity(&a, &alice.did_string()))
            .unwrap();
    let bob_mls =
        jig_client::secure::Session::open(mls.path(), load_identity(&b, &bob.did_string()))
            .unwrap();
    server
        .create_restricted_channel(&alice, &alice_mls, "#private")
        .await
        .expect("create");
    server
        .add_restricted_member(&alice, &alice_mls, "#private", &bob_mls)
        .await
        .expect("add bob");

    let history = format!("{}/api/v1/channels/%23private/blocks", server.http_url());
    let (status, _) = signed_get(&bob, &history).await;
    assert_eq!(status, 200, "bob is a member");
    let (status, body) = signed_get(&carol, &history).await;
    assert_eq!(status, 403, "carol is not: body={body}");
    assert_eq!(body["code"], "NOT_A_MEMBER");

    let listing = format!("{}/api/v1/channels", server.http_url());
    let (status, body) = signed_get(&carol, &listing).await;
    assert_eq!(status, 200, "the listing itself succeeds: {body}");
    assert!(
        !body.to_string().contains("#private"),
        "carol's listing must not name the channel: {body}"
    );
}

/// Send `proof` as a GET of `url`, returning the status and error code.
async fn send_proof(url: &str, headers: &[(&'static str, String)]) -> (u16, String) {
    let mut req = reqwest::Client::new().get(url);
    for (name, value) in headers {
        req = req.header(*name, value);
    }
    let resp = req.send().await.expect("GET");
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    (
        status,
        body["code"].as_str().unwrap_or_default().to_string(),
    )
}

/// #464: one proof, made for server A, sent to two servers on the same path
/// inside the freshness window. B refuses it as addressed elsewhere, and
/// records nothing; A, where it was meant to go, accepts it.
#[tokio::test]
async fn a_proof_for_one_server_is_refused_at_another() {
    let a = TestJigServer::start_with_full_kinds().await.expect("A");
    let b = TestJigServer::start_with_full_kinds().await.expect("B");
    assert_ne!(a.server_did_string, b.server_did_string);
    let (alice, _dir) = test_identity_with_dir();
    let path = "/api/v1/channels";
    let proof = ReadProof::sign(&alice, &a.server_did_string, "GET", path);
    let headers = proof.headers();

    let at_b = send_proof(&format!("{}{path}", b.http_url()), &headers).await;
    assert_eq!(at_b, (401, "WRONG_AUDIENCE".to_string()));

    let at_a = send_proof(&format!("{}{path}", a.http_url()), &headers).await;
    assert_eq!(at_a.0, 200, "A accepts the proof addressed to it: {at_a:?}");

    // Rewriting the audience header to B's DID breaks the signature.
    let mut rewritten = headers.clone();
    rewritten[1].1 = b.server_did_string.clone();
    let forged = send_proof(&format!("{}{path}", b.http_url()), &rewritten).await;
    assert_eq!(forged, (401, "INVALID_SIG".to_string()));
}

/// An unbound v1 proof is refused by name, so an old client is told to
/// upgrade rather than that its signature is wrong.
#[tokio::test]
async fn a_v1_proof_is_refused_as_an_unsupported_version() {
    use base64::Engine as _;
    let server = TestJigServer::start_with_full_kinds()
        .await
        .expect("server");
    let (alice, _dir) = test_identity_with_dir();
    let path = "/api/v1/channels";
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // The v1 layout: no audience, no signer DID.
    let v1 = jig_core::crypto::hash_labeled_parts(&[
        ("domain", b"jig-request-auth-v1".as_slice()),
        ("method", b"GET".as_slice()),
        ("path", path.as_bytes()),
        ("body", b"".as_slice()),
        ("hlc_wall_ms", &wall.to_le_bytes()),
        ("hlc_logical", &0u32.to_le_bytes()),
        ("nonce", b"v1-nonce".as_slice()),
    ]);
    use jig_core::request_auth::headers as h;
    let headers = [
        (h::DID, alice.did_string()),
        (h::HLC_WALL_MS, wall.to_string()),
        (h::HLC_LOGICAL, "0".to_string()),
        (h::NONCE, "v1-nonce".to_string()),
        (
            h::SIGNATURE,
            base64::engine::general_purpose::STANDARD.encode(alice.sign(v1.as_bytes()).to_bytes()),
        ),
    ];
    let got = send_proof(&format!("{}{path}", server.http_url()), &headers).await;
    assert_eq!(got, (401, "PROOF_VERSION_UNSUPPORTED".to_string()));
}
