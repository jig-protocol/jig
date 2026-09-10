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
    let proof = ReadProof::sign(who, "GET", signable_path(url));
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
    let (alice, _a) = test_identity_with_dir();
    let (bob, _b) = test_identity_with_dir();
    let (carol, _c) = test_identity_with_dir();
    server
        .create_channel(&alice, "#private", "restricted")
        .await
        .expect("create");
    server
        .add_member(&alice, "#private", &bob.did_string())
        .await
        .expect("add bob");

    let history = format!("{}/api/v1/channels/%23private/blocks", server.http_url());
    let (status, _) = signed_get(&bob, &history).await;
    assert_eq!(status, 200, "bob is a member");
    let (status, body) = signed_get(&carol, &history).await;
    assert_eq!(status, 403, "carol is not: body={body}");
    assert_eq!(body["code"], "NOT_A_MEMBER");

    let listing = format!("{}/api/v1/channels", server.http_url());
    let (_, body) = signed_get(&carol, &listing).await;
    assert!(
        !body.to_string().contains("#private"),
        "carol's listing must not name the channel: {body}"
    );
}
