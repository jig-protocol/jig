//! A `member-remove` ends the membership it names (JEP-0002 rule 11).
//!
//! A channel is named by slug, and two servers can each have a `#team`. A
//! member's leave written on one server names the membership it ends there,
//! so the same signed bytes handed to the other server, where the member
//! also belongs to a `#team`, end nothing: the membership there began with a
//! different block.

use integration_tests::harness::*;
use jig_client::blocks::{build_member_remove, ends};
use jig_client::read_auth::{ReadProof, signable_path};
use serde_json::Value;

/// The `since` the server lists for `did` in `slug`, read as `who`.
async fn since_of(
    server: &TestJigServer,
    who: &jig_client::Identity,
    slug: &str,
    did: &str,
) -> Option<String> {
    let url = format!(
        "{}/api/v1/channels/{}/members",
        server.http_url(),
        slug.replace('#', "%23")
    );
    let audience = audience_for(&url).await;
    let proof = ReadProof::sign(who, &audience, "GET", signable_path(&url));
    let mut req = reqwest::Client::new().get(&url);
    for (name, value) in proof.headers() {
        req = req.header(name, value);
    }
    let body: Value = req.send().await.unwrap().json().await.unwrap();
    body["members"]
        .as_array()?
        .iter()
        .find(|m| m["did"] == did)
        .and_then(|m| m["since"].as_str().map(str::to_string))
}

async fn is_member(server: &TestJigServer, slug: &str, did: &str) -> bool {
    server.state.ingest_ctx.store.is_member(slug, did).unwrap()
}

#[tokio::test]
async fn a_leave_replayed_on_another_server_ends_nothing_there() {
    let a = TestJigServer::start_with_full_kinds().await.unwrap();
    let b = TestJigServer::start_with_full_kinds().await.unwrap();
    let (owner_a, _da) = test_identity_with_dir();
    let (owner_b, _db) = test_identity_with_dir();
    let (member, _dm) = test_identity_with_dir();
    let did = member.did_string();

    a.create_channel(&owner_a, "#team", "open").await.unwrap();
    b.create_channel(&owner_b, "#team", "open").await.unwrap();
    // The member joins both, each by its own `member-add`. The two are
    // stamped a millisecond apart, so their CIDs differ however fast they go.
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let joined_a = a.add_member_at(&member, "#team", &did, now).await.unwrap();
    let joined_b = b
        .add_member_at(&member, "#team", &did, now + 1)
        .await
        .unwrap();
    assert_ne!(joined_a, joined_b);
    assert_eq!(
        since_of(&a, &member, "#team", &did).await,
        Some(joined_a.clone())
    );
    assert_eq!(since_of(&b, &member, "#team", &did).await, Some(joined_b));

    // It leaves A, naming the membership it ends there.
    let leave = build_member_remove(
        &member,
        "#team",
        &did,
        ends(Some(&joined_a)),
        jig_core::HlcTimestamp::now_wall(member.did().clone()),
    );
    a.submit_block(&leave).await.unwrap();
    assert!(!is_member(&a, "#team", &did).await);

    // The same bytes, handed to B, are refused, and the member stays.
    let replayed = b.submit_block(&leave).await.unwrap_err().to_string();
    assert!(
        replayed.contains("409") && replayed.contains("REMOVE_ENDS_STALE"),
        "{replayed}"
    );
    assert!(is_member(&b, "#team", &did).await);
}
