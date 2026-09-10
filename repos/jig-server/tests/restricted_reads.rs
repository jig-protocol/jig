//! `visibility = "restricted"` gates reads, as the CLI's `--help` has always
//! claimed.
//!
//! Channels here are created through the real admin endpoint and memberships
//! are written by the real `member-add` effect, so a refusal below is a refusal
//! of state production would have produced — not of a hand-seeded row.

use axum::http::StatusCode;

mod support;
use support::{Identity, TestServer, history_path};

#[tokio::test]
async fn a_non_member_cannot_read_a_restricted_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    let (status, body) = server
        .send(&server.sign_get(&stranger, &history_path("#private")))
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_A_MEMBER");
}

#[tokio::test]
async fn a_member_can_read_a_restricted_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let member = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    server.add_member(&owner, "#private", &member).await;

    let (status, body) = server
        .send(&server.sign_get(&member, &history_path("#private")))
        .await;

    assert_eq!(status, StatusCode::OK, "body={body}");
}

#[tokio::test]
async fn an_owner_can_read_their_own_restricted_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    let (status, body) = server
        .send(&server.sign_get(&owner, &history_path("#private")))
        .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "an owner must not be locked out of the channel they created: body={body}"
    );
}

#[tokio::test]
async fn an_open_channel_is_readable_by_any_authenticated_caller() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server.create_channel(&owner, "#open", "open").await;

    let (status, body) = server
        .send(&server.sign_get(&stranger, &history_path("#open")))
        .await;

    assert_eq!(status, StatusCode::OK, "body={body}");
}

/// A channel with no local row reads as an empty timeline, not a refusal:
/// federated channels live on a peer and have blocks here but no row, and
/// their backfill must keep working. (The row, once it exists, is enforced.)
#[tokio::test]
async fn reading_a_channel_with_no_local_row_is_not_refused() {
    let server = TestServer::authenticated();
    let caller = Identity::new(1);

    let (status, body) = server
        .send(&server.sign_get(&caller, &history_path("#remote-only")))
        .await;

    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.as_array().is_some_and(Vec::is_empty), "body={body}");
}

/// The migration escape hatch disables the whole read pipeline, gate 3
/// included: with no verified caller there is nobody to authorize.
#[tokio::test]
async fn the_escape_hatch_reads_restricted_channels_unauthenticated() {
    let server = TestServer::unauthenticated();
    let owner = Identity::new(1);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    let (status, body) = server.send_unsigned(&history_path("#private")).await;

    assert_eq!(status, StatusCode::OK, "body={body}");
}

// ---- The write side of the same gate -----------------------------------------
//
// A read gate on memberships is only as strong as the write gate on
// memberships. `member-add` is in the default allow-list, and the public
// `POST /api/v1/blocks` accepts any well-signed block — so without a write-side
// check, a stranger self-adds in one request and reads in the next.

use jig_client::blocks::build_member_add;
use jig_core::HlcTimestamp;

fn self_join(who: &Identity, slug: &str) -> jig_client::blocks::BuiltBlock {
    let me = who.as_client();
    build_member_add(
        &me,
        slug,
        &me.did_string(),
        HlcTimestamp::now_wall(me.did().clone()),
    )
}

#[tokio::test]
async fn a_stranger_cannot_self_join_a_restricted_channel_through_the_public_submit_path() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    let (status, body) = server.try_submit(&self_join(&stranger, "#private")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_CHANNEL_OWNER");

    // And the read that a successful self-join would have unlocked stays shut.
    let (status, body) = server
        .send(&server.sign_get(&stranger, &history_path("#private")))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
}

/// `jig channel join` goes through the admin endpoint; same rule, same answer.
#[tokio::test]
async fn a_stranger_cannot_self_join_a_restricted_channel_through_the_admin_endpoint() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    let (status, body) = server
        .try_add_member(&stranger, "#private", &stranger)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_CHANNEL_OWNER");
}

/// Being a member is not being the owner: a member cannot invite others into a
/// restricted channel.
#[tokio::test]
async fn a_member_cannot_add_others_to_a_restricted_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let member = Identity::new(2);
    let friend = Identity::new(3);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    server.add_member(&owner, "#private", &member).await;

    let (status, body) = server.try_add_member(&member, "#private", &friend).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_CHANNEL_OWNER");
}

/// Open channels keep IRC `/join` semantics: anyone may add themselves.
#[tokio::test]
async fn anyone_can_self_join_an_open_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server.create_channel(&owner, "#open", "open").await;

    let (status, body) = server.try_submit(&self_join(&stranger, "#open")).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}

/// Self-join is the only thing a non-owner may do; adding *someone else* to an
/// open channel is still the owner's call. Membership drives delivery (fanout
/// and bridge dispatch), so letting strangers enrol third parties would let
/// them subscribe anyone to anything.
#[tokio::test]
async fn a_stranger_cannot_add_someone_else_to_an_open_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    let victim = Identity::new(3);
    server.create_channel(&owner, "#open", "open").await;

    let (status, body) = server.try_add_member(&stranger, "#open", &victim).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_CHANNEL_OWNER");
}

// ---- The listing ---------------------------------------------------------------
//
// A 403 on the timeline conceals nothing if `GET /api/v1/channels` still names
// every restricted channel — and its owner_did — to whoever asks.

fn listed_slugs(body: &serde_json::Value) -> Vec<String> {
    body["channels"]
        .as_array()
        .expect("channels array")
        .iter()
        .filter_map(|c| c["slug"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn the_channel_list_hides_restricted_channels_from_non_members() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    let private_owner = Identity::new(3);
    server.create_channel(&owner, "#open", "open").await;
    server
        .create_channel(&private_owner, "#private", "restricted")
        .await;

    let (status, body) = server
        .send(&server.sign_get(&stranger, "/api/v1/channels"))
        .await;
    assert_eq!(status, StatusCode::OK, "body={body}");

    let slugs = listed_slugs(&body);
    assert!(
        slugs.contains(&"#open".to_string()),
        "open channels stay visible: {slugs:?}"
    );
    assert!(
        !slugs.contains(&"#private".to_string()),
        "a restricted channel must not be listed to a non-member — listing it \
         leaks both its existence and its owner_did: {slugs:?}"
    );
    assert!(
        !body
            .to_string()
            .contains(&private_owner.did().to_did_jig_string()),
        "the restricted channel's owner_did must not appear anywhere in a \
         stranger's listing: {body}"
    );
}

#[tokio::test]
async fn the_channel_list_shows_restricted_channels_to_their_members() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let member = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    server.add_member(&owner, "#private", &member).await;

    let (status, body) = server
        .send(&server.sign_get(&member, "/api/v1/channels"))
        .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    let slugs = listed_slugs(&body);
    assert!(
        slugs.contains(&"#private".to_string()),
        "members see their channels: {slugs:?}"
    );
}

#[tokio::test]
async fn the_channel_list_shows_owners_their_own_restricted_channels() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    let (status, body) = server
        .send(&server.sign_get(&owner, "/api/v1/channels"))
        .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    let slugs = listed_slugs(&body);
    assert!(
        slugs.contains(&"#private".to_string()),
        "owners see their channels: {slugs:?}"
    );
}

/// Under the escape hatch nobody is authenticated, so nobody is filtered —
/// the pre-authentication listing, exactly as documented.
#[tokio::test]
async fn the_escape_hatch_lists_every_channel() {
    let server = TestServer::unauthenticated();
    let owner = Identity::new(1);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    let (status, body) = server.send_unsigned("/api/v1/channels").await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(listed_slugs(&body).contains(&"#private".to_string()));
}

// ---- Posting ---------------------------------------------------------------------
//
// "Membership-gated" cuts both ways. A restricted channel whose members can be
// messaged by anyone with a keypair is not a private club, it is a private
// club with an open letterbox.

use jig_client::blocks::build_text_render;

fn text(who: &Identity, slug: &str, body: &str) -> jig_client::blocks::BuiltBlock {
    let me = who.as_client();
    build_text_render(&me, slug, body, HlcTimestamp::now_wall(me.did().clone()))
}

#[tokio::test]
async fn a_stranger_cannot_post_to_a_restricted_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    // The timeline already holds the channel-create block; what matters is
    // that the refused post adds nothing to it.
    let timeline_len = |body: &serde_json::Value| body.as_array().map_or(0, Vec::len);
    let (_, before) = server
        .send(&server.sign_get(&owner, &history_path("#private")))
        .await;

    let (status, body) = server
        .try_submit(&text(&stranger, "#private", "psst"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_A_MEMBER");

    let (status, after) = server
        .send(&server.sign_get(&owner, &history_path("#private")))
        .await;
    assert_eq!(status, StatusCode::OK, "body={after}");
    assert_eq!(
        timeline_len(&after),
        timeline_len(&before),
        "a refused block must not persist"
    );
}

#[tokio::test]
async fn members_and_the_owner_can_post_to_a_restricted_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let member = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    server.add_member(&owner, "#private", &member).await;

    let (status, body) = server
        .try_submit(&text(&owner, "#private", "welcome"))
        .await;
    assert_eq!(status, StatusCode::OK, "owner: body={body}");
    let (status, body) = server
        .try_submit(&text(&member, "#private", "thanks"))
        .await;
    assert_eq!(status, StatusCode::OK, "member: body={body}");
}

#[tokio::test]
async fn anyone_can_post_to_an_open_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server.create_channel(&owner, "#open", "open").await;

    let (status, body) = server.try_submit(&text(&stranger, "#open", "hello")).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}

// ---- Block by CID -------------------------------------------------------------
//
// A CID is a content hash, not a secret: it appears in acks, receipts,
// delivery frames and logs. `GET /api/v1/blocks/:cid` must run the same gates
// as the timeline the block lives in, or the timeline gate is a detour.

async fn post_and_get_cid(server: &TestServer, who: &Identity, slug: &str) -> String {
    let (status, body) = server.try_submit(&text(who, slug, "for the record")).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    body["block_cid"]
        .as_str()
        .expect("block_cid in ack")
        .to_string()
}

#[tokio::test]
async fn a_block_in_a_restricted_channel_cannot_be_fetched_by_cid_by_a_non_member() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    let cid = post_and_get_cid(&server, &owner, "#private").await;

    let (status, body) = server
        .send(&server.sign_get(&stranger, &format!("/api/v1/blocks/{cid}")))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_A_MEMBER");
}

#[tokio::test]
async fn a_block_in_a_restricted_channel_can_be_fetched_by_cid_by_a_member() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let member = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    server.add_member(&owner, "#private", &member).await;
    let cid = post_and_get_cid(&server, &owner, "#private").await;

    let (status, body) = server
        .send(&server.sign_get(&member, &format!("/api/v1/blocks/{cid}")))
        .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["block_cid"], cid);
}

#[tokio::test]
async fn fetching_a_block_by_cid_requires_a_proof() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    server.create_channel(&owner, "#open", "open").await;
    let cid = post_and_get_cid(&server, &owner, "#open").await;

    let (status, body) = server.send_unsigned(&format!("/api/v1/blocks/{cid}")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body}");
    assert_eq!(body["code"], "AUTH_REQUIRED");
}

#[tokio::test]
async fn a_block_in_an_open_channel_can_be_fetched_by_cid_by_anyone_authenticated() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server.create_channel(&owner, "#open", "open").await;
    let cid = post_and_get_cid(&server, &owner, "#open").await;

    let (status, body) = server
        .send(&server.sign_get(&stranger, &format!("/api/v1/blocks/{cid}")))
        .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}

// ---- The key that names the channel ------------------------------------------
//
// Found in review: the write gate read `metadata.channel` while the stored
// `channel_id` fell back to `metadata.slug`, so a block could be authorized
// against no channel and then land in a restricted one. The key is now chosen
// by kind, and these pin it on the wire.

fn text_with_metadata(
    who: &Identity,
    metadata: serde_json::Value,
) -> jig_client::blocks::BuiltBlock {
    let me = who.as_client();
    jig_client::blocks::build_with_metadata(
        &me,
        jig_core::BlockKind::TextRender,
        HlcTimestamp::now_wall(me.did().clone()),
        metadata,
    )
}

/// A `text-render` naming a restricted channel under `slug` instead of
/// `channel` must not land in that channel's timeline.
#[tokio::test]
async fn a_stranger_cannot_smuggle_a_post_into_a_restricted_channel_under_the_slug_key() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    let (_, before) = server
        .send(&server.sign_get(&owner, &history_path("#private")))
        .await;

    let block = text_with_metadata(
        &stranger,
        serde_json::json!({"slug": "#private", "body": "psst"}),
    );
    let (status, body) = server.try_submit(&block).await;
    // Whatever the server makes of a channel-less text-render, it must not
    // be accepted INTO #private.
    let (_, after) = server
        .send(&server.sign_get(&owner, &history_path("#private")))
        .await;
    assert_eq!(
        after.as_array().map_or(0, Vec::len),
        before.as_array().map_or(0, Vec::len),
        "a block naming the channel only under `slug` must not enter it: submit={status} {body}"
    );
}

/// Both keys present: the gate and the store must agree on which one counts.
#[tokio::test]
async fn a_post_carrying_both_keys_is_gated_on_the_key_it_is_stored_under() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    server.create_channel(&owner, "#open", "open").await;
    let (_, before) = server
        .send(&server.sign_get(&owner, &history_path("#private")))
        .await;

    let block = text_with_metadata(
        &stranger,
        serde_json::json!({"channel": "#open", "slug": "#private", "body": "psst"}),
    );
    let (status, body) = server.try_submit(&block).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "posting to #open is allowed: {body}"
    );

    let (_, after) = server
        .send(&server.sign_get(&owner, &history_path("#private")))
        .await;
    assert_eq!(
        after.as_array().map_or(0, Vec::len),
        before.as_array().map_or(0, Vec::len),
        "the block was gated as #open and must be stored as #open, not #private"
    );
}

// ---- Replay of an accepted control-plane block ---------------------------------

/// The owner's member-add is genuine and stays genuine. What must not stay is
/// its effect: once the owner has removed the member, re-submitting the
/// captured block must not put them back.
#[tokio::test]
async fn replaying_an_accepted_member_add_does_not_undo_a_revocation() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let member = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    let by = owner.as_client();
    let block = build_member_add(
        &by,
        "#private",
        &member.did().to_did_jig_string(),
        HlcTimestamp::now_wall(by.did().clone()),
    );
    let (status, body) = server.try_submit(&block).await;
    assert_eq!(status, StatusCode::OK, "owner enrols member: {body}");
    let (status, _) = server
        .send(&server.sign_get(&member, &history_path("#private")))
        .await;
    assert_eq!(status, StatusCode::OK, "precondition: member can read");

    server.revoke_membership("#private", &member);

    let (status, body) = server.try_submit(&block).await;
    assert_eq!(status, StatusCode::CONFLICT, "replay: {body}");
    assert_eq!(body["code"], "DUPLICATE_BLOCK");
    let (status, body) = server
        .send(&server.sign_get(&member, &history_path("#private")))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the revocation must hold: {body}"
    );
}

// ---- Archived channels ----------------------------------------------------------
//
// Found in review: "no local row → allow" (there for federated channels)
// read an ARCHIVED restricted channel as absent, because the live-channel
// lookup filters archived rows out. Archiving is a soft delete that keeps
// every block, so the row — and its visibility and owner — must keep
// governing reads.

#[tokio::test]
async fn archiving_a_restricted_channel_does_not_open_its_history() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let member = Identity::new(2);
    let stranger = Identity::new(3);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    server.add_member(&owner, "#private", &member).await;
    let cid = post_and_get_cid(&server, &owner, "#private").await;

    server.archive_channel(&owner, "#private").await;

    let (status, body) = server
        .send(&server.sign_get(&stranger, &history_path("#private")))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "history after archive: {body}"
    );
    assert_eq!(body["code"], "NOT_A_MEMBER");

    let (status, body) = server
        .send(&server.sign_get(&stranger, &format!("/api/v1/blocks/{cid}")))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "fetch-by-CID after archive: {body}"
    );

    // The owner keeps their history; an archived channel has no members, so
    // the member does not — retired means retired, and the owner is who
    // "every block survives" is for.
    let (status, body) = server
        .send(&server.sign_get(&owner, &history_path("#private")))
        .await;
    assert_eq!(status, StatusCode::OK, "owner after archive: {body}");
    let (status, _) = server
        .send(&server.sign_get(&member, &history_path("#private")))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a former member after archive"
    );
}
