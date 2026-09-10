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

/// Reading a channel that does not exist is a 404, not an empty 200. Before
/// this gate a mistyped slug read back as a silent empty timeline.
#[tokio::test]
async fn reading_an_unknown_channel_is_not_found() {
    let server = TestServer::authenticated();
    let caller = Identity::new(1);

    let (status, body) = server
        .send(&server.sign_get(&caller, &history_path("#nowhere")))
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "body={body}");
    assert_eq!(body["code"], "NO_SUCH_CHANNEL");
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
