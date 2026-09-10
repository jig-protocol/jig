//! Live delivery over WSS runs the same read gate as the REST timeline — on
//! every delivery, not once at subscribe time.
//!
//! Real server on an ephemeral port, real signed subscribes, real blocks
//! through the real submit path. A block that does not arrive here did not
//! arrive because fanout refused it, not because a stub swallowed it.

mod support;
use jig_pipeline::Frame;
use support::ws::WsClient;
use support::{Identity, TestServer};

#[tokio::test]
async fn a_member_receives_live_blocks_on_a_restricted_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let member = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    server.add_member(&owner, "#private", &member).await;

    let url = server.serve_ws().await;
    let mut sub = WsClient::connect(&url).await;
    assert!(sub.subscribe(&member, "#private").await.is_none());

    server.post_text(&owner, "#private", "hello member").await;
    assert!(sub.next_block().await.is_some(), "a member must receive");
}

/// THE test this task exists for. The subscription is never touched; only
/// the membership row goes away. Delivery must stop with it.
#[tokio::test]
async fn revoking_membership_stops_delivery_on_a_live_subscription() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let member = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    server.add_member(&owner, "#private", &member).await;

    let url = server.serve_ws().await;
    let mut sub = WsClient::connect(&url).await;
    assert!(sub.subscribe(&member, "#private").await.is_none());

    server
        .post_text(&owner, "#private", "before revocation")
        .await;
    assert!(
        sub.next_block().await.is_some(),
        "precondition: a member receives before revocation"
    );

    server.revoke_membership("#private", &member);
    server
        .post_text(&owner, "#private", "after revocation")
        .await;
    assert!(
        sub.no_block().await,
        "delivery must stop after revocation — a subscription authorized once at \
         subscribe time would keep delivering to a revoked member forever"
    );
}

/// A stranger cannot even open the subscription: the same 403 the REST
/// timeline gives, before any block is posted.
#[tokio::test]
async fn a_stranger_is_refused_at_subscribe_time() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    let url = server.serve_ws().await;
    let mut sub = WsClient::connect(&url).await;
    match sub.subscribe(&stranger, "#private").await {
        Some(Frame::Error { status, code, .. }) => {
            assert_eq!(status, Some(403));
            assert_eq!(code, "NOT_A_MEMBER");
        }
        other => panic!("expected a 403 error frame, got {other:?}"),
    }
}

/// Subscribing before the channel exists is allowed — federated channels
/// routinely have no local row — so the subscribe-time check alone would let
/// a stranger in early. The delivery-time check is what actually holds.
#[tokio::test]
async fn a_stranger_who_subscribed_early_still_receives_nothing() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);

    let url = server.serve_ws().await;
    let mut sub = WsClient::connect(&url).await;
    assert!(
        sub.subscribe(&stranger, "#private").await.is_none(),
        "subscribing to a not-yet-created channel is allowed"
    );

    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    server.post_text(&owner, "#private", "secret").await;
    assert!(
        sub.no_block().await,
        "a stranger must not receive from a restricted channel however early \
         they subscribed"
    );
}

#[tokio::test]
async fn anyone_receives_live_blocks_on_an_open_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server.create_channel(&owner, "#open", "open").await;

    let url = server.serve_ws().await;
    let mut sub = WsClient::connect(&url).await;
    assert!(sub.subscribe(&stranger, "#open").await.is_none());

    server.post_text(&owner, "#open", "hi all").await;
    assert!(sub.next_block().await.is_some());
}

#[tokio::test]
async fn the_owner_receives_live_blocks_on_their_restricted_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let member = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    server.add_member(&owner, "#private", &member).await;

    let url = server.serve_ws().await;
    let mut sub = WsClient::connect(&url).await;
    assert!(sub.subscribe(&owner, "#private").await.is_none());

    server.post_text(&member, "#private", "hi owner").await;
    assert!(sub.next_block().await.is_some());
}
