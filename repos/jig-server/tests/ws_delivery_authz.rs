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
    // A second subscriber who IS allowed to receive: proof that the block
    // after revocation was actually fanned out, so the member's silence is a
    // refusal and not a delivery that never happened.
    let mut witness = WsClient::connect(&url).await;
    assert!(witness.subscribe(&owner, "#private").await.is_none());

    server
        .post_text(&owner, "#private", "before revocation")
        .await;
    assert!(
        sub.next_block().await.is_some(),
        "precondition: a member receives before revocation"
    );
    assert!(witness.next_block().await.is_some());

    server.revoke_membership("#private", &member);
    server
        .post_text(&owner, "#private", "after revocation")
        .await;
    assert!(
        witness.next_block().await.is_some(),
        "the block was fanned out"
    );
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
    let mut witness = WsClient::connect(&url).await;
    assert!(witness.subscribe(&owner, "#private").await.is_none());
    server.post_text(&owner, "#private", "secret").await;
    assert!(
        witness.next_block().await.is_some(),
        "the block was fanned out"
    );
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

/// A connection holds one subscription. Re-subscribing must replace it in
/// the fanout map, not leave the old one delivering under its old scope and
/// identity until the process exits.
#[tokio::test]
async fn re_subscribing_replaces_the_previous_subscription() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let member = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    server.create_channel(&owner, "#open", "open").await;
    server.add_member(&owner, "#private", &member).await;

    let url = server.serve_ws().await;
    let mut sub = WsClient::connect(&url).await;
    assert!(sub.subscribe(&member, "#private").await.is_none());
    assert!(sub.subscribe(&member, "#open").await.is_none());
    assert_eq!(
        server.fanout().local_subscription_count().await,
        1,
        "the first subscription must have been removed, not orphaned"
    );

    // The old scope no longer delivers on this socket…
    server.post_text(&owner, "#private", "old scope").await;
    assert!(
        sub.no_block().await,
        "#private must not reach a socket now on #open"
    );
    // …and the new one does.
    server.post_text(&owner, "#open", "new scope").await;
    assert!(sub.next_block().await.is_some());
}

/// A write-gate refusal over WSS carries the same status and code as over
/// REST, so a client sees one word for "not a member here" on either pipe.
#[tokio::test]
async fn a_refused_post_over_wss_carries_the_rest_status_and_code() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);
    server
        .create_channel(&owner, "#private", "restricted")
        .await;

    let url = server.serve_ws().await;
    let mut ws = WsClient::connect(&url).await;
    match ws.submit_text(&stranger, "#private", "psst").await {
        Frame::Error { status, code, .. } => {
            assert_eq!(status, Some(403));
            assert_eq!(code, "NOT_A_MEMBER");
        }
        other => panic!("expected an error frame, got {other:?}"),
    }
}

/// Archiving is a control-plane block that lands in the channel's own
/// timeline. It must be delivered under the channel's policy — the archived
/// row still says who may read — not fanned out to everyone because the
/// live-channel lookup no longer finds a row.
#[tokio::test]
async fn the_archive_block_of_a_restricted_channel_reaches_only_its_readers() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let stranger = Identity::new(2);

    let url = server.serve_ws().await;
    let mut early = WsClient::connect(&url).await;
    assert!(early.subscribe(&stranger, "#private").await.is_none());

    server
        .create_channel(&owner, "#private", "restricted")
        .await;
    let mut witness = WsClient::connect(&url).await;
    assert!(witness.subscribe(&owner, "#private").await.is_none());

    server.archive_channel(&owner, "#private").await;
    assert!(
        witness.next_block().await.is_some(),
        "the owner sees their own archive block"
    );
    assert!(
        early.no_block().await,
        "a stranger must not learn of the channel from its archive block"
    );

    // And a fresh subscribe to the archived restricted channel is refused,
    // exactly as it was while the channel was live.
    let mut late = WsClient::connect(&url).await;
    match late.subscribe(&stranger, "#private").await {
        Some(Frame::Error { status, code, .. }) => {
            assert_eq!(status, Some(403));
            assert_eq!(code, "NOT_A_MEMBER");
        }
        other => panic!("expected a 403 error frame, got {other:?}"),
    }
}
