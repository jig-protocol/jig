//! A channel route or subscribe names its channel by id or by slug
//! (JEP-0005 rule 1). The id names one channel on any server; a slug names
//! only a channel this server sequences, so a carried channel that shares a
//! local slug is reached by its id alone.

mod support;
use axum::http::StatusCode;
use jig_client::blocks::build_channel_archive;
use jig_core::HlcTimestamp;
use jig_pipeline::fanout::DeliveryPolicy;
use jig_pipeline::persist::StoredReceipt;
use jig_pipeline::{Frame, Scope};
use support::ws::WsClient;
use support::{Identity, TestServer, encode_slug};

/// The channel GET routes, by the path suffix after the channel.
const READ_ROUTES: [&str; 3] = ["blocks", "records", "members"];

async fn get(
    server: &TestServer,
    who: &Identity,
    channel: &str,
    route: &str,
) -> (StatusCode, serde_json::Value) {
    let path = format!("/api/v1/channels/{}/{route}", encode_slug(channel));
    server.send_full(&server.sign_get(who, &path)).await
}

fn delivery_cids(timeline: &serde_json::Value) -> Vec<String> {
    timeline
        .as_array()
        .expect("a timeline")
        .iter()
        .map(|b| b["delivery_cid"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn every_channel_read_route_gives_the_same_channel_by_id_and_by_slug() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    server.create_channel(&owner, "#room", "open").await;
    server.post_text(&owner, "#room", "hello").await;
    server.create_channel(&owner, "#sealed", "restricted").await;
    server.post_text(&owner, "#sealed", "sealed hello").await;

    for slug in ["#room", "#sealed"] {
        let id = server.channel_id(slug);
        for route in READ_ROUTES.iter().copied().chain(["mls/group-info"]) {
            let by_slug = get(&server, &owner, slug, route).await;
            let by_id = get(&server, &owner, &id, route).await;
            if slug == "#room" && route == "mls/group-info" {
                assert_eq!(by_slug.0, StatusCode::NOT_FOUND, "{slug} {route}");
            } else {
                assert_eq!(by_slug.0, StatusCode::OK, "{slug} {route}: {}", by_slug.1);
            }
            assert_eq!(by_id.0, by_slug.0, "{slug} {route}");
            if by_slug.0 == StatusCode::OK {
                assert_eq!(by_id.1, by_slug.1, "{slug} {route}");
            }
        }
        let (_, history) = get(&server, &owner, &id, "blocks").await;
        assert!(!delivery_cids(&history).is_empty(), "{slug} has history");
    }
}

#[tokio::test]
async fn a_carried_channel_sharing_a_local_slug_is_reached_only_by_its_id() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let theirs = Identity::new(2);
    server.create_channel(&owner, "#shared", "open").await;
    server.post_text(&owner, "#shared", "local").await;
    let (carried_id, carried_block) = server.carry_channel("#shared", &theirs);
    let carried_delivery = format!("delivery:{}", carried_block.cid);

    let (status, local) = get(&server, &owner, "#shared", "blocks").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!delivery_cids(&local).contains(&carried_delivery));
    let (status, carried) = get(&server, &owner, &carried_id, "blocks").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(delivery_cids(&carried), vec![carried_delivery]);

    let (_, local) = get(&server, &owner, "#shared", "members").await;
    let (_, carried) = get(&server, &owner, &carried_id, "members").await;
    assert_eq!(local["members"][0]["did"], owner.did().to_did_jig_string());
    assert_eq!(carried["slug"], "#shared");
    assert_eq!(carried["members"].as_array().unwrap().len(), 1);
    assert_eq!(
        carried["members"][0]["did"],
        theirs.did().to_did_jig_string()
    );

    let (status, body) = get(&server, &owner, "#shared", "mls/group-info").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the local #shared is plain");
    assert_eq!(body["code"], "NOT_ENCRYPTED");
    let (status, body) = get(&server, &owner, &carried_id, "mls/group-info").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["epoch"], 7);
}

/// A reference that is neither an id in its one spelling nor a slug names no
/// channel, answered as an unknown slug is.
#[tokio::test]
async fn a_garbage_reference_is_an_unknown_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    server.create_channel(&owner, "#room", "open").await;
    let shouted = server.channel_id("#room").to_uppercase();

    for garbage in ["notacid", shouted.as_str()] {
        let (status, body) = get(&server, &owner, garbage, "members").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{garbage}");
        assert_eq!(body["code"], "UNKNOWN_CHANNEL", "{garbage}");
        let (status, body) = get(&server, &owner, garbage, "mls/group-info").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{garbage}");
        assert_eq!(body["code"], "NOT_ENCRYPTED", "{garbage}");
        // History has always answered an unknown channel with an empty page.
        for route in ["blocks", "records"] {
            let (status, body) = get(&server, &owner, garbage, route).await;
            assert_eq!(status, StatusCode::OK, "{garbage} {route}");
            assert_eq!(body, serde_json::json!([]), "{garbage} {route}");
        }
    }
}

#[tokio::test]
async fn the_channel_op_routes_take_the_id_of_the_channel_the_block_names() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let joiner = Identity::new(2);
    server.create_channel(&owner, "#room", "open").await;
    let id = server.channel_id("#room");

    let block = server.member_add_block(&owner, "#room", &joiner);
    let (status, body) = server
        .post_channel_op(&format!("/api/v1/channels/{id}/members"), &block)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        server
            .store()
            .is_member_by_id(&id, joiner.did().as_str())
            .unwrap()
    );

    // A path naming another channel, or none, is the old mismatch.
    let (carried_id, _) = server.carry_channel("#room", &joiner);
    for path in [carried_id.as_str(), "notacid", "%23elsewhere"] {
        let block = server.member_add_block(&owner, "#room", &Identity::new(3));
        let (status, body) = server
            .post_channel_op(&format!("/api/v1/channels/{path}/members"), &block)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        assert_eq!(body["code"], "SLUG_MISMATCH", "{path}");
    }

    let me = owner.as_client();
    let archive = build_channel_archive(&me, "#room", HlcTimestamp::now_wall(me.did().clone()));
    let (status, body) = server
        .post_channel_op(&format!("/api/v1/channels/{carried_id}/archive"), &archive)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "SLUG_MISMATCH");
    let (status, body) = server
        .post_channel_op(&format!("/api/v1/channels/{id}/archive"), &archive)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(server.store().get_channel_by_id(&id).unwrap().is_none());
    assert!(
        server
            .store()
            .get_channel_by_id(&carried_id)
            .unwrap()
            .is_some(),
        "the carried #room is untouched"
    );
}

#[tokio::test]
async fn a_subscribe_by_channel_id_receives_the_channels_blocks() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    server.create_channel(&owner, "#room", "open").await;
    let url = server.serve_ws().await;
    let mut sub = WsClient::connect(&url).await;
    let refusal = sub
        .subscribe_scope(
            &owner,
            Scope::ChannelId {
                channel_id: server.channel_id("#room"),
            },
        )
        .await;
    assert!(refusal.is_none(), "{refusal:?}");
    server.post_text(&owner, "#room", "by id").await;
    assert!(sub.next_block().await.is_some());
}

#[tokio::test]
async fn a_subscribe_by_a_non_canonical_channel_id_is_refused() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    server.create_channel(&owner, "#room", "open").await;
    let url = server.serve_ws().await;
    for channel_id in [
        "notacid".to_string(),
        server.channel_id("#room").to_uppercase(),
    ] {
        let mut sub = WsClient::connect(&url).await;
        match sub
            .subscribe_scope(
                &owner,
                Scope::ChannelId {
                    channel_id: channel_id.clone(),
                },
            )
            .await
        {
            Some(Frame::Error { status, code, .. }) => {
                assert_eq!(
                    (status, code.as_str()),
                    (Some(400), "BAD_SCOPE"),
                    "{channel_id}"
                );
            }
            other => panic!("{channel_id}: expected a refusal, got {other:?}"),
        }
    }
    assert_eq!(server.fanout().local_subscription_count().await, 0);
}

/// A slug subscribe follows the local channel of that slug; it never
/// follows a carried channel, which only its id reaches. A slug that names
/// only a carried channel is refused, naming the id, rather than left to
/// wait for a creation that never comes here.
#[tokio::test]
async fn a_slug_subscribe_never_reaches_a_carried_channel() {
    let server = TestServer::authenticated();
    let owner = Identity::new(1);
    let theirs = Identity::new(2);
    server.create_channel(&owner, "#shared", "open").await;
    let url = server.serve_ws().await;

    for slug in ["#shared", "#faraway"] {
        let (carried_id, block) = server.carry_channel(slug, &theirs);
        let mut by_slug = WsClient::connect(&url).await;
        let refusal = by_slug.subscribe(&owner, slug).await;
        if slug == "#faraway" {
            match refusal {
                Some(Frame::Error { code, message, .. }) => {
                    assert_eq!(code, "CARRIED_CHANNEL");
                    assert!(message.contains(&carried_id), "{message}");
                }
                other => panic!("{slug}: expected a refusal naming the id, got {other:?}"),
            }
        } else {
            assert!(refusal.is_none(), "{refusal:?}");
        }
        let mut by_id = WsClient::connect(&url).await;
        let refusal = by_id
            .subscribe_scope(
                &owner,
                Scope::ChannelId {
                    channel_id: carried_id.clone(),
                },
            )
            .await;
        assert!(refusal.is_none(), "{refusal:?}");

        let channel = server
            .store()
            .get_channel_by_id(&carried_id)
            .unwrap()
            .unwrap();
        let receipt = StoredReceipt {
            cid: format!("receipt {slug}"),
            block_cid: block.cid.clone(),
            server_id: "elsewhere".to_string(),
            receipt_bytes: Vec::new(),
            render_hash: None,
            produced_at: 1,
        };
        server
            .fanout()
            .broadcast_local_only(
                &block,
                &receipt,
                Some(&DeliveryPolicy::for_channel(&channel, Vec::new())),
            )
            .await
            .unwrap();
        assert_eq!(
            by_id.next_block().await,
            Some(format!("delivery:{}", block.cid)),
            "{slug}: the carried block was fanned out"
        );
        assert!(
            by_slug.no_block().await,
            "{slug}: not to the slug subscriber"
        );
    }
}
