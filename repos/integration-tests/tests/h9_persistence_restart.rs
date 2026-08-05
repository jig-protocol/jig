//! H9: server state survives a restart.
//!
//! This is the property the whole self-deploy story rests on — a `jig-server`
//! that loses its identity or its history on reboot is not a messaging server.
//! Nothing else in the workspace covers it.
//!
//! Four things must hold across a restart over the same data directory:
//! 1. the server DID is BYTE-identical (clients TOFU-pin it; a new DID breaks
//!    every pin and looks indistinguishable from an impersonation attempt),
//! 2. pre-restart blocks and their receipts are still readable,
//! 3. channels and their memberships survive,
//! 4. the server still accepts and fans out new blocks afterwards.
//!
//! `TestJigServer::restart()` rebinds a NEW ephemeral port, so everything
//! below re-reads `ws_url()` after the restart — only on-disk state carries
//! over, which is exactly what a real reboot gives you.

use std::time::Duration;

use integration_tests::harness::*;
use jig_client::Client;

const SLUG: &str = "#persist";

#[tokio::test]
async fn server_state_survives_restart() {
    let server = TestJigServer::start_with_full_kinds()
        .await
        .expect("start server");
    let owner = test_identity();
    let member = test_identity();

    // ---- pre-restart state -------------------------------------------------
    server
        .create_channel(&owner, SLUG, "open")
        .await
        .expect("create_channel");
    server
        .add_member(&owner, SLUG, &member.did_string())
        .await
        .expect("add_member");
    let msg_cid = server
        .send_text_render(&owner, SLUG, "before restart")
        .await
        .expect("send before restart");

    let did_bytes_before = server.state.server_did.as_bytes().expect("did bytes");
    let did_string_before = server.server_did_string.clone();
    let block_before = server
        .block_for(&msg_cid)
        .expect("block_for")
        .expect("pre-restart block present");
    let receipts_before = server.receipts_for(&msg_cid).expect("receipts_for");
    assert!(
        !receipts_before.is_empty(),
        "precondition: block must have a receipt before we restart"
    );
    let store = &server.state.ingest_ctx.store;
    let channel_before = store
        .get_channel_by_slug(SLUG)
        .expect("get_channel_by_slug")
        .expect("channel present before restart");
    let mut members_before = store
        .list_members(&channel_before.id)
        .expect("list_members before");
    members_before.sort_by(|a, b| a.member_did.cmp(&b.member_did));

    // ---- restart -----------------------------------------------------------
    let server = server.restart().await.expect("restart server");

    // 1. TOFU pin holds: same key on disk ⇒ same DID, byte for byte.
    assert_eq!(
        server.state.server_did.as_bytes().expect("did bytes after"),
        did_bytes_before,
        "server DID must be byte-identical across a restart"
    );
    assert_eq!(server.server_did_string, did_string_before);

    // 2. Blocks and receipts survive.
    let block_after = server
        .block_for(&msg_cid)
        .expect("block_for after")
        .expect("pre-restart block must still be readable after restart");
    assert_eq!(block_after.bundle_bytes, block_before.bundle_bytes);
    assert_eq!(block_after.sender_did, block_before.sender_did);
    assert_eq!(
        block_after.channel_id.as_deref(),
        Some(SLUG),
        "channel_id column must survive the restart intact"
    );
    assert_eq!(
        server.receipts_for(&msg_cid).expect("receipts after"),
        receipts_before,
        "receipts must survive the restart"
    );

    // 3. Channel and memberships survive.
    let store = &server.state.ingest_ctx.store;
    let channel_after = store
        .get_channel_by_slug(SLUG)
        .expect("get_channel_by_slug after")
        .expect("channel must survive restart");
    assert_eq!(channel_after, channel_before);
    let mut members_after = store
        .list_members(&channel_after.id)
        .expect("list_members after");
    members_after.sort_by(|a, b| a.member_did.cmp(&b.member_did));
    assert_eq!(members_after, members_before);
    assert!(
        members_after
            .iter()
            .any(|m| m.member_did == member.did_string()),
        "the added member must still be a member after restart"
    );

    // 4. The restarted server still ingests and fans out. Driven through
    //    `jig_client::Client` — the library jig-cli uses.
    let listener = Client::connect(&server.ws_url(), test_identity())
        .await
        .expect("listener connect");
    let mut stream = listener.subscribe_channel(SLUG).await.expect("subscribe");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (sender_id, sender_dir) = test_identity_with_dir();
    let sender = Client::connect(
        &server.ws_url(),
        load_identity(&sender_dir, &sender_id.did_string()),
    )
    .await
    .expect("sender connect");
    let hlc = jig_core::HlcTimestamp {
        wall_ms: chrono::Utc::now().timestamp_millis() as u64,
        logical: 0,
        server_did: sender_id.did().clone(),
    };
    let block = jig_client::blocks::build_text_render(&sender_id, SLUG, "after restart", hlc);
    let after_cid = sender.submit(block).await.expect("post-restart submit");
    assert_ne!(after_cid, msg_cid);

    let delivered = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timed out waiting for post-restart delivery")
        .expect("stream closed before post-restart delivery");
    let bundle_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &delivered.bundle_b64,
    )
    .expect("bundle b64");
    let (manifest_bytes, _code_bytes): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&bundle_bytes).expect("bundle tuple");
    let manifest: jig_core::BlockManifest =
        serde_json::from_slice(&manifest_bytes).expect("manifest");
    assert_eq!(
        manifest.metadata.get("body").and_then(|v| v.as_str()),
        Some("after restart")
    );

    // And it landed in the (same) store, alongside the pre-restart block.
    assert!(
        server
            .block_for(&after_cid)
            .expect("block_for new")
            .is_some(),
        "post-restart block must be persisted"
    );
    assert!(
        server.block_for(&msg_cid).expect("block_for old").is_some(),
        "pre-restart block must still be there after a post-restart write"
    );
}
