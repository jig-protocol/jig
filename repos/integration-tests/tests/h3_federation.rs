//! H3: Two-server federation chat with cross-server receipt parity.
//!
//! THIS IS THE V0.0.2 ACCEPTANCE TEST. Alice connects to server-a, Bob
//! connects to server-b. Alice sends a text-render block. Bob must
//! receive it via federation within 2s, and both servers' receipts for
//! the block must agree on render_hash.
//!
//! v0.0.2 caveats observed while writing this test:
//! 1. Each server dials the other, proves its DID in the same hello/welcome
//!    a client speaks, and subscribes to the federation stream. The test
//!    doesn't assert the connection is up; we just wait a beat after
//!    add_peer.
//! 2. Each server signs receipts with its OWN server_key — receipt_bytes
//!    differ across servers. We compare render_hash, the deterministic
//!    output marker (None in v0.0.2 — see H1 for the explanation).
//! 3. The receiving server ingests a relayed block like a local submission
//!    (see v0_0_2_federation::ingest_peer_block): it re-verifies the author's
//!    signature, runs the write gate, executes the block and signs its own
//!    receipt.

use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use integration_tests::harness::*;
use jig_core::{Author, BlockKind, BlockManifest, Did, HlcTimestamp};
use jig_pipeline::{
    Envelope, Frame, Scope,
    persist::{StoredBlock, StoredReceipt},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[tokio::test]
async fn two_server_federation_chat_with_receipt_parity() {
    // Boot two TOFU-mode servers (federation handshake doesn't require NS).
    let server_a = TestJigServer::start_copying_peers_channels()
        .await
        .expect("start server_a");
    let server_b = TestJigServer::start_copying_peers_channels()
        .await
        .expect("start server_b");

    // Bidirectional peering.
    server_a.add_peer(&server_b).await.expect("a -> b");
    server_b.add_peer(&server_a).await.expect("b -> a");
    // Give the handshake + subscription dance time to settle.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (alice, _alice_dir) = test_identity_with_dir();
    let (_bob, _bob_dir) = test_identity_with_dir();

    // Alice creates the channel on server_a. The channel-create federates
    // like any block of an open channel, and server_b, which copies its
    // peers' channels (`naively_accept_peer_relayed_creates`), ingests it,
    // so #hello exists on both.
    server_a
        .create_channel(&alice, "#hello", "open")
        .await
        .expect("create_channel");

    // Bob subscribes to #hello on server_b via WSS. The federation stream is
    // for listed peers only, so a client subscribes to the channel; its row
    // reached server_b with alice's channel-create, relayed above.
    let ws_url_b = format!("{}/api/v1/ws", server_b.ws_url());
    let (mut bob_ws, _) = connect_async(&ws_url_b).await.expect("bob ws connect");
    jig_server::v0_0_2_federation::complete_client_handshake(&mut bob_ws, None)
        .await
        .expect("bob handshake");
    // Signed like any real caller: the server refuses an unsigned subscribe.
    let sub = signed_subscribe(
        &alice,
        Scope::Channel {
            slug: "#hello".to_string(),
        },
    );
    bob_ws
        .send(Message::Text(serde_json::to_string(&sub).unwrap().into()))
        .await
        .expect("bob subscribe send");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Alice submits a text-render block to server_a.
    let cid_a = server_a
        .send_text_render(&alice, "#hello", "hi from alice (federated)")
        .await
        .expect("alice send");
    assert!(!cid_a.is_empty());

    // Bob must receive the block on server_b within 3s.
    let mut bob_received_cid: Option<String> = None;
    for _ in 0..10 {
        let timed = tokio::time::timeout(Duration::from_secs(3), bob_ws.next()).await;
        let Ok(Some(Ok(Message::Text(text)))) = timed else {
            continue;
        };
        let env: Envelope = match serde_json::from_str(&text) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if let Frame::Block { bundle_b64, .. } = env.frame {
            let bundle_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &bundle_b64)
                    .expect("bundle b64");
            let derived_cid = jig_server::v0_0_2_federation::peer_block_cid(&bundle_bytes)
                .expect("relayed bundle has a CID");
            // Confirm the body content matches
            let (manifest_bytes, _): (Vec<u8>, Vec<u8>) =
                serde_json::from_slice(&bundle_bytes).expect("tuple");
            let manifest: jig_core::BlockManifest =
                serde_json::from_slice(&manifest_bytes).expect("manifest");
            if manifest
                .metadata
                .get("body")
                .and_then(|v| v.as_str())
                .map(|s| s.contains("federated"))
                .unwrap_or(false)
            {
                bob_received_cid = Some(derived_cid);
                break;
            }
        }
    }
    assert!(
        bob_received_cid.is_some(),
        "Bob must receive alice's federated text-render block via server_b"
    );

    // Confirm BOTH servers have the block + a receipt for it, under ONE CID:
    // the relay derives it the way ingest does, so the block server_b
    // delivered is the block server_a accepted, by identity.
    let receipts_a = server_a.receipts_for(&cid_a).expect("receipts on a");
    assert!(!receipts_a.is_empty(), "server_a must have a receipt");
    assert_eq!(
        bob_received_cid.as_deref(),
        Some(cid_a.as_str()),
        "a federated block keeps its CID across servers"
    );
    let receipts_b = server_b.receipts_for(&cid_a).expect("receipts on b");
    assert!(
        !receipts_b.is_empty(),
        "server_b must have a receipt for the federated block under `{cid_a}`"
    );

    // Cross-server receipt parity: render_hash agreement.
    //
    // This is the assertion issue #5 was filed about. Until text-render actually
    // executed, both sides produced `None` and this compared nothing to nothing —
    // it passed no matter what either server did. The `is_some()` checks below
    // exist so it can never silently return to that state: an equality assertion
    // over two absent values is indistinguishable from agreement.
    let hash_a = receipts_a[0]
        .render_hash
        .as_deref()
        .expect("server_a must have executed the block and recorded a render_hash");
    let hash_b = receipts_b[0]
        .render_hash
        .as_deref()
        .expect("server_b must have executed the federated block and recorded a render_hash");

    assert_eq!(
        hash_a, hash_b,
        "cross-server render_hash parity must hold for federated text-render: \
         two servers independently rendering the same body must derive the same hash"
    );
    // Independently: server_b's receipt is its own, not server_a's relayed.
    // Until relayed blocks went through ingest, server_b stored server_a's
    // receipt and this parity compared server_a with itself.
    assert!(
        receipts_b
            .iter()
            .all(|r| r.server_id == server_b.server_did_string),
        "server_b keeps only receipts it signed: {receipts_b:?}"
    );
}

// ---------------------------------------------------------------------------
// Issue #2 / alpha.1c §1.1 — forged-author peer block must be rejected.
//
// A malicious peer can relay a block whose manifest claims authorship by some
// third-party DID while signing the bundle bytes with its own (or any other)
// key. Pre-fix: v0_0_2_federation::ingest_peer_block stored `sender_sig: vec![]`
// without re-verifying. Post-fix: the receiving server re-verifies the sig
// against the manifest's claimed sender_did and drops the block on mismatch.
// ---------------------------------------------------------------------------

/// Construct a block bundle whose manifest claims `claimed_did` as author
/// but is signed with `actual_signing_key`. Returns (bundle_bytes, sig_bytes).
fn build_forged_block(
    actual_signing_key: &SigningKey,
    claimed_did: &Did,
    channel_slug: &str,
    body: &str,
) -> (Vec<u8>, Vec<u8>) {
    let manifest = BlockManifest::builder()
        .version(semver::Version::new(0, 1, 0))
        .author(Author {
            did: claimed_did.clone(),
            public_key: None,
            roles: vec![],
        })
        .metadata_entry("channel", serde_json::json!(channel_slug))
        .metadata_entry("body", serde_json::json!(body))
        .build()
        .expect("forged manifest builds")
        .with_kind(BlockKind::TextRender)
        .with_hlc(HlcTimestamp {
            wall_ms: 1_747_680_000_000,
            logical: 0,
            server_did: claimed_did.clone(),
        });
    let manifest_bytes = manifest.to_canonical_bytes().expect("canonical bytes");
    let bundle_bytes =
        serde_json::to_vec(&(manifest_bytes, Vec::<u8>::new())).expect("bundle tuple");
    let sig = actual_signing_key.sign(&bundle_bytes).to_bytes().to_vec();
    (bundle_bytes, sig)
}

/// Pretend to be a misbehaving server A: directly inject a forged block + its
/// receipt into A's store, then trigger A's fanout so the WSS-connected peer
/// (B) sees the relay. This bypasses A's own ingest verification (which
/// would catch the forgery locally) — the point is to verify B catches it
/// on the inbound side.
fn inject_forged_block_into_a(
    state: &std::sync::Arc<jig_server::v0_0_2::AppState>,
    bundle_bytes: &[u8],
    forged_sig: &[u8],
    claimed_did_str: &str,
) -> (StoredBlock, StoredReceipt) {
    let block_cid = jig_server::v0_0_2_federation::peer_block_cid(bundle_bytes).unwrap();
    let stored_block = StoredBlock {
        cid: block_cid.clone(),
        channel_id: None,
        block_kind: "text-render".to_string(),
        sender_did: claimed_did_str.to_string(),
        sender_sig: forged_sig.to_vec(),
        bundle_bytes: bundle_bytes.to_vec(),
        is_synthetic: false,
        hlc_wall_ms: 1_747_680_000_000,
        hlc_logical: 0,
        hlc_origin: claimed_did_str.to_string(),
        posted_at: chrono::Utc::now().timestamp(),
        origin_server: "ws://forged-origin".to_string(),
        federated_from: None,
    };
    state
        .ingest_ctx
        .store
        .insert_block(&stored_block)
        .expect("insert forged block");

    let stored_receipt = StoredReceipt {
        cid: format!("r_{}", &block_cid[..16.min(block_cid.len())]),
        block_cid: block_cid.clone(),
        server_id: state.server_did.to_did_jig_string(),
        receipt_bytes: b"{\"v\":\"0.2-forged\"}".to_vec(),
        render_hash: None,
        produced_at: chrono::Utc::now().timestamp(),
    };
    state
        .ingest_ctx
        .store
        .insert_receipt(&stored_receipt)
        .expect("insert forged receipt");
    (stored_block, stored_receipt)
}

#[tokio::test]
async fn federated_block_with_forged_author_did_is_rejected() {
    // Two TOFU-mode servers, bidirectionally peered.
    let srv_a = TestJigServer::start_copying_peers_channels()
        .await
        .expect("srv_a start");
    let srv_b = TestJigServer::start_copying_peers_channels()
        .await
        .expect("srv_b start");
    srv_a.add_peer(&srv_b).await.expect("a -> b peer");
    srv_b.add_peer(&srv_a).await.expect("b -> a peer");
    // Let the handshake + subscription dance settle.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Alice signs; bob is the framed third party.
    let alice_secret: [u8; 32] = rand::random();
    let alice_key = SigningKey::from_bytes(&alice_secret);
    let bob_secret: [u8; 32] = rand::random();
    let bob_key = SigningKey::from_bytes(&bob_secret);
    let bob_did = Did::from_ed25519_pubkey(bob_key.verifying_key().as_bytes());

    // #hello must exist on srv_b, or both relays are refused there as posts
    // to an unknown channel and the forged one proves nothing. Its
    // channel-create federates ahead of them on the same link.
    let (owner, _owner_dir) = test_identity_with_dir();
    srv_a
        .create_channel(&owner, "#hello", "open")
        .await
        .expect("create_channel");

    // #hello is open and unencrypted, so its blocks federate. A block with
    // no channel policy never does.
    let open_policy = jig_pipeline::fanout::DeliveryPolicy {
        open: true,
        owner_did: String::new(),
        member_dids: Vec::new(),
        federates: true,
    };

    // Forged block: alice signs, manifest claims bob.
    let (forged_bundle, forged_sig) =
        build_forged_block(&alice_key, &bob_did, "#hello", "I am bob (forged)");
    let forged_cid = jig_server::v0_0_2_federation::peer_block_cid(&forged_bundle).unwrap();

    // Inject straight into srv_a's store + receipt table, then broadcast through
    // srv_a's Fanout. The outbound peer-tx delivers the relayed block to srv_b's
    // run_peer_loop (via the harness shim, which mirrors production sig-verify).
    let (forged_block, forged_receipt) = inject_forged_block_into_a(
        &srv_a.state,
        &forged_bundle,
        &forged_sig,
        &bob_did.to_did_jig_string(),
    );
    srv_a
        .state
        .ingest_ctx
        .fanout
        .broadcast(&forged_block, &forged_receipt, Some(&open_policy))
        .await
        .expect("a fanout broadcast");

    // Control: the same relay carries a block alice signed as herself. The
    // peer link delivers in order, so once this lands on srv_b the forged
    // block has had its turn; without it, a broken link would pass the
    // assertion below.
    let alice_did = Did::from_ed25519_pubkey(alice_key.verifying_key().as_bytes());
    let (genuine_bundle, genuine_sig) =
        build_forged_block(&alice_key, &alice_did, "#hello", "I am alice");
    let genuine_cid = jig_server::v0_0_2_federation::peer_block_cid(&genuine_bundle).unwrap();
    let (genuine_block, genuine_receipt) = inject_forged_block_into_a(
        &srv_a.state,
        &genuine_bundle,
        &genuine_sig,
        &alice_did.to_did_jig_string(),
    );
    srv_a
        .state
        .ingest_ctx
        .fanout
        .broadcast(&genuine_block, &genuine_receipt, Some(&open_policy))
        .await
        .expect("a fanout broadcast");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while srv_b
        .block_for(&genuine_cid)
        .expect("query srv_b store")
        .is_none()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the genuine block never reached srv_b, so this test proves nothing"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The forged block MUST NOT have been persisted on srv_b.
    let on_b = srv_b.block_for(&forged_cid).expect("query srv_b store");
    assert!(
        on_b.is_none(),
        "srv_b must reject relayed block with forged sender_did (claimed: {}, signed-by: alice); but block was persisted: {:?}",
        bob_did.to_did_jig_string(),
        on_b
    );
}
