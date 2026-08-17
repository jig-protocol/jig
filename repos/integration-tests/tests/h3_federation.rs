//! H3: Two-server federation chat with cross-server receipt parity.
//!
//! THIS IS THE V0.0.2 ACCEPTANCE TEST. Alice connects to server-a, Bob
//! connects to server-b. Alice sends a text-render block. Bob must
//! receive it via federation within 2s, and both servers' receipts for
//! the block must agree on render_hash.
//!
//! v0.0.2 caveats observed while writing this test:
//! 1. Federation handshake is synthetic (not a real Wasm block) — done
//!    via Frame::Submit with a fed-hello bundle signed by the server's
//!    own key. The test doesn't assert handshake completion; we just
//!    wait a beat after add_peer.
//! 2. Each server signs receipts with its OWN server_key — receipt_bytes
//!    differ across servers. We compare render_hash, the deterministic
//!    output marker (None in v0.0.2 — see H1 for the explanation).
//! 3. The receiving server stores federated blocks with `sender_sig: vec![]`
//!    (see v0_0_2_federation::ingest_peer_block) — the connection's
//!    fed-hello is the trust anchor. That's a v0.0.2 carve-out and is
//!    explicitly noted on the federation module.

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
    let server_a = TestJigServer::start_with_full_kinds()
        .await
        .expect("start server_a");
    let server_b = TestJigServer::start_with_full_kinds()
        .await
        .expect("start server_b");

    // Bidirectional peering.
    server_a.add_peer(&server_b).await.expect("a -> b");
    server_b.add_peer(&server_a).await.expect("b -> a");
    // Give the fed-hello handshake + subscription dance time to settle.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (alice, _alice_dir) = test_identity_with_dir();
    let (_bob, _bob_dir) = test_identity_with_dir();

    // Alice creates the channel on server_a. (Channel state doesn't federate
    // in v0.0.2 — channel ops are admin-endpoint-only — but the channel must
    // exist on the SENDER's server so member-add can resolve; for text-render
    // the channel doesn't even need to exist locally.)
    server_a
        .create_channel(&alice, "#hello", "open")
        .await
        .expect("create_channel");

    // Bob subscribes to server_b via WSS (federation scope so we match
    // text-render regardless of channel_id).
    let ws_url_b = format!("{}/api/v1/ws", server_b.ws_url());
    let (mut bob_ws, _) = connect_async(&ws_url_b).await.expect("bob ws connect");
    let sub = Envelope::new(Frame::Subscribe {
        scope: Scope::Federation {
            block_kinds: vec![],
        },
    });
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
            let derived_cid = format!(
                "bafy_{}",
                hex::encode(blake3::hash(&bundle_bytes).as_bytes())
            );
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

    // Confirm BOTH servers have the block + a receipt for it.
    // Server_a stores under its ingest-computed CID. Server_b stores under
    // the federation-receive-computed CID (also blake3 over the bundle).
    let receipts_a = server_a.receipts_for(&cid_a).expect("receipts on a");
    assert!(!receipts_a.is_empty(), "server_a must have a receipt");

    // Server_b's CID for the same block: derived via blake3 over canonical
    // bytes. The federation module uses the same blake3 hash for the CID.
    // Both should produce the same hash since canonical bytes are identical;
    // the format prefix is identical too ("bafy_<hex>" for the federation
    // path; the local ingest may use just blake3 hex without the prefix).
    let receipts_b_with_b_cid = server_b
        .receipts_for(&bob_received_cid.clone().unwrap())
        .expect("receipts on b");
    let receipts_b_with_a_cid = server_b
        .receipts_for(&cid_a)
        .expect("receipts on b via a-cid");

    let receipts_b = if !receipts_b_with_b_cid.is_empty() {
        receipts_b_with_b_cid
    } else {
        receipts_b_with_a_cid
    };

    assert!(
        !receipts_b.is_empty(),
        "server_b must have a receipt for the federated block (looked up under both \
         locally-derived CID `{}` and sender-side CID `{cid_a}`)",
        bob_received_cid.unwrap_or_default()
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
    let block_cid = format!(
        "bafy_{}",
        hex::encode(blake3::hash(bundle_bytes).as_bytes())
    );
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
    let srv_a = TestJigServer::start_with_full_kinds()
        .await
        .expect("srv_a start");
    let srv_b = TestJigServer::start_with_full_kinds()
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

    // Forged block: alice signs, manifest claims bob.
    let (forged_bundle, forged_sig) =
        build_forged_block(&alice_key, &bob_did, "#hello", "I am bob (forged)");
    let forged_cid = format!(
        "bafy_{}",
        hex::encode(blake3::hash(&forged_bundle).as_bytes())
    );

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
        .broadcast(&forged_block, &forged_receipt)
        .await
        .expect("a fanout broadcast");

    // Wait long enough for the relay to reach srv_b and for srv_b to
    // process the inbound Block frame.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // The forged block MUST NOT have been persisted on srv_b.
    let on_b = srv_b.block_for(&forged_cid).expect("query srv_b store");
    assert!(
        on_b.is_none(),
        "srv_b must reject relayed block with forged sender_did (claimed: {}, signed-by: alice); but block was persisted: {:?}",
        bob_did.to_did_jig_string(),
        on_b
    );
}

#[tokio::test]
async fn naively_trust_peer_authored_blocks_accepts_forged_relay() {
    // Same scenario as the rejection test, but srv_b runs with the
    // antipattern flag enabled. Forged block must now be accepted —
    // demonstrating the carve-out is wired and the flag is load-bearing.
    use jig_config::v0_0_2_server::{FederationSection, JigServerConfig};

    let srv_a = TestJigServer::start_with_full_kinds()
        .await
        .expect("srv_a start");

    let mut srv_b_config = JigServerConfig::default();
    srv_b_config.debug.admin_endpoints = true;
    srv_b_config.federation = FederationSection {
        peers: vec![],
        dangerously_disable_federation_tls: false,
        naively_trust_peer_authored_blocks: true,
    };
    srv_b_config.server.allowed_block_kinds = vec![
        "text-render".to_string(),
        "channel-create".to_string(),
        "member-add".to_string(),
        "fed-hello".to_string(),
    ];
    let srv_b = TestJigServer::start_with_config(srv_b_config)
        .await
        .expect("srv_b start");
    srv_a.add_peer(&srv_b).await.expect("a -> b peer");
    srv_b.add_peer(&srv_a).await.expect("b -> a peer");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let alice_secret: [u8; 32] = rand::random();
    let alice_key = SigningKey::from_bytes(&alice_secret);
    let bob_secret: [u8; 32] = rand::random();
    let bob_key = SigningKey::from_bytes(&bob_secret);
    let bob_did = Did::from_ed25519_pubkey(bob_key.verifying_key().as_bytes());

    let (forged_bundle, forged_sig) =
        build_forged_block(&alice_key, &bob_did, "#hello", "trusted relay");
    let forged_cid = format!(
        "bafy_{}",
        hex::encode(blake3::hash(&forged_bundle).as_bytes())
    );
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
        .broadcast(&forged_block, &forged_receipt)
        .await
        .expect("a fanout broadcast");
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Under the antipattern flag, srv_b accepts the forged relay.
    let on_b = srv_b.block_for(&forged_cid).expect("query srv_b store");
    assert!(
        on_b.is_some(),
        "naively_trust_peer_authored_blocks=true on srv_b must persist even forged peer blocks"
    );
}
