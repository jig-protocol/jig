//! H3: two federated servers.
//!
//! The v0.0.2 acceptance test that lived here (Alice posts on one server, Bob
//! reads it on the other, both servers' receipts agree) ran over the legacy
//! relay. A channel now crosses servers only by a share (JEP-0014 rule 37,
//! #357), and the follower executes nothing it carries (JEP-0005 rule 12), so
//! it moved to `jig-server`'s contract tests as
//! `a_post_crosses_by_a_share_and_runs_only_on_its_owner`, over two servers
//! peered both ways. Cross-server render agreement is
//! `federated_render_agrees.rs`.
//!
//! What stays: the relay re-verifies the author of every block it brings.

use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use integration_tests::harness::*;
use jig_core::{Author, BlockKind, BlockManifest, Did, HlcTimestamp};
use jig_pipeline::persist::{StoredBlock, StoredReceipt};

// ---------------------------------------------------------------------------
// Issue #2 / alpha.1c §1.1 — forged-author peer block must be rejected.
//
// A malicious peer can relay a block whose manifest claims authorship by some
// third-party DID while signing the bundle bytes with its own (or any other)
// key. Pre-fix: v0_0_2_federation::ingest_peer_block stored `sender_sig: vec![]`
// without re-verifying. Post-fix: the receiving server re-verifies the sig
// against the manifest's claimed sender_did and drops the block on mismatch.
// ---------------------------------------------------------------------------

/// Construct a `channel-create` of `slug` whose manifest claims `claimed_did`
/// as author but is signed with `actual_signing_key`. Returns (bundle_bytes,
/// sig_bytes). A create, because it is the one block the relay still lands
/// (under the copying flag): a relayed post lands in no channel (#357), so a
/// genuine post could not be the control.
fn build_forged_block(
    actual_signing_key: &SigningKey,
    claimed_did: &Did,
    slug: &str,
) -> (Vec<u8>, Vec<u8>) {
    let manifest = BlockManifest::builder()
        .version(semver::Version::new(0, 1, 0))
        .author(Author {
            did: claimed_did.clone(),
            public_key: None,
            roles: vec![],
        })
        .metadata_entry("slug", serde_json::json!(slug))
        .metadata_entry("tier", serde_json::json!("public"))
        .build()
        .expect("forged manifest builds")
        .with_kind(BlockKind::ChannelCreate)
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
        block_kind: "channel-create".to_string(),
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

    // Both are creates of open, unencrypted channels, so they federate. A
    // block with no channel policy never does.
    let open_policy = jig_pipeline::fanout::DeliveryPolicy {
        open: true,
        owner_did: String::new(),
        member_dids: Vec::new(),
        federates: true,
    };

    // Forged block: alice signs, manifest claims bob.
    let (forged_bundle, forged_sig) = build_forged_block(&alice_key, &bob_did, "#forged");
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
    let (genuine_bundle, genuine_sig) = build_forged_block(&alice_key, &alice_did, "#genuine");
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
