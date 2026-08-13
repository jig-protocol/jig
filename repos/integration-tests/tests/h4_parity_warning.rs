//! H4: Read-time parity divergence renders a warning badge.
//!
//! When two servers ingest the same block but produce different
//! `render_hash` values (e.g. an attacker-controlled server returns a
//! tampered render), readers must SURFACE the divergence — not silently
//! pick one. The CLI prefixes a "⚠ render mismatch" badge on rendered
//! lines for blocks whose receipts disagree.
//!
//! This test injects synthetic receipts with deliberately different
//! render_hash values directly into the persist layer (bypassing
//! ingest), then checks `count_distinct_render_hashes > 1`. The CLI's
//! render path is unit-tested separately in jig-cli's `cmd::blocks_decode`
//! module; we cover the read-time persist-side detection here.

use integration_tests::harness::*;
use jig_pipeline::persist::StoredReceipt;

#[tokio::test]
async fn injected_divergent_receipts_are_detectable_via_persist() {
    let server = TestJigServer::start_with_text_render_only()
        .await
        .expect("start server");
    let (sender, _dir) = test_identity_with_dir();
    // Precondition, not the subject of this test: ingest rejects text-render
    // for an unknown channel. Seeded directly because this server runs with
    // allowed_block_kinds = ["text-render"] and so cannot create one.
    server
        .seed_channel(&sender, "#hello")
        .expect("seed channel");

    // Submit a real block so we have a stored_block entry to attach
    // receipts to.
    let cid = server
        .send_text_render(&sender, "#hello", "parity test")
        .await
        .expect("send");

    // The local ingest receipt now carries a REAL render_hash, because
    // text-render executes. Before #5 it was NULL and was excluded from
    // divergence counting, which meant this scenario only worked because both
    // *injected* receipts carried hashes — the honest local one contributed
    // nothing. Now the local render participates, which is what makes the check
    // meaningful: divergence is measured against a value this server derived
    // itself rather than purely among values peers asserted.
    let receipts_before = server.receipts_for(&cid).expect("receipts");
    assert_eq!(receipts_before.len(), 1);
    let local_hash = receipts_before[0]
        .render_hash
        .clone()
        .expect("local ingest must produce a render_hash now that text-render executes");

    // Inject two receipts from peers with DIFFERENT render_hash values, as
    // federation would deliver them. Neither matches the local hash, so all three
    // disagree.
    let synthetic_a = StoredReceipt {
        cid: format!("r_synthetic_a_{cid}"),
        block_cid: cid.clone(),
        server_id: "did:jig:zPeerHonest".to_string(),
        receipt_bytes: b"{\"version\":\"v0.2\"}".to_vec(),
        render_hash: Some("honest-render-hash-aaa".to_string()),
        produced_at: chrono::Utc::now().timestamp(),
    };
    let synthetic_b = StoredReceipt {
        cid: format!("r_synthetic_b_{cid}"),
        block_cid: cid.clone(),
        server_id: "did:jig:zPeerEvil".to_string(),
        receipt_bytes: b"{\"version\":\"v0.2\",\"tampered\":true}".to_vec(),
        render_hash: Some("tampered-render-hash-zzz".to_string()),
        produced_at: chrono::Utc::now().timestamp(),
    };
    server
        .state
        .ingest_ctx
        .store
        .insert_receipt(&synthetic_a)
        .expect("insert synthetic a");
    server
        .state
        .ingest_ctx
        .store
        .insert_receipt(&synthetic_b)
        .expect("insert synthetic b");

    let receipts_after = server.receipts_for(&cid).expect("receipts after");
    assert_eq!(receipts_after.len(), 3);

    let distinct = server
        .state
        .ingest_ctx
        .store
        .count_distinct_render_hashes(&cid)
        .expect("count distinct");
    // Three receipts, three different hashes — the local render plus two
    // disagreeing peers. Asserted exactly rather than `>= 2`: with the local
    // receipt now carrying a hash, a count of 2 would mean one of the three got
    // silently dropped from the tally.
    assert_eq!(
        distinct, 3,
        "expected all three receipts to count as distinct (local {local_hash}, \
         plus two injected peers); got {distinct}"
    );
}

#[tokio::test]
async fn divergent_render_hashes_produce_parity_warning_in_decoder() {
    // The render-side check used by `jig-cli` (and any future renderer):
    // when count_distinct_render_hashes > 1, the rendered output prefixes
    // a warning. We replicate the marker locally to avoid depending on
    // jig-cli from this crate.

    let server = TestJigServer::start_with_text_render_only()
        .await
        .expect("start server");
    let (sender, _dir) = test_identity_with_dir();
    server
        .seed_channel(&sender, "#hello")
        .expect("seed channel");
    let cid = server
        .send_text_render(&sender, "#hello", "render me")
        .await
        .expect("send");

    // Force divergence — two non-NULL render_hash values.
    server
        .state
        .ingest_ctx
        .store
        .insert_receipt(&StoredReceipt {
            cid: format!("r_div_a_{cid}"),
            block_cid: cid.clone(),
            server_id: "did:jig:zSecond".to_string(),
            receipt_bytes: vec![],
            render_hash: Some("alt-hash-a".to_string()),
            produced_at: chrono::Utc::now().timestamp(),
        })
        .expect("insert a");
    server
        .state
        .ingest_ctx
        .store
        .insert_receipt(&StoredReceipt {
            cid: format!("r_div_b_{cid}"),
            block_cid: cid.clone(),
            server_id: "did:jig:zThird".to_string(),
            receipt_bytes: vec![],
            render_hash: Some("alt-hash-b".to_string()),
            produced_at: chrono::Utc::now().timestamp(),
        })
        .expect("insert b");

    let block = server
        .block_for(&cid)
        .expect("block lookup")
        .expect("block present");
    let receipts = server.receipts_for(&cid).expect("receipts");

    let formatted = format_with_parity_marker(&block, &receipts);
    assert!(
        formatted.contains("⚠ render mismatch"),
        "rendered output must carry parity warning marker; got: `{formatted}`"
    );
    assert!(
        formatted.contains("render me"),
        "rendered output must include the body content"
    );
}

/// Replication of the parity-marker logic used by jig-cli's render path.
/// Kept here to avoid taking a jig-cli dependency from integration-tests.
///
/// Matches the SQL semantics of `count_distinct_render_hashes`: only
/// receipts with `Some(hash)` participate; NULL receipts (synthetic
/// v0.0.2 placeholders) are treated as "no render yet" — not a vote.
fn format_with_parity_marker(
    block: &jig_pipeline::persist::StoredBlock,
    receipts: &[StoredReceipt],
) -> String {
    let hashes: std::collections::HashSet<String> = receipts
        .iter()
        .filter_map(|r| r.render_hash.clone())
        .collect();
    let parity_warning = if hashes.len() > 1 {
        "⚠ render mismatch "
    } else {
        ""
    };

    // Decode body from bundle metadata
    let (manifest_bytes, _code_bytes): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&block.bundle_bytes).expect("bundle tuple");
    let manifest: jig_core::BlockManifest =
        serde_json::from_slice(&manifest_bytes).expect("manifest");
    let body = manifest
        .metadata
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    format!("{parity_warning}{body}")
}
