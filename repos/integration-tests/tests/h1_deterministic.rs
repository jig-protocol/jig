//! H1: text-render block ingest is deterministic across runs and servers.
//!
//! "Deterministic" here means: given the same signed bundle, every server
//! produces a receipt that agrees on the receipt's `render_hash` field.
//!
//! v0.0.2 finding (documented in test): the synthetic-receipt path used
//! for text-render ingest sets `render_hash = None` — Wasm text-render
//! execution lands in v0.0.3. So we assert receipts are `Some(h)` matching
//! across servers OR both `None` (the v0.0.2 trivial-determinism case).

use integration_tests::harness::*;

#[tokio::test]
async fn text_render_block_produces_deterministic_receipts_across_servers() {
    let app1 = TestJigServer::start_with_text_render_only()
        .await
        .expect("start app1");
    let app2 = TestJigServer::start_with_text_render_only()
        .await
        .expect("start app2");

    // Submit 10 different bundles. For each bundle, both servers must
    // agree on the receipt's render_hash (whether Some(h) or None).
    // Precondition: ingest now rejects text-render for an unknown channel.
    // Both servers need the channel; seeded directly because these run with
    // allowed_block_kinds = ["text-render"] and cannot create one.
    let seed_id = test_identity();
    app1.seed_channel(&seed_id, "#hello").expect("seed app1");
    app2.seed_channel(&seed_id, "#hello").expect("seed app2");

    // Within a single server, submitting the same bundle yields the same
    // block CID (insert_block primary key dedupes), so we vary the body
    // to get 10 distinct CIDs.
    for i in 0..10 {
        let id = test_identity();
        let hlc = jig_core::HlcTimestamp {
            wall_ms: 1_700_000_000_000 + i as u64,
            logical: 0,
            server_did: id.did().clone(),
        };
        let body = format!("hello {i}");
        let block = jig_client::blocks::build_text_render(&id, "#hello", &body, hlc);

        let cid_1 = app1.submit_block(&block).await.expect("submit app1");
        let cid_2 = app2.submit_block(&block).await.expect("submit app2");
        assert_eq!(
            cid_1, cid_2,
            "identical bundle must yield identical CID on both servers (iter {i})"
        );

        let r1 = app1.receipts_for(&cid_1).expect("receipts app1");
        let r2 = app2.receipts_for(&cid_2).expect("receipts app2");
        assert_eq!(r1.len(), 1, "exactly one receipt expected on app1");
        assert_eq!(r2.len(), 1, "exactly one receipt expected on app2");

        // Each server signs receipts with its OWN server_did key, so
        // `receipt_bytes` will differ. But the `render_hash` field — the
        // deterministic-output marker — must agree (or both be None).
        assert_eq!(
            r1[0].render_hash, r2[0].render_hash,
            "render_hash must match across servers for the same bundle (iter {i}, body=\"{body}\")"
        );
    }
}

/// A text-render block EXECUTES, and its receipt carries the resulting hash.
///
/// This test replaces `text_render_block_receipts_render_hash_documented_as_none_in_v0_0_2`,
/// which asserted the opposite. That test was a characterization of the v0.0.2
/// carve-out and said so in its own comment: *"If this assertion starts failing
/// because v0.0.3+ wires real Wasm execution, that's the expected behavior change
/// — update this test to assert Some(h) instead."* This is that update, and it is
/// the acceptance criterion for issue #5.
///
/// It asserts against an independently computed expectation rather than merely
/// `is_some()`: a receipt carrying *some* hash proves the field is populated, not
/// that the module rendered the message that was actually sent.
#[tokio::test]
async fn a_text_render_block_executes_and_its_receipt_carries_the_render_hash() {
    let app = TestJigServer::start_with_text_render_only()
        .await
        .expect("start app");
    let id = test_identity();
    app.seed_channel(&id, "#hello").expect("seed channel");
    let hlc = jig_core::HlcTimestamp {
        wall_ms: 1_700_000_000_000,
        logical: 0,
        server_did: id.did().clone(),
    };
    const BODY: &str = "the first message to really execute";
    let block = jig_client::blocks::build_text_render(&id, "#hello", BODY, hlc);

    let cid = app.submit_block(&block).await.expect("submit");
    let receipts = app.receipts_for(&cid).expect("receipts");

    assert_eq!(receipts.len(), 1);
    let hash = receipts[0]
        .render_hash
        .as_deref()
        .expect("text-render must execute and produce a render_hash");

    // The value must be the render of THIS body. `execute_pure` is the native
    // reference, pinned to the Wasm module by jig-runtime's payload tests.
    let expected = text_block::execute_pure(&text_block::Input {
        sender_did: id.did().to_did_jig_string(),
        channel_id: "#hello".to_string(),
        body_raw: BODY.to_string(),
        hlc_wall_ms: 1_700_000_000_000,
        hlc_logical: 0,
        hlc_origin: id.did().to_did_jig_string(),
        client_version: String::new(),
    })
    .render_hash;
    assert_eq!(
        hash, expected,
        "render_hash must be the render of the submitted body"
    );

    // A different body must not produce the same hash, or the value carries no
    // information about the message.
    let other = text_block::execute_pure(&text_block::Input {
        sender_did: String::new(),
        channel_id: String::new(),
        body_raw: format!("{BODY}!"),
        hlc_wall_ms: 0,
        hlc_logical: 0,
        hlc_origin: String::new(),
        client_version: String::new(),
    })
    .render_hash;
    assert_ne!(hash, other);
}
