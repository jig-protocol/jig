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

#[tokio::test]
async fn text_render_block_receipts_render_hash_documented_as_none_in_v0_0_2() {
    // Explicit characterization of the v0.0.2 behavior: text-render Wasm
    // execution is NOT wired in v0.0.2 (the canonical text-render.wasm
    // exists but the ingest pipeline uses the synthetic-receipt path for
    // all kinds). render_hash should be None.
    //
    // If this assertion starts failing because v0.0.3+ wires real Wasm
    // execution, that's the expected behavior change — update this test
    // to assert Some(h) instead and confirm parity in H1's main test.

    let app = TestJigServer::start_with_text_render_only()
        .await
        .expect("start app");
    let id = test_identity();
    // Precondition, not the subject of this test — see the note above.
    app.seed_channel(&id, "#hello").expect("seed channel");
    let hlc = jig_core::HlcTimestamp {
        wall_ms: 1_700_000_000_000,
        logical: 0,
        server_did: id.did().clone(),
    };
    let block = jig_client::blocks::build_text_render(&id, "#hello", "v0.0.2 snapshot", hlc);

    let cid = app.submit_block(&block).await.expect("submit");
    let receipts = app.receipts_for(&cid).expect("receipts");

    assert_eq!(receipts.len(), 1);
    assert!(
        receipts[0].render_hash.is_none(),
        "v0.0.2 text-render uses the synthetic-receipt path; render_hash should be None"
    );
}
