//! The signed text-render receipt names the engine that measured its fuel.
//!
//! It used to sign `jig_runtime::RUNTIME_VERSION`, which was jig-runtime's own
//! crate version: "0.1.0" from 2024 onward, across wasmtime 24 to 49. Fuel is
//! only comparable between receipts from the same engine, configuration and
//! schedule, so the signed identity has to say which ones produced it.

use integration_tests::harness::*;

#[tokio::test]
async fn the_signed_render_receipt_carries_the_engine_identity() {
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
    let block = jig_client::blocks::build_text_render(&id, "#hello", "identify yourself", hlc);
    let cid = app.submit_block(&block).await.expect("submit");

    let receipts = app.receipts_for(&cid).expect("receipts");
    assert_eq!(receipts.len(), 1);
    let wrapped: serde_json::Value =
        serde_json::from_slice(&receipts[0].receipt_bytes).expect("receipt wrapper is JSON");
    let canonical = hex::decode(wrapped["canonical_hex"].as_str().expect("canonical_hex"))
        .expect("canonical_hex is hex");
    let signed: serde_json::Value =
        serde_json::from_slice(&canonical).expect("signed payload is JSON");

    let identity = &signed["engine"]["identity"];
    assert_eq!(
        identity["wasmtime"],
        jig_runtime::WASMTIME_VERSION,
        "signed payload: {signed}"
    );
    assert_eq!(
        identity["fuel_schedule"],
        jig_runtime::FUEL_SCHEDULE_VERSION
    );
    assert!(
        identity["config_fingerprint"]
            .as_str()
            .is_some_and(|f| f.starts_with("blake3:")),
        "signed payload: {signed}"
    );
    assert!(
        signed["engine"].get("runtime_version").is_none(),
        "the crate-version label must be gone: {signed}"
    );
}
