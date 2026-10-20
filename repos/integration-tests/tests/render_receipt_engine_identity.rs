//! The signed text-render receipt names the engine that measured its fuel.
//!
//! It used to sign `jig_runtime::RUNTIME_VERSION`, which was jig-runtime's own
//! crate version: "0.1.0" from 2024 onward, across wasmtime 24 to 49. Fuel is
//! only comparable between receipts from the same engine and configuration, so
//! the signed v0.3 `exec` receipt names the exact wasmtime patch and the
//! engine's configuration fingerprint.

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
    let signed = match jig_pipeline::receipts::read(&receipts[0].receipt_bytes)
        .expect("the receipt verifies")
    {
        jig_pipeline::receipts::ReadReceipt::V03(r) => r,
        other => panic!("a new receipt is v0.3, got {other:?}"),
    };
    let jig_core::block_receipt::Body::Exec(exec) = &signed.receipt.body else {
        panic!(
            "a rendered block gets an exec receipt: {:?}",
            signed.receipt.body
        );
    };

    // The exact wasmtime patch and the configuration fingerprint together fix how fuel is
    // metered, so the separate fuel-schedule label of the JSON receipts is not carried.
    assert_eq!(exec.engine.version, jig_runtime::WASMTIME_VERSION);
    assert_eq!(exec.engine.name, "wasmtime");
    assert_eq!(exec.engine.profile, "jig-det-1");
    assert!(
        exec.engine.config_fingerprint.starts_with("blake3:"),
        "{:?}",
        exec.engine
    );
}
