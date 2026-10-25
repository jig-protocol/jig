//! Step 8's federation case (JEP-0006, JEP-0011 §5.1): server X renders a text-render block, and
//! server Y, running X's invocation under Y's own default operator policy, reaches the same
//! outcome. The two servers sign different text-block program manifests, so their program CIDs
//! differ; comparison keys on the component, the invocation and the outcome.

use integration_tests::harness::*;
use jig_core::block_receipt::{Body, Comparison, compare};
use jig_pipeline::executor::{text_input, text_render_invocation};

#[tokio::test]
async fn server_y_agrees_with_server_xs_text_block_render() {
    let x = TestJigServer::start_with_text_render_only()
        .await
        .expect("start X");
    let y = TestJigServer::start_with_text_render_only()
        .await
        .expect("start Y");
    let id = test_identity();
    x.seed_channel(&id, "#hello").expect("seed channel on X");
    let cid = x
        .send_text_render(&id, "#hello", "rendered on X, checked on Y")
        .await
        .expect("submit to X");

    let receipt = x.receipts_for(&cid).expect("receipts").remove(0);
    let jig_pipeline::receipts::ReadReceipt::V03(signed) =
        jig_pipeline::receipts::read(&receipt.receipt_bytes).expect("X's receipt verifies")
    else {
        panic!("X writes v0.3 receipts");
    };
    let Body::Exec(x_exec) = signed.receipt.body else {
        panic!("X ran the block");
    };

    // Y runs the invocation X's receipt names: the block and X's ingest record for it.
    let stored = x.block_for(&cid).expect("store").expect("landed on X");
    let (manifest_bytes, _): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&stored.bundle_bytes).expect("stored bundle");
    let manifest: jig_core::BlockManifest =
        serde_json::from_slice(&manifest_bytes).expect("manifest");
    let record = x
        .state
        .ingest_ctx
        .store
        .get_ingest_record(&cid)
        .expect("store")
        .expect("X sequenced the block");
    let invocation = text_render_invocation(&text_input(&manifest).expect("body"), &cid, &record);
    let y_run = y
        .state
        .ingest_ctx
        .executor
        .as_ref()
        .expect("Y has an executor")
        .render(&invocation)
        .expect("Y's default policy allows text-block by component");

    assert_ne!(
        y_run.exec.program, x_exec.program,
        "each server signs its own manifest"
    );
    assert_ne!(y_run.exec.operator_policy_cid, x_exec.operator_policy_cid);
    assert_eq!(compare(&y_run.exec, &x_exec), Comparison::Agree);
}
