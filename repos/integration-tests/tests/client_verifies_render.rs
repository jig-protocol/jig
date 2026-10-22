//! Exit-gate item 2 (JEP-0006 step 7): a client re-executes a text-render block and agrees with
//! the server's signed `exec` receipt.
//!
//! The server renders through the text-block component and signs a v0.3 receipt naming the
//! component, the invocation (from the block's ingest record) and the outcome. The client
//! rebuilds the invocation from the same block and record, runs the same component, and must
//! reach the same outcome.

use base64::Engine as _;
use integration_tests::harness::*;
use jig_client::DeliveredBlock;
use jig_client::verify::{Verification, verify};
use jig_pipeline::envelope::ReceiptRef;

#[tokio::test]
async fn a_client_agrees_with_the_servers_exec_receipt() {
    let app = TestJigServer::start_with_text_render_only()
        .await
        .expect("start app");
    let id = test_identity();
    app.seed_channel(&id, "#hello").expect("seed channel");
    let cid = app
        .send_text_render(&id, "#hello", "checked by the client")
        .await
        .expect("submit");

    // The block as the history endpoint delivers it.
    let b64 = base64::engine::general_purpose::STANDARD;
    let stored = app.block_for(&cid).expect("store").expect("landed");
    let delivered = DeliveredBlock {
        bundle_b64: b64.encode(&stored.bundle_bytes),
        sig_b64: Some(b64.encode(&stored.sender_sig)),
        receipts: app
            .receipts_for(&cid)
            .expect("receipts")
            .into_iter()
            .map(|r| ReceiptRef {
                server_did: r.server_id,
                render_hash: r.render_hash,
                receipt_bytes_b64: b64.encode(&r.receipt_bytes),
            })
            .collect(),
        delivery_cid: format!("delivery:{cid}"),
        ingest: app
            .state
            .ingest_ctx
            .store
            .get_ingest_record(&cid)
            .expect("store"),
    };
    assert!(delivered.ingest.is_some(), "the channel is sequenced");

    let opened = jig_client::open::open(&delivered).expect("the block opens");
    assert_eq!(verify(&delivered, &opened), Verification::Agree);
}
