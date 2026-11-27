//! The federated-pair harness (F2 Task 11): two servers, each a configured
//! peer of the other, with the channel contract running on both. A share
//! from one is accepted by the other, which then carries the channel under
//! its id. The end-to-end contract cases build on this.

use std::time::Duration;

use integration_tests::harness::*;
use jig_client::blocks::build_channel_share;
use jig_config::v0_0_2_server::OfferPolicy;
use jig_core::HlcTimestamp;
use jig_core::contract::Grant;
use jig_pipeline::contracts::{OfferState, Side};

/// Wait up to `secs` seconds for `check` to hold.
async fn within(secs: u64, what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..secs * 20 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{what}: not within {secs} seconds");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_share_between_a_federated_pair_is_accepted_and_carried() {
    let (a, b) = TestJigServer::start_federated_pair(OfferPolicy::Hold, OfferPolicy::Accept)
        .await
        .expect("start the pair");
    within(5, "each connected to the other", || a.connected_to(&b)).await;

    let owner = test_identity();
    let channel = a
        .create_channel(&owner, "#shared", "open")
        .await
        .expect("create");
    a.submit_block(&build_channel_share(
        &owner,
        "#shared",
        &b.server_did_string,
        Grant::Read,
        HlcTimestamp::now_wall(owner.did().clone()),
    ))
    .await
    .expect("the owner may share");

    // B accepts by its policy, and carries the channel under its id, owned
    // by A.
    let carried = || {
        b.state
            .ingest_ctx
            .store
            .get_channel_by_id(&channel)
            .ok()
            .flatten()
    };
    // A follower asks for a channel's records on its next pull, at most
    // `PULL_EVERY` (10 s) after the share is accepted.
    let pull = jig_server::v0_0_2_stream::PULL_EVERY.as_secs() + 5;
    within(pull, "B carries the channel", || carried().is_some()).await;
    assert_eq!(carried().unwrap().sequencer_did, a.server_did_string);
    let accepted = |server: &TestJigServer, peer: &TestJigServer, side| {
        server
            .state
            .ingest_ctx
            .store
            .contract_offers_for(
                &channel,
                &peer.server_did_string,
                side,
                OfferState::Accepted,
            )
            .unwrap()
            .len()
    };
    within(5, "both hold the share as accepted", || {
        accepted(&a, &b, Side::Owner) == 1 && accepted(&b, &a, Side::Follower) == 1
    })
    .await;
}
