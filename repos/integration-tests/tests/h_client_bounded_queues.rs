//! A client holds at most `jig_client::connection::SUBSCRIPTION_QUEUE`
//! deliveries for a subscriber that does not read them: past that, the
//! subscription ends, marked lagged, and the connection carries on.

use std::time::Duration;

use integration_tests::harness::*;
use jig_client::Client;
use jig_client::connection::SUBSCRIPTION_QUEUE;

#[tokio::test]
async fn a_subscriber_that_falls_behind_is_ended_and_the_connection_lives() {
    let server = TestJigServer::start().await.expect("start");
    let owner = test_identity();
    server
        .create_channel(&owner, "#busy", "open")
        .await
        .expect("create");

    let reader = Client::connect(&server.ws_url(), test_identity())
        .await
        .expect("connect");
    let mut stream = reader.subscribe_channel("#busy").await.expect("subscribe");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // More deliveries than the subscription holds, none of them read yet.
    let sent = SUBSCRIPTION_QUEUE + 16;
    for i in 0..sent {
        server
            .send_text_render(&owner, "#busy", &format!("m{i}"))
            .await
            .expect("send");
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut got = 0;
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_secs(2), stream.next()).await {
        got += 1;
    }
    assert_eq!(
        got, SUBSCRIPTION_QUEUE,
        "the queue held what fit, and the stream then ended"
    );
    assert!(stream.lagged(), "it ended because it fell behind");

    // The connection is still up: the same client subscribes again and
    // receives what is sent next.
    let mut again = reader
        .subscribe_channel("#busy")
        .await
        .expect("resubscribe");
    tokio::time::sleep(Duration::from_millis(200)).await;
    server
        .send_text_render(&owner, "#busy", "after")
        .await
        .expect("send");
    let next = tokio::time::timeout(Duration::from_secs(5), again.next())
        .await
        .expect("a delivery after resubscribing")
        .expect("the new stream is open");
    assert!(!next.delivery_cid.is_empty());
    assert!(!again.lagged());
}
