//! A server's welcome and its manifest log tell one story (JEP-0002 rule 12):
//! the block and record a welcome cites, as the server serves them over REST,
//! hold up for a client that trusts nothing but the welcome's key.

use integration_tests::harness::{TestJigServer, test_identity};
use jig_client::manifest::{LOG_SLUG, ManifestCheck, check_cited};
use jig_client::read_auth::{ReadProof, signable_path};

async fn get_json(who: &jig_client::Identity, url: &str) -> serde_json::Value {
    let proof = ReadProof::sign(who, "GET", signable_path(url));
    let mut req = reqwest::Client::new().get(url);
    for (name, value) in proof.headers() {
        req = req.header(name, value);
    }
    let resp = req.send().await.unwrap();
    assert!(resp.status().is_success(), "GET {url}: {}", resp.status());
    resp.json().await.unwrap()
}

#[tokio::test]
async fn the_manifest_a_welcome_cites_is_served_and_agrees_with_it() {
    let server = TestJigServer::start().await.unwrap();
    let published = jig_server::v0_0_2_manifest_log::publish(&server.state)
        .await
        .unwrap();

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("{}/api/v1/ws", server.ws_url()))
        .await
        .unwrap();
    let welcome = jig_server::v0_0_2_federation::complete_client_handshake(&mut ws, None)
        .await
        .unwrap();
    let cited = welcome
        .manifest
        .clone()
        .expect("the welcome cites the manifest");
    assert_eq!(cited, published);

    let who = test_identity();
    let base = server.http_url();
    let block = get_json(&who, &format!("{base}/api/v1/blocks/{}", cited.cid)).await;
    let records = get_json(
        &who,
        &format!(
            "{base}/api/v1/channels/{}/records?from={}&limit=1",
            LOG_SLUG.replace('#', "%23").replace('/', "%2F"),
            cited.seq
        ),
    )
    .await;
    let record: jig_client::chain::IngestRecord =
        serde_json::from_value(records[0].clone()).unwrap();
    let doc = check_cited(
        &welcome,
        &cited,
        block["bundle_b64"].as_str().unwrap(),
        block["sig_b64"].as_str().unwrap(),
        &record,
    )
    .expect("the server's own manifest agrees with its welcome");
    assert_eq!(doc.suites.len(), welcome.suites.len());

    // A welcome that told this client a different story would not.
    let mut tailored = welcome.clone();
    tailored.suites.retain(|s| s == "none");
    assert!(matches!(
        check_cited(
            &tailored,
            &cited,
            block["bundle_b64"].as_str().unwrap(),
            block["sig_b64"].as_str().unwrap(),
            &record,
        ),
        Err(ManifestCheck::Contradicts(_))
    ));
}
