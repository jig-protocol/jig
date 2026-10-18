//! H7: Unsafe options are actively advertised in `/.well-known/jig`.
//!
//! Every antipattern flag — listed in `JigServerConfig::unsafe_options_active`
//! — must surface in the server's well-known discovery JSON so federated
//! peers can detect a misconfigured neighbor and refuse to peer with it.
//!
//! A default install lists none (a block's clock is bounded by
//! `[server] max_future_skew_ms`). Each flag appears only when explicitly
//! enabled in the server config:
//!   - `federation.dangerously_disable_federation_tls`
//!   - `identity.naively_allow_unknown_handles_fallback`
//!   - `debug.list_handles`

use integration_tests::harness::*;
use jig_config::v0_0_2_server::{DebugSection, IdentitySection, JigServerConfig};

async fn well_known(server: &TestJigServer) -> serde_json::Value {
    reqwest::get(format!("{}/.well-known/jig", server.http_url()))
        .await
        .expect("GET well-known")
        .json()
        .await
        .expect("json parse")
}

#[tokio::test]
async fn default_install_advertises_no_unsafe_option() {
    // A block's clock is bounded by `[server] max_future_skew_ms`, so a
    // default install has nothing to advertise.
    let config = JigServerConfig {
        debug: DebugSection::default(),
        identity: IdentitySection::default(),
        ..Default::default()
    };

    let server = TestJigServer::start_with_config(config)
        .await
        .expect("start");
    let info = well_known(&server).await;
    let active = info["unsafe_options_active"]
        .as_array()
        .expect("array")
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect::<Vec<_>>();
    assert!(
        active.is_empty(),
        "a default install must advertise no unsafe option (got {active:?})"
    );
}

#[tokio::test]
async fn dangerously_disable_federation_tls_surfaces_in_well_known() {
    let mut config = JigServerConfig::default();
    config.federation.dangerously_disable_federation_tls = true;
    let server = TestJigServer::start_with_config(config).await.unwrap();
    let info = well_known(&server).await;
    let active: Vec<String> = info["unsafe_options_active"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(active.contains(&"federation.dangerously_disable_federation_tls".to_string()));
}

#[tokio::test]
async fn dangerously_allow_plaintext_federation_surfaces_in_well_known() {
    let mut config = JigServerConfig::default();
    config.federation.dangerously_allow_plaintext_federation = true;
    let server = TestJigServer::start_with_config(config).await.unwrap();
    let info = well_known(&server).await;
    let active: Vec<String> = info["unsafe_options_active"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(active.contains(&"federation.dangerously_allow_plaintext_federation".to_string()));
}

#[tokio::test]
async fn naively_allow_unknown_handles_surfaces_in_well_known() {
    let mut config = JigServerConfig::default();
    config.identity.naively_allow_unknown_handles_fallback = true;
    let server = TestJigServer::start_with_config(config).await.unwrap();
    let info = well_known(&server).await;
    let active: Vec<String> = info["unsafe_options_active"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(active.contains(&"identity.naively_allow_unknown_handles_fallback".to_string()));
}

#[tokio::test]
async fn list_handles_flag_surfaces_in_well_known() {
    let mut config = JigServerConfig::default();
    config.debug.list_handles = true;
    let server = TestJigServer::start_with_config(config).await.unwrap();
    let info = well_known(&server).await;
    let active: Vec<String> = info["unsafe_options_active"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(active.contains(&"debug.list_handles".to_string()));
}

#[tokio::test]
async fn all_antipatterns_simultaneously_advertised() {
    let mut config = JigServerConfig::default();
    config.federation.dangerously_disable_federation_tls = true;
    config.federation.dangerously_allow_plaintext_federation = true;
    config.identity.naively_allow_unknown_handles_fallback = true;
    config.debug.list_handles = true;

    let server = TestJigServer::start_with_config(config).await.unwrap();
    let info = well_known(&server).await;
    let active: Vec<String> = info["unsafe_options_active"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    for expected in [
        "federation.dangerously_disable_federation_tls",
        "federation.dangerously_allow_plaintext_federation",
        "identity.naively_allow_unknown_handles_fallback",
        "debug.list_handles",
    ] {
        assert!(
            active.contains(&expected.to_string()),
            "well-known unsafe_options_active must include `{expected}` (got {active:?})"
        );
    }
}

#[tokio::test]
async fn well_known_exposes_server_did_and_allowed_block_kinds() {
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let info = well_known(&server).await;

    assert!(
        info["server_did"]
            .as_str()
            .unwrap_or("")
            .starts_with("did:jig:z"),
        "server_did must be present in canonical form"
    );

    let kinds: Vec<String> = info["allowed_block_kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(kinds.contains(&"text-render".to_string()));
    assert!(kinds.contains(&"channel-create".to_string()));
    assert!(kinds.contains(&"member-add".to_string()));
}
