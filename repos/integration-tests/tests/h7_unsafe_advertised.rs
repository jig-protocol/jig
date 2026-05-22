//! H7: Unsafe options are actively advertised in `/.well-known/jig`.
//!
//! Every antipattern flag — listed in `JigServerConfig::unsafe_options_active`
//! — must surface in the server's well-known discovery JSON so federated
//! peers can detect a misconfigured neighbor and refuse to peer with it.
//!
//! v0.0.2 always lists `naively_unbounded_clock_skew` (no time-attestation
//! servers exist yet). The other flags only appear when explicitly enabled
//! in the server config:
//!   - `debug.admin_endpoints`
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
async fn default_install_always_advertises_unbounded_clock_skew() {
    // Even with no antipatterns enabled, naively_unbounded_clock_skew must
    // be present — it captures the v0.0.2 reality that no time-attestation
    // server exists yet.
    let mut config = JigServerConfig::default();
    // No debug.admin_endpoints, no TLS-disabled, no allow-unknown-handles.
    // (Default config already has these off, but be explicit.)
    config.debug = DebugSection::default();
    config.identity = IdentitySection::default();

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
        active.contains(&"naively_unbounded_clock_skew".to_string()),
        "default install must always advertise naively_unbounded_clock_skew (got {active:?})"
    );
}

#[tokio::test]
async fn admin_endpoints_flag_surfaces_in_well_known() {
    let mut config = JigServerConfig::default();
    config.debug.admin_endpoints = true;
    let server = TestJigServer::start_with_config(config).await.unwrap();
    let info = well_known(&server).await;
    let active: Vec<String> = info["unsafe_options_active"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(active.contains(&"debug.admin_endpoints".to_string()));
    assert!(active.contains(&"naively_unbounded_clock_skew".to_string()));
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
    config.debug.admin_endpoints = true;
    config.federation.dangerously_disable_federation_tls = true;
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
        "naively_unbounded_clock_skew",
        "debug.admin_endpoints",
        "federation.dangerously_disable_federation_tls",
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
