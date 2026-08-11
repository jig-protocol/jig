//! H5: TOFU mode locks nickname-to-DID binding.
//!
//! Behavior (per the v0.0.2 design memo, enforced by v0.0.3-alpha.1c Task 1.2):
//! - First submission claiming nickname `dj` with DID A is accepted; the
//!   pair is locked in the `tofu_keys` table.
//! - Subsequent submission claiming nickname `dj` with DID B (different
//!   keypair) is rejected unless `naively_allow_unknown_handles_fallback`
//!   is enabled.
//!
//! v0.0.2 blocks have no first-class nickname field; the ingest pipeline
//! reads `manifest.metadata["nickname"]` (a string) and, when present,
//! invokes `IdentityResolver::verify(nickname, sender_did)`. Blocks that
//! omit the nickname are not subject to TOFU lock at ingest time — this
//! is the documented v0.0.2 carve-out, lifted in v0.0.3+ when channel/
//! membership blocks make the identifier explicit.

use integration_tests::harness::*;
use jig_pipeline::identity::{IdentityError, IdentityResolver, TofuResolver};

#[tokio::test]
async fn tofu_resolver_locks_nickname_to_first_did_seen() {
    let server = TestJigServer::start_with_full_kinds()
        .await
        .expect("start server");

    // Get a Arc<TofuResolver> view by constructing one with the SAME
    // store the server uses — that way the test exercises the same
    // persist-layer state ingest WOULD touch.
    let resolver = TofuResolver::new(server.state.ingest_ctx.store.clone());

    let did_alice = "did:jig:zAlice";
    let did_bob = "did:jig:zBob";

    // First submission with nickname=dj locks the pair to did_alice.
    resolver
        .verify("dj", did_alice)
        .await
        .expect("first verify locks");

    // Repeat with same DID — accepted (idempotent).
    resolver
        .verify("dj", did_alice)
        .await
        .expect("same DID re-verify");

    // Different DID for the SAME nickname — rejected.
    let err = resolver
        .verify("dj", did_bob)
        .await
        .expect_err("different DID for same nickname must be rejected");
    assert!(
        matches!(err, IdentityError::TofuMismatch { .. }),
        "expected TofuMismatch, got {err:?}"
    );
}

#[tokio::test]
async fn tofu_resolver_rejects_invalid_nicknames_with_at_or_colon() {
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let resolver = TofuResolver::new(server.state.ingest_ctx.store.clone());

    let err = resolver
        .verify("dj@dj.jig", "did:jig:zAlice")
        .await
        .expect_err("@-bearing nickname must be rejected");
    assert!(matches!(err, IdentityError::InvalidNickname));
}

/// v0.0.3-alpha.1c: ingest now consults the IdentityResolver between
/// signature verification and the kind whitelist. When a block carries a
/// `nickname` field in `manifest.metadata`, the resolver locks the
/// `(nickname → sender_did)` pair on first sight and rejects subsequent
/// submissions under the same nickname with a different DID.
///
/// Closes #3. See also `naively_allow_unknown_handles_fallback_bypasses_lock`
/// below for the carve-out path.
#[tokio::test]
async fn v0_0_2_ingest_enforces_tofu_lock() {
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let (alice, _alice_dir) = test_identity_with_dir();
    let (bob, _bob_dir) = test_identity_with_dir();
    // Precondition: ingest now rejects text-render for an unknown channel.
    // Seeded directly so this test stays about the TOFU nickname lock, not channel setup.
    server.seed_channel(&alice, "#hello").expect("seed channel");
    assert_ne!(
        alice.did_string(),
        bob.did_string(),
        "alice and bob have distinct DIDs"
    );

    // Alice's first submit under nickname `dj` locks dj → alice's DID.
    let cid_a = send_text_render_with_nickname(&server, &alice, "#hello", "alice first", "dj")
        .await
        .expect("alice submits with nickname dj");
    assert!(server.block_for(&cid_a).unwrap().is_some());

    // Alice resubmitting under the same nickname is fine — same DID.
    let cid_a2 = send_text_render_with_nickname(&server, &alice, "#hello", "alice second", "dj")
        .await
        .expect("alice idempotent resubmit");
    assert_ne!(cid_a, cid_a2);

    // Bob claims the same nickname `dj` but signs with his own (different)
    // DID. Ingest must reject this as a TOFU mismatch.
    let err = send_text_render_with_nickname(&server, &bob, "#hello", "bob first", "dj")
        .await
        .expect_err("bob impersonating dj must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("401") || msg.to_lowercase().contains("unauthorized"),
        "expected 401/UNAUTHORIZED on TOFU mismatch, got: {msg}"
    );

    // Bob CAN submit under his own distinct nickname.
    let cid_b = send_text_render_with_nickname(&server, &bob, "#hello", "bob first", "bob")
        .await
        .expect("bob submits under nickname `bob`");
    assert!(server.block_for(&cid_b).unwrap().is_some());

    // The tofu_keys table now has both bindings.
    let dj = server
        .state
        .ingest_ctx
        .store
        .get_tofu_key("dj")
        .expect("get_tofu_key dj");
    assert_eq!(
        dj.expect("dj row present").did,
        alice.did_string(),
        "nickname dj is locked to alice's DID"
    );
    let bob_row = server
        .state
        .ingest_ctx
        .store
        .get_tofu_key("bob")
        .expect("get_tofu_key bob");
    assert_eq!(bob_row.expect("bob row present").did, bob.did_string());
}

/// Build, sign, and POST a text-render block whose manifest metadata carries
/// an explicit `nickname` field. v0.0.2's canonical builders don't surface
/// the field directly, so we wire it in by extending the manifest after the
/// builder runs. Returns the CID on 2xx, or the harness error on 4xx/5xx.
async fn send_text_render_with_nickname(
    server: &TestJigServer,
    sender: &jig_client::Identity,
    channel_slug: &str,
    body: &str,
    nickname: &str,
) -> anyhow::Result<String> {
    use base64::Engine as _;
    use jig_core::{Author, BlockKind, BlockManifest, HlcTimestamp};

    let hlc = HlcTimestamp {
        wall_ms: chrono::Utc::now().timestamp_millis() as u64,
        logical: 0,
        server_did: sender.did().clone(),
    };
    let manifest = BlockManifest::builder()
        .version(semver::Version::new(0, 1, 0))
        .author(Author {
            did: sender.did().clone(),
            public_key: None,
            roles: vec![],
        })
        .metadata_entry("channel", serde_json::json!(channel_slug))
        .metadata_entry("body", serde_json::json!(body))
        .metadata_entry("nickname", serde_json::json!(nickname))
        .build()
        .expect("manifest builds")
        .with_kind(BlockKind::TextRender)
        .with_hlc(hlc);
    let manifest_bytes = manifest.to_canonical_bytes().expect("canonical bytes");
    let code_bytes: Vec<u8> = vec![];
    let canonical = serde_json::to_vec(&(&manifest_bytes, &code_bytes)).unwrap();
    let sig = sender.sign(&canonical).to_bytes().to_vec();
    let payload = serde_json::json!({
        "bundle_b64": base64::engine::general_purpose::STANDARD.encode(&canonical),
        "sig_b64": base64::engine::general_purpose::STANDARD.encode(&sig),
    });
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/blocks", server.http_url()))
        .json(&payload)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("submit failed: {status} body={body}");
    }
    let body: serde_json::Value = resp.json().await?;
    Ok(body["block_cid"].as_str().unwrap_or_default().to_string())
}

/// `identity.naively_allow_unknown_handles_fallback = true` lets the second
/// submission through with a logged warning instead of rejecting it.
#[tokio::test]
async fn naively_allow_unknown_handles_fallback_bypasses_lock() {
    use jig_config::v0_0_2_server::{IdentityMode, IdentitySection};
    let mut config = {
        // base_config is private to the harness, so build via a default start
        // and then mutate identity. We rebuild a fresh server with the flag
        // enabled by going through start_with_config.
        let mut cfg = jig_config::v0_0_2_server::JigServerConfig::default();
        cfg.server.allowed_block_kinds = vec![
            "text-render".to_string(),
            "channel-create".to_string(),
            "member-add".to_string(),
            "fed-hello".to_string(),
        ];
        cfg.debug.admin_endpoints = true;
        cfg
    };
    config.identity = IdentitySection {
        mode: IdentityMode::Tofu,
        trusted_nameservers: vec![],
        cache_ttl_seconds: 300,
        naively_allow_unknown_handles_fallback: true,
    };
    let server = TestJigServer::start_with_config(config).await.unwrap();

    let (alice, _alice_dir) = test_identity_with_dir();
    let (bob, _bob_dir) = test_identity_with_dir();
    // Precondition: ingest now rejects text-render for an unknown channel.
    // Seeded directly so this test stays about the fallback antipattern flag, not channel setup.
    server.seed_channel(&alice, "#hello").expect("seed channel");

    let _cid_a = send_text_render_with_nickname(&server, &alice, "#hello", "alice", "dj")
        .await
        .expect("alice first ok");

    // With the bypass enabled, bob impersonating `dj` is accepted.
    let cid_b = send_text_render_with_nickname(&server, &bob, "#hello", "bob", "dj")
        .await
        .expect("bypass allows bob to impersonate dj");
    assert!(server.block_for(&cid_b).unwrap().is_some());
}
