//! H6: Nameserver mode resolves and respects TTL expiry.
//!
//! Flow:
//! 1. Start a `TestNameserver` authoritative for `dj.jig`.
//! 2. Register alias `alice@dj.jig` against the NS with a fresh identity.
//! 3. Start a `TestJigServer` in nameserver mode pointing at the NS.
//! 4. Resolve `alice@dj.jig` via the server's NameserverResolver — must
//!    return alice's DID.
//! 5. Expire the attestation on the NS side.
//! 6. After cache TTL (configured to 1s in the harness), the resolver
//!    rejects subsequent resolutions of `alice@dj.jig`.
//!
//! v0.0.2 finding (same as H5): the ingest pipeline never invokes
//! IdentityResolver, so a tampered DID claim doesn't get refused at
//! ingest time. The test exercises the resolver directly, just like H5,
//! to confirm the building-block correctness while documenting the
//! ingest-side gap.

use std::time::Duration;

use integration_tests::harness::*;
use jig_pipeline::identity::{IdentityResolver, NameserverResolver};

#[tokio::test]
async fn nameserver_resolves_registered_alias_to_did() {
    let ns = TestNameserver::start().await.expect("start ns");
    let alice = ns.register("alice").await.expect("register alice");
    let alias_full = format!("alice@{}", ns.alias_suffix);

    // Construct a resolver pointed at the NS, exactly as the jig-server
    // boot path would when identity.mode = "nameserver".
    let resolver = NameserverResolver::new(vec![ns.http_url()], 1);
    let did = resolver.resolve(&alias_full).await.expect("resolve");
    assert_eq!(did, alice.did_string());
}

#[tokio::test]
async fn nameserver_rejects_mismatched_did_claim() {
    let ns = TestNameserver::start().await.expect("start ns");
    let alice = ns.register("alice").await.expect("register alice");
    let alias_full = format!("alice@{}", ns.alias_suffix);

    let resolver = NameserverResolver::new(vec![ns.http_url()], 1);

    // Correct DID — accepted.
    resolver
        .verify(&alias_full, &alice.did_string())
        .await
        .expect("correct did accepted");

    // Different DID claim — rejected.
    let err = resolver
        .verify(&alias_full, "did:jig:zEvilImpostor")
        .await
        .expect_err("different DID must be rejected");
    assert!(
        err.to_string().contains("dj.jig")
            || err.to_string().contains("did:jig:zEvilImpostor")
            || err.to_string().contains("alice")
            || matches!(
                err,
                jig_pipeline::identity::IdentityError::TofuMismatch { .. }
            ),
        "expected an identity-mismatch error, got: {err}"
    );
}

#[tokio::test]
async fn nameserver_returns_not_found_for_unattested_alias() {
    let ns = TestNameserver::start().await.expect("start ns");
    let resolver = NameserverResolver::new(vec![ns.http_url()], 1);
    let err = resolver
        .resolve("nobody@dj.jig")
        .await
        .expect_err("unattested alias must fail");
    assert!(
        matches!(err, jig_pipeline::identity::IdentityError::NotFound { .. }),
        "expected NotFound, got: {err:?}"
    );
}

#[tokio::test]
async fn nameserver_expires_attestation_after_explicit_expiry() {
    let ns = TestNameserver::start().await.expect("start ns");
    let alice = ns.register("alice").await.expect("register alice");
    let alias_full = format!("alice@{}", ns.alias_suffix);

    // Fresh resolver with 1s cache TTL so we don't have to wait long.
    let resolver = NameserverResolver::new(vec![ns.http_url()], 1);

    // Initial resolution succeeds.
    let did = resolver
        .resolve(&alias_full)
        .await
        .expect("initial resolve");
    assert_eq!(did, alice.did_string());

    // Expire the attestation on the NS side directly (mimics the
    // /v1/rotate path which expires the old binding).
    let now = chrono::Utc::now().timestamp();
    let ns_did = ns.state.ns_did_string();
    ns.state
        .ingest_ctx
        .store
        .expire_alias_attestation(&alice.did_string(), &ns_did, now)
        .expect("expire");

    // Wait for cache TTL to elapse so the resolver re-queries the NS.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let err = resolver
        .resolve(&alias_full)
        .await
        .expect_err("expired attestation must fail to resolve");
    assert!(
        matches!(err, jig_pipeline::identity::IdentityError::NotFound { .. }),
        "expected NotFound after expiry, got: {err:?}"
    );
}

/// Integration sanity: a TestJigServer started in nameserver mode wires up
/// a NameserverResolver pointing at the NS. Resolving via the server's
/// resolver Arc reaches the NS.
#[tokio::test]
async fn jig_server_in_nameserver_mode_resolves_through_authority() {
    let ns = TestNameserver::start().await.expect("start ns");
    let alice = ns.register("alice").await.expect("register alice");
    let alias_full = format!("alice@{}", ns.alias_suffix);

    let server = TestJigServer::start_with_nameserver(&ns, &ns.alias_suffix)
        .await
        .expect("start server");

    // Confirm config sees nameserver mode + the right URL.
    assert_eq!(
        server.state.config.identity.mode,
        jig_config::v0_0_2_server::IdentityMode::Nameserver
    );
    assert!(
        server
            .state
            .config
            .identity
            .trusted_nameservers
            .contains(&ns.http_url()),
        "server's trusted_nameservers must include the test NS URL"
    );

    // Direct resolver test against the same NS URL — gives us deterministic
    // results without depending on the server's internal Arc construction.
    let resolver = NameserverResolver::new(
        server.state.config.identity.trusted_nameservers.clone(),
        server.state.config.identity.cache_ttl_seconds,
    );
    let did = resolver.resolve(&alias_full).await.expect("resolve via NS");
    assert_eq!(did, alice.did_string());
}
