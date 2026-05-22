//! H5: TOFU mode locks nickname-to-DID binding (or documents the gap).
//!
//! Intended behavior (per the v0.0.2 design memo):
//! - First submission claiming nickname `dj` with DID A is accepted; the
//!   pair is locked in the `tofu_keys` table.
//! - Subsequent submission claiming nickname `dj` with DID B (different
//!   keypair) is rejected unless `naively_allow_unknown_handles_fallback`
//!   is enabled.
//!
//! v0.0.2 finding: the ingest pipeline (`jig_pipeline::ingest::ingest`)
//! constructs an `IdentityResolver` at boot but never invokes it. Signing
//! is verified at the ed25519 layer (`verify_sig`), but the identifier-
//! to-DID mapping is not exercised. As a result, two different DIDs can
//! submit blocks regardless of nickname conflict.
//!
//! This test EXERCISES the TofuResolver directly (via the AppState's
//! identity Arc) to confirm the LOCKING behavior of the resolver is
//! intact. That's the unit-level guarantee the ingest layer would
//! consume once it wires resolver-checks into the pipeline. The test
//! also documents the v0.0.2 gap so the v0.0.3 follow-up has a clear
//! starting point.

use integration_tests::harness::*;
use jig_pipeline::identity::{IdentityError, IdentityResolver, TofuResolver};
use std::sync::Arc;

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

/// Documents the v0.0.2 gap: ingest does NOT consult the IdentityResolver.
/// Both Alice (DID A) and Bob (DID B) can submit text-render blocks to the
/// same server in v0.0.2 even though neither nickname is bound. This test
/// captures the current behavior; v0.0.3 should make the equivalent
/// scenario produce an INVALID_SIG / IDENTITY_ERROR on the second submit.
#[tokio::test]
async fn v0_0_2_ingest_does_not_enforce_tofu_lock_documented_gap() {
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let (alice, _alice_dir) = test_identity_with_dir();
    let (bob, _bob_dir) = test_identity_with_dir();
    assert_ne!(
        alice.did_string(),
        bob.did_string(),
        "alice and bob have distinct DIDs"
    );

    // Both submit successfully — ingest only checks the ed25519 sig, not
    // any nickname-to-DID locking. Each block is signed with its sender's
    // own key, so verify_sig passes. The resolver is never consulted.
    let cid_a = server
        .send_text_render(&alice, "#hello", "alice's first message")
        .await
        .expect("alice submits");
    let cid_b = server
        .send_text_render(&bob, "#hello", "bob's first message")
        .await
        .expect("bob submits");
    assert_ne!(cid_a, cid_b);

    // Both blocks are stored. The TOFU table is empty (nothing wrote to it
    // because ingest doesn't call resolver.verify).
    assert!(server.block_for(&cid_a).unwrap().is_some());
    assert!(server.block_for(&cid_b).unwrap().is_some());
    let tofu_key = server
        .state
        .ingest_ctx
        .store
        .get_tofu_key("alice")
        .expect("get_tofu_key");
    assert!(
        tofu_key.is_none(),
        "v0.0.2 ingest never inserts into tofu_keys (documented gap; v0.0.3 wires it in)"
    );

    // Sanity: the resolver, if invoked manually, WOULD reject the second
    // claim. This is the v0.0.3 wiring target.
    let resolver: Arc<TofuResolver> =
        Arc::new(TofuResolver::new(server.state.ingest_ctx.store.clone()));
    resolver
        .verify("alice", &alice.did_string())
        .await
        .expect("first verify ok");
    let err = resolver
        .verify("alice", &bob.did_string())
        .await
        .expect_err("second verify with mismatched did must reject");
    assert!(matches!(err, IdentityError::TofuMismatch { .. }));
}
