//! A nameserver serves TLS by default, with a self-signed certificate its DID
//! vouches for at `/.well-known/jig-ns`. Both resolvers that ask
//! `config`-delegated nameservers (the client's `NameResolver` and the
//! server's `NameserverResolver`) reach it only over TLS bound to one of the
//! suffix's authorities: never on a CA's word, never in plaintext unless the
//! operator opts in for local testing.

use std::collections::BTreeMap;
use std::sync::Arc;

use integration_tests::harness::TestNameserver;
use jig_client::naming::{
    ConfigDelegation, Delegations, NameEvidence, NameEvidenceBundle, NameKey, NamePin, NamePins,
    NameResolver, ResolveError, Verified,
};
use jig_pipeline::identity::{IdentityError, NameserverResolver};
use jig_pipeline::persist::SqliteStore;
use jig_server::v0_0_2::suffix_authorities;
use jig_server::v0_0_2_nameserver_tls::BoundNameservers;

struct NoPins;
impl NamePins for NoPins {
    fn name_pin(&self, _: &NameKey) -> Option<NamePin> {
        None
    }
}

struct NoEvidence;
impl NameEvidence for NoEvidence {
    fn record(&self, _: &NameEvidenceBundle) -> Result<(), String> {
        Ok(())
    }
}

/// `ns`'s suffix delegated to `authorities`, asked at `ns`'s URL.
fn client_delegations(ns: &TestNameserver, authorities: Vec<String>) -> Delegations {
    Delegations {
        config: BTreeMap::from([(
            ns.alias_suffix.clone(),
            ConfigDelegation {
                authorities,
                nameservers: vec![ns.http_url()],
            },
        )]),
        dangerously_allow_plaintext_nameservers: false,
    }
}

/// The server's resolver for `ns`'s suffix, as jig-server boots it.
fn server_resolver(
    ns: &TestNameserver,
    authorities: Vec<String>,
    allow_plaintext: bool,
) -> NameserverResolver {
    let mut delegations = ns.delegations();
    for d in delegations.values_mut() {
        d.authorities = authorities.clone();
    }
    NameserverResolver::new(
        suffix_authorities(&delegations),
        1,
        Arc::new(SqliteStore::open_in_memory().unwrap()),
        Arc::new(BoundNameservers { allow_plaintext }),
    )
}

#[tokio::test]
async fn both_resolvers_reach_a_default_tls_nameserver_through_its_did() {
    let ns = TestNameserver::start_tls_with_suffix("dj.jig")
        .await
        .unwrap();
    assert!(ns.http_url().starts_with("https://"));
    let alice = ns.register("alice").await.unwrap();
    let ns_did = ns.state.ns_did_string();
    // The lists are not paired: any listed authority vouching will do.
    let other = jig_core::Did::from_ed25519_pubkey(&[7u8; 32]).to_did_jig_string();
    let authorities = vec![other, ns_did];

    let verified = NameResolver::new()
        .resolve(
            "alice@dj.jig",
            &client_delegations(&ns, authorities.clone()),
            &NoPins,
            &NoEvidence,
        )
        .await
        .expect("the client resolves over DID-bound TLS");
    let Verified::New(binding) = verified else {
        panic!("nothing pinned, so new: {verified:?}");
    };
    assert_eq!(binding.did(), alice.did_string());

    let did = server_resolver(&ns, authorities, false)
        .resolve("alice@dj.jig")
        .await
        .expect("the server resolves over DID-bound TLS");
    assert_eq!(did, alice.did_string());
}

#[tokio::test]
async fn a_nameserver_bound_to_an_unlisted_did_is_refused_by_both() {
    let ns = TestNameserver::start_tls_with_suffix("dj.jig")
        .await
        .unwrap();
    ns.register("alice").await.unwrap();
    let listed = vec![jig_core::Did::from_ed25519_pubkey(&[7u8; 32]).to_did_jig_string()];

    let err = NameResolver::new()
        .resolve(
            "alice@dj.jig",
            &client_delegations(&ns, listed.clone()),
            &NoPins,
            &NoEvidence,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, ResolveError::Untrusted { ref reason, .. } if reason.contains("not one of the authorities")),
        "{err:?}"
    );

    let err = server_resolver(&ns, listed, false)
        .resolve("alice@dj.jig")
        .await
        .unwrap_err();
    assert!(
        matches!(err, IdentityError::UntrustedNameserver(ref e) if e.contains("not one of the authorities")),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_plaintext_nameserver_is_refused_unless_the_resolver_opts_in() {
    let ns = TestNameserver::start_with_suffix("dj.jig").await.unwrap();
    assert!(ns.http_url().starts_with("http://"));
    let alice = ns.register("alice").await.unwrap();
    let authorities = vec![ns.state.ns_did_string()];

    let err = NameResolver::new()
        .resolve(
            "alice@dj.jig",
            &client_delegations(&ns, authorities.clone()),
            &NoPins,
            &NoEvidence,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, ResolveError::Untrusted { ref reason, .. } if reason.contains("plaintext")),
        "{err:?}"
    );
    let err = server_resolver(&ns, authorities.clone(), false)
        .resolve("alice@dj.jig")
        .await
        .unwrap_err();
    assert!(
        matches!(err, IdentityError::UntrustedNameserver(ref e) if e.contains("plaintext")),
        "{err:?}"
    );

    // Opted in, for loopback testing, both resolve; every attestation is
    // still verified.
    let verified = NameResolver::new()
        .resolve(
            "alice@dj.jig",
            &Delegations {
                dangerously_allow_plaintext_nameservers: true,
                ..client_delegations(&ns, authorities.clone())
            },
            &NoPins,
            &NoEvidence,
        )
        .await
        .unwrap();
    let (Verified::New(b) | Verified::Pinned(b) | Verified::Rotated { binding: b, .. }) = verified;
    assert_eq!(b.did(), alice.did_string());
    assert_eq!(
        server_resolver(&ns, authorities, true)
            .resolve("alice@dj.jig")
            .await
            .unwrap(),
        alice.did_string()
    );
}
