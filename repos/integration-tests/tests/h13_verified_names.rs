//! H13: verified names end to end, against lying nameservers and a lying
//! server (F1 slice 7; JEP-0004 rules 4, 6, 9 and 13–20).
//!
//! The nameservers run `jig-nameserver`'s production router and the jig
//! server is a real one. Bob's client is `jig_client`'s resolver, name pins
//! and evidence directory, called the way `jig dm alice@<suffix>` calls them
//! (`jig-cli/src/cmd/trust.rs`, `verify_name`): resolve, then pin a new or
//! matching name, and hand anything else back as an error. Each case asserts
//! what Bob's client does. That the CLI sends nothing to the server about a
//! refused name is `jig-cli/tests/verified_names.rs`.

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use integration_tests::harness::*;
use jig_client::Identity;
use jig_client::evidence::NameEvidenceDir;
use jig_client::naming::{
    ConfigDelegation, Delegations, MismatchReason, NameKey, NamePin, NamePins, NameResolver,
    ResolveError, Verified,
};
use jig_client::pins::Pins;
use jig_client::secure::Session;
use jig_core::naming::{Action, NamingError};
use jig_core::{BlockKind, HlcTimestamp};
use serde_json::json;
use tempfile::TempDir;

const SUFFIX: &str = "h13.example.org";

fn alice_name() -> String {
    format!("alice@{SUFFIX}")
}

/// Someone with a key and the MLS state `jig` keeps for them.
struct Person {
    key: SigningKey,
    id: Identity,
    session: Session,
    _dir: TempDir,
}

impl Person {
    fn new() -> Self {
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::from_signing_key(key.clone());
        let session = Session::open(dir.path(), id.duplicate()).unwrap();
        Self {
            key,
            id,
            session,
            _dir: dir,
        }
    }

    fn did(&self) -> String {
        self.id.did_string()
    }
}

/// Bob's client: his person, plus the name pins and evidence `jig` keeps in
/// `~/.jig`.
struct Bob {
    me: Person,
    home: TempDir,
}

impl Bob {
    fn new() -> Self {
        Self {
            me: Person::new(),
            home: tempfile::tempdir().unwrap(),
        }
    }

    fn pins_path(&self) -> PathBuf {
        self.home.path().join("pins.json")
    }

    fn evidence(&self) -> NameEvidenceDir {
        NameEvidenceDir::new(&self.home.path().join("evidence"))
    }

    /// `verify_name`: resolve `name`, pin it if it is new or matches, and
    /// return anything else as the error.
    async fn verify(
        &self,
        resolver: &NameResolver,
        delegations: &Delegations,
        name: &str,
    ) -> Result<Verified, ResolveError> {
        let mut pins = Pins::load(&self.pins_path()).unwrap();
        let verified = resolver
            .resolve(name, delegations, &pins, &self.evidence())
            .await?;
        match &verified {
            Verified::New(b) | Verified::Pinned(b) => pins.pin_name(b).unwrap(),
            Verified::Rotated { binding, .. } => {
                pins.accept_name(binding, binding.did()).unwrap();
            }
        }
        Ok(verified)
    }

    /// `jig trust accept-name <name> --did <confirmed>`: the name's holder
    /// confirmed its new DID out of band (rule 9).
    async fn accept(&self, delegations: &Delegations, name: &str, confirmed: &str) {
        struct Unpinned;
        impl NamePins for Unpinned {
            fn name_pin(&self, _: &NameKey) -> Option<NamePin> {
                None
            }
        }
        let binding = match NameResolver::new()
            .resolve(name, delegations, &Unpinned, &self.evidence())
            .await
            .unwrap()
        {
            Verified::New(b) | Verified::Pinned(b) | Verified::Rotated { binding: b, .. } => b,
        };
        Pins::load(&self.pins_path())
            .unwrap()
            .accept_name(&binding, confirmed)
            .unwrap();
    }

    /// The DID `name` is pinned to, and until when the pinned attestation
    /// holds.
    fn pinned(&self, name: &str) -> Option<(String, i64)> {
        Pins::load(&self.pins_path())
            .unwrap()
            .names()
            .iter()
            .find(|e| format!("{}@{}", e.alias, e.suffix) == name)
            .map(|e| (e.did.clone(), e.valid_until))
    }

    /// Every evidence file kept so far.
    fn kept(&self) -> Vec<serde_json::Value> {
        let dir = self.home.path().join("evidence");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        entries
            .map(|e| serde_json::from_slice(&std::fs::read(e.unwrap().path()).unwrap()).unwrap())
            .collect()
    }
}

fn did_of(v: &Verified) -> &str {
    match v {
        Verified::New(b) | Verified::Pinned(b) | Verified::Rotated { binding: b, .. } => b.did(),
    }
}

/// Bob's `[naming.delegations]` entry for [`SUFFIX`]: whose attestations
/// count, and whom to ask.
fn delegation(authorities: &[&TestNameserver], nameservers: &[String]) -> Delegations {
    Delegations {
        config: [(
            SUFFIX.to_string(),
            ConfigDelegation {
                authorities: authorities
                    .iter()
                    .map(|n| n.state.ns_did_string())
                    .collect(),
                nameservers: nameservers.to_vec(),
            },
        )]
        .into(),
        refused: Default::default(),
        // The test nameservers serve plaintext http on loopback. Without
        // this the resolver refuses them before any lookup, and the lying
        // server's case would fail for the wrong reason.
        dangerously_allow_plaintext_nameservers: true,
    }
}

async fn challenge(ns: &TestNameserver) -> String {
    let body: serde_json::Value = reqwest::get(format!("{}/v1/challenge", ns.http_url()))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["challenge"].as_str().unwrap().to_string()
}

/// A nameserver for [`SUFFIX`] without proof-of-work: this file builds
/// renew and rotate requests by hand, as a client did before JEP-0008, and is
/// about verified names, not the work (jig-cli's round trips cover that).
async fn nameserver() -> TestNameserver {
    TestNameserver::start_with_pow(SUFFIX, PowPolicy::off())
        .await
        .unwrap()
}

async fn post(ns: &TestNameserver, path: &str, body: serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("{}{path}", ns.http_url()))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status.is_success(),
        "{path}: {status} {}",
        resp.text().await.unwrap_or_default()
    );
}

/// `jig keys rotate`: both keys sign the challenge.
async fn rotate(ns: &TestNameserver, alias: &str, old: &Person, new: &Person) {
    let challenge = challenge(ns).await;
    let sig = |k: &SigningKey| STANDARD.encode(k.sign(challenge.as_bytes()).to_bytes());
    let body = json!({
        "alias": alias,
        "old_did": old.did(),
        "new_did": new.did(),
        "challenge": challenge,
        "sig_by_old": sig(&old.key),
        "sig_by_new": sig(&new.key),
    });
    post(ns, "/v1/rotate", body).await;
}

/// `jig keys renew`: a fresh validity window for the same DID.
async fn renew(ns: &TestNameserver, alias: &str, holder: &Person) {
    let challenge = challenge(ns).await;
    let proof = jig_core::naming::sign_proof(
        &holder.key,
        Action::Renew,
        &ns.state.ns_did_string(),
        alias,
        &challenge,
    );
    let body = json!({
        "alias": alias,
        "did": holder.did(),
        "challenge": challenge,
        "proof_of_control": URL_SAFE_NO_PAD.encode(proof),
    });
    post(ns, "/v1/renew", body).await;
}

/// What `jig dm` does once the name has verified: open the pair's locked,
/// encrypted channel, naming the verified DID as `dm_peer`, and add that DID.
async fn open_dm(server: &TestJigServer, bob: &Person, peer: &Person) -> String {
    let slug = jig_core::dm::dm_slug(&bob.did(), &peer.did());
    let created = bob.session.create_group(&server.http_url(), &slug).unwrap();
    let block = jig_client::blocks::build_with_metadata(
        &bob.id,
        BlockKind::ChannelCreate,
        HlcTimestamp::now_wall(bob.id.did().clone()),
        json!({
            "slug": slug,
            "visibility": "restricted",
            "suite": "mls",
            "dm": true,
            "dm_peer": peer.did(),
            "mls_group_info": STANDARD.encode(&created.group_info),
            "mls_ratchet_tree": STANDARD.encode(&created.ratchet_tree),
        }),
    );
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/channels", server.http_url()))
        .json(&json!({
            "bundle_b64": STANDARD.encode(block.canonical_bytes()),
            "sig_b64": STANDARD.encode(&block.sender_sig),
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    server
        .add_restricted_member(&bob.id, &bob.session, &slug, &peer.session)
        .await
        .unwrap();
    slug
}

/// Who the server holds as members of `slug`.
fn members(server: &TestJigServer, slug: &str) -> Vec<String> {
    let store = &server.state.ingest_ctx.store;
    let Some(channel) = store.get_channel_by_slug(slug).unwrap() else {
        return Vec::new();
    };
    let mut dids: Vec<String> = store
        .list_members(&channel.id)
        .unwrap()
        .into_iter()
        .map(|m| m.member_did)
        .collect();
    dids.sort();
    dids
}

fn pair(a: &Person, b: &Person) -> Vec<String> {
    let mut dids = vec![a.did(), b.did()];
    dids.sort();
    dids
}

/// Honest: a name that verifies is pinned on first use, and the DM goes to
/// the DID it verified to.
#[tokio::test]
async fn an_honest_name_is_pinned_and_the_dm_opens() {
    let ns = nameserver().await;
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let alice = Person::new();
    ns.register_with_key("alice", &alice.key).await.unwrap();
    let bob = Bob::new();
    let d = delegation(&[&ns], &[ns.http_url()]);

    let first = bob
        .verify(&NameResolver::new(), &d, &alice_name())
        .await
        .unwrap();
    assert!(matches!(first, Verified::New(_)), "{first:?}");
    assert_eq!(did_of(&first), alice.did());
    assert_eq!(
        bob.pinned(&alice_name()).map(|p| p.0),
        Some(alice.did()),
        "pinned on first use"
    );

    let slug = open_dm(&server, &bob.me, &alice).await;
    assert_eq!(members(&server, &slug), pair(&bob.me, &alice));

    let again = bob
        .verify(&NameResolver::new(), &d, &alice_name())
        .await
        .unwrap();
    assert!(matches!(again, Verified::Pinned(_)), "{again:?}");
    let kept = bob.kept();
    assert!(
        !kept.is_empty() && kept.iter().all(|k| k["name"] == alice_name()),
        "what each resolution acted on is kept: {kept:?}"
    );
}

/// Substitution after pin: the nameserver re-binds the name to Mallory with
/// no rotation. Bob refuses, keeps his pin, and opens nothing to Mallory.
#[tokio::test]
async fn a_name_rebound_without_a_rotation_is_refused() {
    let ns = nameserver().await;
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let (alice, mallory) = (Person::new(), Person::new());
    ns.register_with_key("alice", &alice.key).await.unwrap();
    let bob = Bob::new();
    let d = delegation(&[&ns], &[ns.http_url()]);
    bob.verify(&NameResolver::new(), &d, &alice_name())
        .await
        .unwrap();

    // The operator drops Alice's binding and hands the name to Mallory.
    let now = chrono::Utc::now().timestamp();
    ns.state
        .ingest_ctx
        .store
        .expire_alias_attestation(&alice.did(), &ns.state.ns_did_string(), &alice_name(), now)
        .unwrap();
    ns.register_with_key("alice", &mallory.key).await.unwrap();

    let err = bob
        .verify(&NameResolver::new(), &d, &alice_name())
        .await
        .unwrap_err();
    // No rotation links were served at all, so the reason is a re-binding
    // rather than an unverifiable rotation.
    assert!(
        matches!(
            &err,
            ResolveError::PinMismatch { reason: MismatchReason::ReRegistered, old, new, .. }
                if *old == alice.did() && *new == mallory.did()
        ),
        "{err:?}"
    );
    assert_eq!(bob.pinned(&alice_name()).map(|p| p.0), Some(alice.did()));
    let dm = jig_core::dm::dm_slug(&bob.me.did(), &mallory.did());
    assert!(
        members(&server, &dm).is_empty(),
        "nothing opened to Mallory"
    );
}

/// Rotation: Alice moves her name to a new key, signed by both keys. Until
/// lane I's I3 has the nameserver serve rotation links (JEP-0012) that the
/// client verifies, a rotation looks to Bob like any other change of DID: it
/// is refused, and the pin moves only once Alice confirms the new DID and
/// Bob runs `jig trust accept-name`. When links are served, the first lookup
/// here becomes `Verified::Rotated` and the pin moves by itself.
#[tokio::test]
async fn a_rotation_moves_the_pin_once_its_holder_confirms_it() {
    let ns = nameserver().await;
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let (alice, alice2) = (Person::new(), Person::new());
    ns.register_with_key("alice", &alice.key).await.unwrap();
    let bob = Bob::new();
    let d = delegation(&[&ns], &[ns.http_url()]);
    bob.verify(&NameResolver::new(), &d, &alice_name())
        .await
        .unwrap();

    rotate(&ns, &alice_name(), &alice, &alice2).await;

    let err = bob
        .verify(&NameResolver::new(), &d, &alice_name())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ResolveError::PinMismatch { old, new, .. }
            if *old == alice.did() && *new == alice2.did()),
        "{err:?}"
    );
    assert_eq!(bob.pinned(&alice_name()).map(|p| p.0), Some(alice.did()));

    bob.accept(&d, &alice_name(), &alice2.did()).await;
    let after = bob
        .verify(&NameResolver::new(), &d, &alice_name())
        .await
        .unwrap();
    assert!(matches!(after, Verified::Pinned(_)), "{after:?}");
    assert_eq!(bob.pinned(&alice_name()).map(|p| p.0), Some(alice2.did()));
    let slug = open_dm(&server, &bob.me, &alice2).await;
    assert_eq!(members(&server, &slug), pair(&bob.me, &alice2));
}

/// Unauthorised signer: a nameserver Bob's delegation does not name as an
/// authority answers. Its attestation counts for nothing, alone or beside an
/// authoritative one.
#[tokio::test]
async fn a_signer_outside_the_delegation_is_refused() {
    let ns = nameserver().await;
    let rogue = nameserver().await;
    let (alice, mallory) = (Person::new(), Person::new());
    ns.register_with_key("alice", &alice.key).await.unwrap();
    rogue
        .register_with_key("alice", &mallory.key)
        .await
        .unwrap();
    let bob = Bob::new();

    let only_rogue = delegation(&[&ns], &[rogue.http_url()]);
    let err = bob
        .verify(&NameResolver::new(), &only_rogue, &alice_name())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ResolveError::Refused(NamingError::NotAuthoritative(signer, _))
            if *signer == rogue.state.ns_did_string()),
        "{err:?}"
    );
    assert_eq!(bob.pinned(&alice_name()), None, "nothing pinned");

    let both = delegation(&[&ns], &[ns.http_url(), rogue.http_url()]);
    let verified = bob
        .verify(&NameResolver::new(), &both, &alice_name())
        .await
        .unwrap();
    assert_eq!(
        did_of(&verified),
        alice.did(),
        "the rogue answer is ignored"
    );
}

/// Equivocation: two nameservers the delegation names both answer, with
/// different DIDs. Bob refuses the name and keeps one evidence bundle that
/// holds both signed attestations.
#[tokio::test]
async fn two_authorities_that_disagree_are_refused_with_evidence() {
    let one = nameserver().await;
    let two = nameserver().await;
    let (alice, mallory) = (Person::new(), Person::new());
    one.register_with_key("alice", &alice.key).await.unwrap();
    two.register_with_key("alice", &mallory.key).await.unwrap();
    let bob = Bob::new();
    let d = delegation(&[&one, &two], &[one.http_url(), two.http_url()]);

    let err = bob
        .verify(&NameResolver::new(), &d, &alice_name())
        .await
        .unwrap_err();
    let ResolveError::Equivocation { dids, .. } = &err else {
        panic!("expected an equivocation, got {err:?}");
    };
    assert_eq!(*dids, pair(&alice, &mallory));
    assert_eq!(bob.pinned(&alice_name()), None, "nothing pinned");

    let kept = bob.kept();
    assert_eq!(kept.len(), 1, "one bundle: {kept:?}");
    let bundle = &kept[0];
    assert_eq!(bundle["name"], alice_name());
    assert_eq!(bundle["attestations"].as_array().unwrap().len(), 2);
    let mut signers: Vec<String> = bundle["ns_dids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap().to_string())
        .collect();
    signers.sort();
    let mut expected = vec![one.state.ns_did_string(), two.state.ns_did_string()];
    expected.sort();
    assert_eq!(signers, expected);
    // Each kept attestation still verifies on its own, offline.
    for a in bundle["attestations"].as_array().unwrap() {
        let bytes = STANDARD.decode(a.as_str().unwrap()).unwrap();
        jig_core::naming::Attestation::from_envelope(&bytes).unwrap();
    }
}

/// Expired: with Bob's clock at the end of the pinned attestation's window,
/// the name is refused, even though the pin is still there. Bob asks again
/// each time rather than reusing what he pinned: once Alice renews, the same
/// clock verifies the fresh attestation.
#[tokio::test]
async fn an_expired_attestation_is_refused_and_a_renewed_one_is_fetched() {
    let ns = nameserver().await;
    let alice = Person::new();
    ns.register_with_key("alice", &alice.key).await.unwrap();
    let bob = Bob::new();
    let d = delegation(&[&ns], &[ns.http_url()]);
    bob.verify(&NameResolver::new(), &d, &alice_name())
        .await
        .unwrap();
    let (_, until) = bob.pinned(&alice_name()).unwrap();

    let at_expiry = NameResolver::new().with_clock(move || until);
    let err = bob.verify(&at_expiry, &d, &alice_name()).await.unwrap_err();
    assert!(
        matches!(err, ResolveError::Refused(NamingError::Expired(t)) if t == until),
        "{err:?}"
    );
    assert_eq!(
        bob.pinned(&alice_name()),
        Some((alice.did(), until)),
        "the pin is kept"
    );

    // A renewal issued at least a second later ends at least a second later.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    renew(&ns, &alice_name(), &alice).await;
    let verified = bob.verify(&at_expiry, &d, &alice_name()).await.unwrap();
    assert!(matches!(verified, Verified::Pinned(_)), "{verified:?}");
    let (_, renewed) = bob.pinned(&alice_name()).unwrap();
    assert!(renewed > until, "the pin holds the fresh window");
}

/// Server lies: Bob's own server, asked for the name, serves Alice's real
/// attestation with Mallory's DID put in its place. The client checks the
/// signature itself, so the forgery is refused alone and loses beside the
/// real nameserver.
#[tokio::test]
async fn a_forged_attestation_from_the_server_is_refused() {
    let ns = nameserver().await;
    let (alice, mallory) = (Person::new(), Person::new());
    ns.register_with_key("alice", &alice.key).await.unwrap();

    // The real answer, with the DID swapped. did:jig DIDs of ed25519 keys are
    // all one length, so the CBOR around it still parses.
    let real: serde_json::Value =
        reqwest::get(format!("{}/v1/resolve/{}", ns.http_url(), alice_name()))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let mut envelope = URL_SAFE_NO_PAD
        .decode(real["attestation"].as_str().unwrap())
        .unwrap();
    let (from, to) = (alice.did().into_bytes(), mallory.did().into_bytes());
    assert_eq!(from.len(), to.len());
    let at = envelope
        .windows(from.len())
        .position(|w| w == from.as_slice())
        .expect("the DID is in the signed bytes");
    envelope[at..at + to.len()].copy_from_slice(&to);
    let forged = json!({
        "attestation": URL_SAFE_NO_PAD.encode(&envelope),
        "links": [],
        "reachability": null,
    })
    .to_string();
    let lying_server = serve_resolve(forged).await;

    let bob = Bob::new();
    let only_server = delegation(&[&ns], std::slice::from_ref(&lying_server));
    let err = bob
        .verify(&NameResolver::new(), &only_server, &alice_name())
        .await
        .unwrap_err();
    // Refused for its signature, not for anything about how it was fetched.
    assert!(
        matches!(err, ResolveError::Refused(NamingError::BadSignature(_))),
        "{err:?}"
    );
    assert_eq!(bob.pinned(&alice_name()), None, "nothing pinned");

    let both = delegation(&[&ns], &[lying_server, ns.http_url()]);
    let verified = bob
        .verify(&NameResolver::new(), &both, &alice_name())
        .await
        .unwrap();
    assert_eq!(did_of(&verified), alice.did());
}

/// A host that answers every `/v1/resolve/...` with `body`.
async fn serve_resolve(body: String) -> String {
    let app = axum::Router::new().route(
        "/v1/resolve/{name}",
        axum::routing::get(move || {
            let body = body.clone();
            async move { ([("content-type", "application/json")], body) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    url
}
