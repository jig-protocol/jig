//! jig speaks one ciphersuite, and refuses MLS in any other before running its
//! crypto. That is what makes the P-256 code openmls_rust_crypto links in
//! (and RUSTSEC-2026-0387 in crypto-bigint 0.5 under it) unreachable: no
//! P-256 key, secret or public, is generated, derived or verified for anything
//! jig is handed. `deny.toml` relies on these tests.

use jig_core::Did;
use jig_mls::delivery;
use jig_mls::member::Member;
use jig_mls::{CIPHERSUITE, MlsError};
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, KeyPackage, MlsGroup, MlsGroupCreateConfig,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider as _;

const P256: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

/// Someone speaking P-256 MLS, built straight on openmls.
struct Stranger {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl Stranger {
    fn new(name: &str) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(P256.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Self {
            provider,
            signer,
            credential,
        }
    }
    fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .build(P256, &self.provider, &self.signer, self.credential.clone())
            .unwrap()
            .key_package()
            .clone()
    }
    fn group(&self) -> MlsGroup {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(P256)
            .use_ratchet_tree_extension(true)
            .build();
        MlsGroup::new(
            &self.provider,
            &self.signer,
            &config,
            self.credential.clone(),
        )
        .unwrap()
    }
    fn group_info(&self, group: &MlsGroup) -> Vec<u8> {
        group
            .export_group_info(self.provider.crypto(), &self.signer, true)
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    }
}

fn jig_member() -> (Member, String) {
    let seed = [7; 32];
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let did = Did::from_ed25519_pubkey(&key.verifying_key().to_bytes());
    (Member::new(&seed, &did).unwrap(), did.to_did_jig_string())
}

fn assert_refused_for_ciphersuite<T: std::fmt::Debug>(result: Result<T, MlsError>) {
    match result {
        Err(MlsError::Rejected(why)) => {
            assert!(
                why.contains("ciphersuite"),
                "refused, but not for its ciphersuite: {why}"
            )
        }
        other => panic!("expected a ciphersuite refusal, got {other:?}"),
    }
}

#[test]
fn the_server_refuses_another_ciphersuites_group() {
    assert_ne!(P256, CIPHERSUITE);
    let mallory = Stranger::new("mallory");
    let group = mallory.group();
    let info = mallory.group_info(&group);
    let tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .unwrap();

    assert_refused_for_ciphersuite(delivery::genesis(&info, &tree, "did:jig:mallory"));
    assert_refused_for_ciphersuite(delivery::group_info_epoch(&info));
}

#[test]
fn the_server_refuses_another_ciphersuites_key_package() {
    let kp = Stranger::new("mallory")
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    assert_refused_for_ciphersuite(delivery::validate_key_package(&kp));
}

#[test]
fn a_member_will_not_join_another_ciphersuites_group() {
    let (member, _) = jig_member();
    let mallory = Stranger::new("mallory");

    // An external join would mean a P-256 leaf secret and a P-256 HPKE
    // encapsulation to the group's external key.
    let group = mallory.group();
    assert_refused_for_ciphersuite(member.join_external(&mallory.group_info(&group)));

    // A welcome in another ciphersuite cannot be for one of this member's
    // key packages; it is refused before any of it is decrypted.
    let mut group = mallory.group();
    let (_, welcome, _) = group
        .add_members(
            &mallory.provider,
            &mallory.signer,
            &[Stranger::new("trent").key_package()],
        )
        .unwrap();
    assert_refused_for_ciphersuite(member.join_welcome(&welcome.tls_serialize_detached().unwrap()));
}

#[test]
fn an_owner_will_not_add_another_ciphersuites_key_package() {
    let (owner, _) = jig_member();
    let created = owner.create_group().unwrap();
    let kp = Stranger::new("mallory")
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    assert_refused_for_ciphersuite(owner.add(&created.group_id, &kp, "did:jig:mallory"));
}
