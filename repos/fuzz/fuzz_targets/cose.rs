//! COSE_Sign1 and COSE_Sign (`jig_core::cose`), and the JEP-0005 contract
//! envelopes a peer sends in its `offer`/`answer`/`end` frames.
//!
//! Random bytes rarely get past a signature, so each input is also signed
//! with a fixed key and fed through as a payload: the decoders behind the
//! signature check see the fuzzer's bytes too.
#![no_main]

use std::sync::LazyLock;

use ed25519_dalek::SigningKey;
use jig_core::contract::{ContractAccept, ContractEnd, ContractOffer, ContractRefuse};
use jig_core::cose;
use jig_core::did::Did;
use libfuzzer_sys::fuzz_target;

static KEY: LazyLock<SigningKey> = LazyLock::new(|| SigningKey::from_bytes(&[7; 32]));
static DID: LazyLock<String> =
    LazyLock::new(|| Did::from_ed25519_pubkey(KEY.verifying_key().as_bytes()).to_did_jig_string());

fn contracts(envelope: &[u8]) {
    let _ = ContractOffer::from_envelope(envelope).map(|o| o.verify());
    let _ = ContractAccept::from_envelope(envelope).map(|a| a.verify());
    let _ = ContractRefuse::from_envelope(envelope).map(|r| r.verify());
    let _ = ContractEnd::from_envelope(envelope).map(|e| e.verify());
}

fuzz_target!(|data: &[u8]| {
    if let Ok(sign1) = cose::open_sign1(data) {
        let _ = sign1.verify(&DID);
    }
    if let Ok(sign) = cose::open_sign(data) {
        let _ = sign.verify_all(&[&DID, &DID]);
    }
    contracts(data);

    // Whatever the payload, a fresh signature over it opens and verifies.
    let signed = cose::sign1(&KEY, data);
    let opened = cose::open_sign1(&signed).expect("a Sign1 this key made opens");
    assert_eq!(opened.payload, data);
    opened.verify(&DID).expect("a Sign1 this key made verifies");
    contracts(&signed);
    contracts(&cose::sign_all(&[&KEY, &KEY], data));
});
