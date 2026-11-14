//! The WebSocket envelope (`jig_pipeline::Envelope`) every client and peer
//! frame arrives in, and the handshake's reading of a server's welcome.
#![no_main]

use jig_pipeline::Envelope;
use jig_pipeline::handshake;
use libfuzzer_sys::fuzz_target;

const SERVER_DID: &str = "did:jig:zaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(envelope) = Envelope::parse(text) {
        let again = serde_json::to_string(&envelope).expect("a parsed envelope serializes");
        assert_eq!(
            Envelope::parse(&again).expect("a serialized envelope parses"),
            envelope
        );
    }
    let _ = handshake::verify_offline(text, SERVER_DID);
});
