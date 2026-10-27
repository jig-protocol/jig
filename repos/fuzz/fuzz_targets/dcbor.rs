//! Deterministic CBOR (`jig_core::dcbor`): what every signed jig structure is
//! encoded in. Only deterministic encodings decode, so whatever decodes must
//! encode back to exactly the bytes it came from.
#![no_main]

use jig_core::dcbor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = dcbor::decode(data) {
        let again = dcbor::encode(&value).expect("a decoded value encodes");
        assert_eq!(
            again, data,
            "decoded bytes that are not the value's one encoding"
        );
    }
});
