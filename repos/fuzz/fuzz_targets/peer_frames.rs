//! The follower stream's peer frames (`channel-records`, `records-from`,
//! `records-later`), decoded as jig-server decodes them off a peer connection.
//! The first byte picks the kind. jig-server's `fuzzing` feature exposes the
//! decoder and asserts that whatever decodes survives its own encoding.
#![no_main]

use jig_server::v0_0_2_stream::{
    RECORDS_FRAME, RECORDS_FROM_FRAME, RECORDS_LATER_FRAME, fuzz_decode_frame,
};
use libfuzzer_sys::fuzz_target;

const KINDS: [&str; 3] = [RECORDS_FRAME, RECORDS_FROM_FRAME, RECORDS_LATER_FRAME];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, body)) = data.split_first() else {
        return;
    };
    fuzz_decode_frame(KINDS[usize::from(pick) % KINDS.len()], body);
});
