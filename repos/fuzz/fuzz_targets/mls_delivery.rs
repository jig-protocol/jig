//! What jig-server's MLS delivery service decodes from a client before it has
//! any group state: key packages, group infos, a channel's genesis, and the
//! stored state snapshot.
#![no_main]

use jig_mls::{delivery, snapshot};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = delivery::validate_key_package(data);
    let _ = delivery::group_info_epoch(data);
    let _ = delivery::reencode(data);
    let _ = snapshot::decode(data);
    if let Some((&split, rest)) = data.split_first() {
        let (info, tree) = rest.split_at(usize::from(split).min(rest.len()));
        let _ = delivery::genesis(
            info,
            tree,
            "did:jig:zaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
    }
});
