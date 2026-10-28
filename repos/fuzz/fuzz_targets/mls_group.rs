//! MLS messages against a live group: the server's checks of a commit and an
//! application message (`delivery::apply_commit`, `check_application`), and a
//! member's `decrypt`.
//!
//! A fixture builds a real two-member group once. Each input either replaces
//! a valid commit or message outright, or (more often) patches one: the first
//! byte picks the target and the mode, then each 3-byte chunk XORs one byte at
//! a 16-bit offset, so mutations reach past the outer framing.
#![no_main]

use std::sync::LazyLock;

use ed25519_dalek::SigningKey;
use jig_core::did::Did;
use jig_mls::delivery::{self, Intent};
use jig_mls::member::Member;
use libfuzzer_sys::fuzz_target;

struct Fixture {
    owner: String,
    bob: String,
    bob_seed: [u8; 32],
    bob_did: Did,
    group_id: Vec<u8>,
    /// The server's state at genesis, owner alone.
    genesis: Vec<u8>,
    /// The server's state after bob joined.
    joined: Vec<u8>,
    /// The owner's commit adding bob, valid against `genesis`.
    add: Vec<u8>,
    /// An application message from the owner, valid against `joined`.
    message: Vec<u8>,
    /// Bob's member state, able to decrypt `message`.
    bob_snapshot: Vec<u8>,
}

fn member(seed: [u8; 32]) -> (Member, Did) {
    let key = SigningKey::from_bytes(&seed);
    let did = Did::from_ed25519_pubkey(key.verifying_key().as_bytes());
    (Member::new(&seed, &did).expect("member"), did)
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let (owner, _) = member([1; 32]);
    let bob_seed = [2; 32];
    let (bob, bob_did) = member(bob_seed);
    let created = owner.create_group().expect("group");
    let genesis = delivery::genesis(&created.group_info, &created.ratchet_tree, owner.did())
        .expect("genesis");
    let package = bob.key_packages(1, false).expect("key package").remove(0);
    let add = owner
        .add(&genesis.group_id, &package, bob.did())
        .expect("add commit");
    let joined = delivery::apply_commit(
        &genesis.state,
        &genesis.group_id,
        &add.commit,
        Intent::Add {
            committer: owner.did(),
            member: bob.did(),
        },
    )
    .expect("the add applies")
    .state;
    owner.confirm(&genesis.group_id).expect("confirm");
    bob.join_welcome(add.welcome.as_ref().expect("welcome"))
        .expect("bob joins");
    let (message, _) = owner.encrypt(&genesis.group_id, b"fuzz").expect("encrypt");
    delivery::check_application(&joined, &genesis.group_id, &message).expect("the message checks");
    Fixture {
        owner: owner.did().to_string(),
        bob: bob.did().to_string(),
        bob_seed,
        bob_did,
        group_id: genesis.group_id,
        genesis: genesis.state,
        joined,
        add: add.commit,
        message,
        bob_snapshot: bob.snapshot(),
    }
});

/// `valid` with `patches` applied: each 3-byte chunk XORs one byte.
fn patched(valid: &[u8], patches: &[u8]) -> Vec<u8> {
    let mut out = valid.to_vec();
    for [lo, hi, xor] in patches.as_chunks::<3>().0 {
        let at = usize::from(u16::from_le_bytes([*lo, *hi])) % out.len();
        out[at] ^= xor;
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let f = &*FIXTURE;
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let valid = if mode % 3 == 0 { &f.add } else { &f.message };
    let input = if mode & 0x80 == 0 {
        patched(valid, rest)
    } else {
        rest.to_vec()
    };
    match mode % 3 {
        0 => {
            let _ = delivery::apply_commit(
                &f.genesis,
                &f.group_id,
                &input,
                Intent::Add {
                    committer: &f.owner,
                    member: &f.bob,
                },
            );
        }
        1 => {
            let _ = delivery::check_application(&f.joined, &f.group_id, &input);
        }
        _ => {
            let bob = Member::restore(&f.bob_seed, &f.bob_did, &f.bob_snapshot).expect("restore");
            if let Ok(d) = bob.decrypt(&f.group_id, &input) {
                // A patched message that still decrypts must be the original.
                assert_eq!(d.plaintext, b"fuzz");
                assert_eq!(d.sender, f.owner);
            }
        }
    }
});
