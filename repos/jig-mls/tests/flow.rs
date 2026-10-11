//! The two roles against each other: members build, the delivery service
//! validates, members apply. Each test is one channel's life or one attack on
//! it.

use jig_core::Did;
use jig_mls::delivery::{self, Intent};
use jig_mls::member::{CommitOutcome, Member};
use jig_mls::{MlsError, PAST_EPOCHS};

struct Person {
    seed: [u8; 32],
    did: Did,
    member: Member,
}

impl Person {
    fn new(n: u8) -> Self {
        let seed = [n; 32];
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let did = Did::from_ed25519_pubkey(&key.verifying_key().to_bytes());
        let member = Member::new(&seed, &did).unwrap();
        Self { seed, did, member }
    }
    fn id(&self) -> String {
        self.did.to_did_jig_string()
    }
    fn kp(&self) -> Vec<u8> {
        self.member.key_packages(1, false).unwrap().remove(0)
    }
    /// Snapshot and restore, as a client does between commands.
    fn reload(&mut self) {
        let bytes = self.member.snapshot();
        self.member = Member::restore(&self.seed, &self.did, &bytes).unwrap();
    }
}

/// A channel on the server: its public state.
struct Channel {
    state: Vec<u8>,
    group_id: Vec<u8>,
    info: Vec<u8>,
}

impl Channel {
    fn create(owner: &Person) -> Self {
        let created = owner.member.create_group().unwrap();
        let g = delivery::genesis(&created.group_info, &created.ratchet_tree, &owner.id()).unwrap();
        assert_eq!(g.group_id, created.group_id);
        Self {
            state: g.state,
            group_id: g.group_id,
            info: created.group_info,
        }
    }
    fn epoch(&self) -> u64 {
        delivery::epoch(&self.state, &self.group_id).unwrap()
    }
    fn accept(&mut self, commit: &jig_mls::member::Commit, intent: Intent<'_>) -> Result<(), MlsError> {
        let applied = delivery::apply_commit(&self.state, &self.group_id, &commit.commit, intent)?;
        self.state = applied.state;
        if let Some(info) = &commit.group_info {
            let (gid, epoch) = delivery::group_info_epoch(info).unwrap();
            assert_eq!((gid, epoch), (self.group_id.clone(), applied.epoch));
            self.info = info.clone();
        }
        Ok(())
    }
}

fn add(ch: &mut Channel, owner: &Person, who: &Person) -> jig_mls::member::Commit {
    let commit = owner.member.add(&ch.group_id, &who.kp(), &who.id()).unwrap();
    ch.accept(&commit, Intent::Add { committer: &owner.id(), member: &who.id() })
        .unwrap();
    owner.member.confirm(&ch.group_id).unwrap();
    let joined = who.member.join_welcome(commit.welcome.as_ref().unwrap()).unwrap();
    assert_eq!(joined, ch.group_id);
    commit
}

fn say(ch: &Channel, from: &Person, text: &str) -> Vec<u8> {
    let (msg, epoch) = from.member.encrypt(&ch.group_id, text.as_bytes()).unwrap();
    assert_eq!(delivery::check_application(&ch.state, &ch.group_id, &msg).unwrap(), epoch);
    msg
}

fn hear(ch: &Channel, to: &Person, msg: &[u8]) -> (String, String) {
    let d = to.member.decrypt(&ch.group_id, msg).unwrap();
    (String::from_utf8(d.plaintext).unwrap(), d.sender)
}

#[test]
fn a_channel_lives_its_whole_life() {
    let alice = Person::new(1);
    let mut bob = Person::new(2);
    let carol = Person::new(3);
    let mut ch = Channel::create(&alice);
    assert_eq!(ch.epoch(), 0);

    add(&mut ch, &alice, &bob);
    assert_eq!(ch.epoch(), 1);
    assert_eq!(bob.member.epoch(&ch.group_id).unwrap(), 1);

    let m = say(&ch, &alice, "hello bob");
    bob.reload();
    assert_eq!(hear(&ch, &bob, &m), ("hello bob".to_string(), alice.id()));
    assert!(
        bob.member.decrypt(&ch.group_id, &m).is_err(),
        "a message decrypts once; the client keeps the plaintext"
    );

    // Carol self-joins from the group info the server holds.
    let (gid, join) = carol.member.join_external(&ch.info).unwrap();
    assert_eq!(gid, ch.group_id);
    assert_eq!(join.epoch, 1);
    ch.accept(&join, Intent::Join { joiner: &carol.id() }).unwrap();
    for p in [&alice, &bob] {
        assert_eq!(
            p.member.apply_commit(&ch.group_id, &join.commit).unwrap(),
            CommitOutcome::Applied { epoch: 2 }
        );
    }
    let m = say(&ch, &carol, "hi all");
    assert_eq!(hear(&ch, &alice, &m).1, carol.id());

    // Alice removes Bob.
    let kick = alice.member.remove(&ch.group_id, &bob.id()).unwrap();
    ch.accept(&kick, Intent::Remove { committer: &alice.id(), member: &bob.id() })
        .unwrap();
    alice.member.confirm(&ch.group_id).unwrap();
    assert_eq!(
        carol.member.apply_commit(&ch.group_id, &kick.commit).unwrap(),
        CommitOutcome::Applied { epoch: 3 }
    );
    assert_eq!(
        bob.member.apply_commit(&ch.group_id, &kick.commit).unwrap(),
        CommitOutcome::Removed
    );
    assert!(!bob.member.has_group(&ch.group_id));
    let m = say(&ch, &alice, "bob is gone");
    assert_eq!(hear(&ch, &carol, &m).0, "bob is gone");
    assert_eq!(
        delivery::members(&ch.state, &ch.group_id).unwrap().len(),
        2
    );

    // The committer's own commit, echoed back, is recognised as applied.
    assert_eq!(
        alice.member.apply_commit(&ch.group_id, &kick.commit).unwrap(),
        CommitOutcome::AlreadyApplied
    );
}

#[test]
fn genesis_refuses_a_group_that_is_not_the_creators() {
    let alice = Person::new(1);
    let mallory = Person::new(9);
    let created = alice.member.create_group().unwrap();
    assert!(matches!(
        delivery::genesis(&created.group_info, &created.ratchet_tree, &mallory.id()),
        Err(MlsError::Rejected(_))
    ));
}

#[test]
fn a_stale_commit_is_refused_by_epoch() {
    let alice = Person::new(1);
    let bob = Person::new(2);
    let carol = Person::new(3);
    let mut ch = Channel::create(&alice);
    let first = alice.member.add(&ch.group_id, &bob.kp(), &bob.id()).unwrap();
    ch.accept(&first, Intent::Add { committer: &alice.id(), member: &bob.id() })
        .unwrap();
    // Alice never merged, so her next commit is built on epoch 0 again.
    alice.member.abandon(&ch.group_id).unwrap();
    let second = alice.member.add(&ch.group_id, &carol.kp(), &carol.id()).unwrap();
    assert_eq!(
        ch.accept(&second, Intent::Add { committer: &alice.id(), member: &carol.id() }),
        Err(MlsError::StaleEpoch { current: 1, got: 0 })
    );
    assert_eq!(
        ch.accept(&first, Intent::Add { committer: &alice.id(), member: &bob.id() }),
        Err(MlsError::StaleEpoch { current: 1, got: 0 }),
        "a replayed commit is stale"
    );
}

#[test]
fn a_commit_must_do_what_its_block_says() {
    let alice = Person::new(1);
    let bob = Person::new(2);
    let carol = Person::new(3);
    let mallory = Person::new(9);
    let mut ch = Channel::create(&alice);
    let commit = alice.member.add(&ch.group_id, &bob.kp(), &bob.id()).unwrap();

    let wrong_member = ch.accept(&commit, Intent::Add { committer: &alice.id(), member: &carol.id() });
    assert!(matches!(wrong_member, Err(MlsError::Rejected(_))), "{wrong_member:?}");
    let wrong_signer = ch.accept(&commit, Intent::Add { committer: &mallory.id(), member: &bob.id() });
    assert!(matches!(wrong_signer, Err(MlsError::Rejected(_))), "{wrong_signer:?}");
    let wrong_kind = ch.accept(&commit, Intent::Remove { committer: &alice.id(), member: &bob.id() });
    assert!(matches!(wrong_kind, Err(MlsError::Rejected(_))), "{wrong_kind:?}");
    let as_join = ch.accept(&commit, Intent::Join { joiner: &alice.id() });
    assert!(matches!(as_join, Err(MlsError::Rejected(_))), "{as_join:?}");

    // Refusals leave the state alone; the honest reading still applies.
    ch.accept(&commit, Intent::Add { committer: &alice.id(), member: &bob.id() })
        .unwrap();
}

#[test]
fn an_external_join_must_be_the_block_signer() {
    let alice = Person::new(1);
    let carol = Person::new(3);
    let mallory = Person::new(9);
    let mut ch = Channel::create(&alice);
    let (_, join) = carol.member.join_external(&ch.info).unwrap();
    assert!(matches!(
        ch.accept(&join, Intent::Join { joiner: &mallory.id() }),
        Err(MlsError::Rejected(_))
    ));
}

#[test]
fn garbage_is_refused_without_moving_the_epoch() {
    let alice = Person::new(1);
    let mut ch = Channel::create(&alice);
    for junk in [&b""[..], b"\x00\x01garbage", &ch.info.clone()] {
        let r = delivery::apply_commit(
            &ch.state,
            &ch.group_id,
            junk,
            Intent::Join { joiner: &alice.id() },
        );
        assert!(r.is_err(), "{junk:?}");
    }
    assert_eq!(ch.epoch(), 0);
    let _ = &mut ch;
}

#[test]
fn application_messages_must_be_this_groups_and_recent() {
    let alice = Person::new(1);
    let bob = Person::new(2);
    let mut ch = Channel::create(&alice);
    let old = say(&ch, &alice, "epoch 0");
    add(&mut ch, &alice, &bob);

    let other = Channel::create(&bob);
    let (foreign, _) = bob.member.encrypt(&other.group_id, b"x").unwrap();
    assert!(matches!(
        delivery::check_application(&ch.state, &ch.group_id, &foreign),
        Err(MlsError::Rejected(_))
    ));
    // One epoch back is within the window.
    assert_eq!(delivery::check_application(&ch.state, &ch.group_id, &old).unwrap(), 0);
    // A commit smuggled as content is refused.
    let commit = alice.member.remove(&ch.group_id, &bob.id()).unwrap();
    assert!(delivery::check_application(&ch.state, &ch.group_id, &commit.commit).is_err());
    assert!(PAST_EPOCHS >= 1);
}

#[test]
fn key_packages_are_bound_to_their_publisher() {
    let bob = Person::new(2);
    let info = delivery::validate_key_package(&bob.kp()).unwrap();
    assert_eq!(info.did, bob.id());
    assert!(!info.last_resort);
    let lr = bob.member.key_packages(1, true).unwrap().remove(0);
    assert!(delivery::validate_key_package(&lr).unwrap().last_resort);
    assert!(delivery::validate_key_package(b"not a key package").is_err());
}

#[test]
fn an_owner_refuses_a_key_package_for_the_wrong_did() {
    let alice = Person::new(1);
    let bob = Person::new(2);
    let mallory = Person::new(9);
    let ch = Channel::create(&alice);
    assert!(matches!(
        alice.member.add(&ch.group_id, &mallory.kp(), &bob.id()),
        Err(MlsError::Rejected(_))
    ));
}
