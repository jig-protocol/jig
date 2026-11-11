//! Encryption-suite conformance vectors (JEP-0001, "Conformance vectors").
//!
//! Every registered suite ships `jig-spec/vectors/suites/<id>.json`: cases of
//! blocks submitted in order to a server with no state, each with the outcome
//! the server must reach — accept, or refuse with a spec error code — and,
//! where the suite's reading is deterministic, what a member reads. The check
//! drives the same suite gate as ingest (`mls_gate::plan`) and maps refusals
//! through the same codes the server answers with. Signatures and freshness
//! are suite-independent and tested elsewhere, so manifests are unsigned.
//!
//! The files are generated, then checked in:
//!
//! ```text
//! cargo test -p jig-server --test suite_vectors -- --ignored regenerate
//! ```
//!
//! openmls checks leaf lifetimes against the clock, so the `mls` file's
//! leaves are minted to last until `MLS_NOT_AFTER`; past that, regenerate.

use std::collections::BTreeSet;
use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use jig_core::suite::test_aead;
use jig_core::{Author, BlockKind, BlockManifest, Did, EncryptionSuite, Privacy};
use jig_mls::member::Member;
use jig_pipeline::mls_gate::{self, MlsPlan};
use jig_pipeline::persist::{StoredChannel, StoredMlsGroup};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The vector format this check reads.
const FORMAT: u32 = 1;

/// 2126-01-01T00:00:00Z: how long the `mls` vectors' leaves stay valid.
const MLS_NOT_AFTER: u64 = 4_922_289_600;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorFile {
    format: u32,
    suite: String,
    description: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    suite_params: Value,
    cases: Vec<Case>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    steps: Vec<Step>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Step {
    /// Submit a block manifest from `sender` (a canonical `did:jig`).
    Submit {
        sender: String,
        manifest: Value,
        expect: Expect,
    },
    /// Read the content block submitted at step index `step`.
    Read { step: usize, expect: Expect },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Expect {
    Accept,
    /// Refused with this spec error code.
    Refuse(String),
    Plaintext(String),
    /// A member cannot read it.
    Unreadable,
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../jig-spec/vectors/suites")
}

// ---- the check ------------------------------------------------------------

/// A channel's state as ingest would hold it after the steps so far.
#[derive(Default)]
struct Server {
    channel: Option<StoredChannel>,
    group: Option<StoredMlsGroup>,
}

impl Server {
    fn submit(&mut self, sender: &str, manifest: &BlockManifest) -> Expect {
        let Some(kind) = manifest.kind else {
            return Expect::Refuse("KIND_REQUIRED".to_string());
        };
        if let Err(gate) = manifest.check_gates() {
            let e = jig_pipeline::ingest::IngestError::ManifestGate(gate);
            return Expect::Refuse(code(&e));
        }
        let plan = match mls_gate::plan(
            kind,
            sender,
            manifest,
            self.channel.as_ref(),
            self.group.as_ref(),
        ) {
            Ok(plan) => plan,
            Err(refusal) => {
                let slug = self
                    .channel
                    .as_ref()
                    .map(|c| c.slug.clone())
                    .unwrap_or_default();
                let e = jig_pipeline::ingest::suite_refusal(refusal, &slug);
                return Expect::Refuse(code(&e));
            }
        };
        if kind == BlockKind::ChannelCreate {
            let visibility = meta(manifest, "visibility").unwrap_or("open").to_string();
            let suite = mls_gate::requested_suite(manifest)
                .expect("the gate accepted it")
                .as_str()
                .to_string();
            self.channel = Some(StoredChannel {
                id: "vector".to_string(),
                slug: meta(manifest, "slug").unwrap_or_default().to_string(),
                tiering: jig_pipeline::persist::ChannelTiering::current(&visibility, &suite),
                visibility,
                created_at: 0,
                owner_did: sender.to_string(),
                suite,
                sequencer_did: String::new(),
                co_owners: Vec::new(),
            });
        }
        match plan {
            MlsPlan::Genesis(group) => self.group = Some(group),
            MlsPlan::Advance {
                from_epoch,
                state,
                to_epoch,
                group_info,
                ..
            } => {
                let group = self.group.as_mut().expect("a commit needs a group");
                assert_eq!(group.epoch, from_epoch, "the gate validated another epoch");
                group.state = state;
                group.epoch = to_epoch;
                if group_info.is_some() {
                    group.group_info = group_info;
                }
            }
            MlsPlan::Nothing | MlsPlan::Sealed => {}
        }
        Expect::Accept
    }
}

fn code(e: &jig_pipeline::ingest::IngestError) -> String {
    jig_server::v0_0_2_ingest_error::classify_ingest_error(e)
        .1
        .to_string()
}

fn meta<'a>(m: &'a BlockManifest, key: &str) -> Option<&'a str> {
    m.metadata.get(key).and_then(Value::as_str)
}

/// What a member reads from a content block, for suites whose reading the
/// vectors can state.
fn read(sender: &str, manifest: &BlockManifest) -> Expect {
    let suite = manifest.content_suite();
    match suite {
        EncryptionSuite::Unencrypted => match meta(manifest, "body") {
            Some(body) => Expect::Plaintext(body.to_string()),
            None => Expect::Unreadable,
        },
        EncryptionSuite::TestAead => {
            let slug = meta(manifest, "channel").unwrap_or_default();
            meta(manifest, test_aead::PAYLOAD_FIELD)
                .and_then(|p| STANDARD.decode(p).ok())
                .and_then(|p| test_aead::open(slug, sender, &p))
                .map(|pt| Expect::Plaintext(String::from_utf8_lossy(&pt).into_owned()))
                .unwrap_or(Expect::Unreadable)
        }
        EncryptionSuite::Mls => panic!("`mls` vectors carry no read steps"),
    }
}

fn check(file: &VectorFile) -> Vec<String> {
    let mut failures = Vec::new();
    for case in &file.cases {
        let mut server = Server::default();
        for (i, step) in case.steps.iter().enumerate() {
            let (got, want) = match step {
                Step::Submit {
                    sender,
                    manifest,
                    expect,
                } => {
                    let manifest: BlockManifest = match serde_json::from_value(manifest.clone()) {
                        Ok(m) => m,
                        Err(e) => {
                            failures.push(format!("{}: step {i}: manifest: {e}", case.name));
                            break;
                        }
                    };
                    (server.submit(sender, &manifest), expect)
                }
                Step::Read { step, expect } => {
                    let Some(Step::Submit {
                        sender, manifest, ..
                    }) = case.steps.get(*step)
                    else {
                        failures.push(format!("{}: step {i}: reads a non-submit", case.name));
                        break;
                    };
                    let manifest: BlockManifest = serde_json::from_value(manifest.clone())
                        .expect("parsed when it was submitted");
                    (read(sender, &manifest), expect)
                }
            };
            if &got != want {
                failures.push(format!(
                    "{} / {}: step {i}: expected {want:?}, got {got:?}",
                    file.suite, case.name
                ));
            }
        }
    }
    failures
}

fn load_all() -> Vec<(PathBuf, VectorFile)> {
    let mut files: Vec<_> = std::fs::read_dir(vectors_dir())
        .expect("jig-spec/vectors/suites exists")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let text = std::fs::read_to_string(&p).unwrap();
            let file: VectorFile =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            (p, file)
        })
        .collect()
}

#[test]
fn every_registered_suite_has_vectors_and_every_file_a_suite() {
    let files = load_all();
    let mut covered = BTreeSet::new();
    for (path, file) in &files {
        assert_eq!(file.format, FORMAT, "{}", path.display());
        let suite: EncryptionSuite = file
            .suite
            .parse()
            .unwrap_or_else(|_| panic!("{}: `{}` is not registered", path.display(), file.suite));
        assert_eq!(
            path.file_stem().unwrap().to_str().unwrap(),
            suite.as_str(),
            "a vector file is named after its suite"
        );
        assert!(!file.cases.is_empty(), "{}: no cases", path.display());
        covered.insert(suite.as_str());
    }
    for suite in EncryptionSuite::REGISTERED {
        assert!(
            covered.contains(suite.as_str()),
            "registered suite `{suite}` ships no conformance vectors"
        );
    }
}

#[test]
fn every_suite_meets_its_vectors() {
    let failures: Vec<String> = load_all().iter().flat_map(|(_, f)| check(f)).collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

// ---- the generator --------------------------------------------------------

struct Who {
    did: String,
    key: Did,
    seed: [u8; 32],
}

fn who(n: u8) -> Who {
    let seed = [n; 32];
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let key = Did::from_ed25519_pubkey(&key.verifying_key().to_bytes());
    Who {
        did: key.to_did_jig_string(),
        key,
        seed,
    }
}

fn member(w: &Who) -> Member {
    Member::new(&w.seed, &w.key)
        .unwrap()
        .with_lifetime_until(MLS_NOT_AFTER)
}

fn manifest(kind: BlockKind, sender: &str, suite: EncryptionSuite, meta: Value) -> Value {
    let mut b = BlockManifest::builder()
        .version(semver::Version::new(0, 1, 0))
        .author(Author {
            did: sender.into(),
            public_key: None,
            roles: vec![],
        });
    if suite != EncryptionSuite::Unencrypted {
        b = b.privacy(Privacy {
            encryption: suite,
            recipients: vec![],
            metadata_visibility: Default::default(),
        });
    }
    if let Value::Object(map) = meta {
        for (k, v) in map {
            b = b.metadata_entry(&k, v);
        }
    }
    serde_json::to_value(b.build().unwrap().with_kind(kind)).unwrap()
}

fn submit(
    sender: &Who,
    kind: BlockKind,
    suite: EncryptionSuite,
    meta: Value,
    expect: Expect,
) -> Step {
    Step::Submit {
        sender: sender.did.clone(),
        manifest: manifest(kind, &sender.did, suite, meta),
        expect,
    }
}

fn accept() -> Expect {
    Expect::Accept
}

fn refuse(code: &str) -> Expect {
    Expect::Refuse(code.to_string())
}

fn case(name: &str, steps: Vec<Step>) -> Case {
    Case {
        name: name.to_string(),
        steps,
    }
}

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

use BlockKind::{ChannelCreate, MemberAdd, MemberRemove, TextRender};
use EncryptionSuite::{Mls, TestAead, Unencrypted};

/// Every suite: a control block is read by the server to apply it, so it
/// declaring an encrypted suite is refused.
fn control_blocks_are_plaintext(a: &Who, create: Value, declared: EncryptionSuite) -> Case {
    case(
        "control blocks are never encrypted",
        vec![
            submit(a, ChannelCreate, Unencrypted, create, accept()),
            submit(
                a,
                MemberAdd,
                declared,
                json!({"channel": "#v", "member_did": who(2).did}),
                refuse("SUITE_MISMATCH"),
            ),
        ],
    )
}

fn none_vectors() -> VectorFile {
    let a = who(1);
    VectorFile {
        format: FORMAT,
        suite: "none".to_string(),
        description: "No encryption: open channels only, plaintext `body`.".to_string(),
        suite_params: Value::Null,
        cases: vec![
            case(
                "an open channel takes plaintext",
                vec![
                    submit(
                        &a,
                        ChannelCreate,
                        Unencrypted,
                        json!({"slug": "#v"}),
                        accept(),
                    ),
                    submit(
                        &a,
                        TextRender,
                        Unencrypted,
                        json!({"channel": "#v", "body": "hello"}),
                        accept(),
                    ),
                    Step::Read {
                        step: 1,
                        expect: Expect::Plaintext("hello".to_string()),
                    },
                ],
            ),
            case(
                "a restricted channel is never plaintext",
                vec![
                    submit(
                        &a,
                        ChannelCreate,
                        Unencrypted,
                        json!({"slug": "#v", "visibility": "restricted"}),
                        refuse("RESTRICTED_REQUIRES_MLS"),
                    ),
                    submit(
                        &a,
                        ChannelCreate,
                        Unencrypted,
                        json!({"slug": "#v", "visibility": "restricted", "suite": "none"}),
                        refuse("RESTRICTED_REQUIRES_MLS"),
                    ),
                ],
            ),
            case(
                "an unregistered suite is refused at creation",
                vec![submit(
                    &a,
                    ChannelCreate,
                    Unencrypted,
                    json!({"slug": "#v", "suite": "test-unregistered"}),
                    refuse("UNSUPPORTED_SUITE"),
                )],
            ),
            case(
                "content under another suite is refused",
                vec![
                    submit(
                        &a,
                        ChannelCreate,
                        Unencrypted,
                        json!({"slug": "#v"}),
                        accept(),
                    ),
                    submit(
                        &a,
                        TextRender,
                        Mls,
                        json!({"channel": "#v", "mls_message": "AAAA"}),
                        refuse("SUITE_MISMATCH"),
                    ),
                ],
            ),
            control_blocks_are_plaintext(&a, json!({"slug": "#v"}), Mls),
        ],
    }
}

fn test_aead_vectors() -> VectorFile {
    let a = who(1);
    let b = who(2);
    let sealed = |slug: &str, from: &Who, nonce: u8, text: &str| {
        b64(&test_aead::seal(
            slug,
            &from.did,
            &[nonce; test_aead::NONCE_LEN],
            text.as_bytes(),
        ))
    };
    let create = json!({"slug": "#v", "suite": "test-aead"});
    let post = |from: &Who, payload: String, expect: Expect| {
        submit(
            from,
            TextRender,
            TestAead,
            json!({"channel": "#v", "test_ciphertext": payload}),
            expect,
        )
    };
    VectorFile {
        format: FORMAT,
        suite: "test-aead".to_string(),
        description: "Reserved for conformance testing: ChaCha20-Poly1305 under the published \
                      key. The payload `test_ciphertext` is base64 of nonce (12 bytes) followed \
                      by the AEAD output; the AAD is `jig-test-aead-v1|<slug>|<sender DID>`."
            .to_string(),
        suite_params: json!({ "key": hex::encode(test_aead::KEY) }),
        cases: vec![
            case(
                "an open channel takes sealed content, readable with the published key",
                vec![
                    submit(&a, ChannelCreate, Unencrypted, create.clone(), accept()),
                    post(&a, sealed("#v", &a, 1, "hello, test-aead"), accept()),
                    Step::Read {
                        step: 1,
                        expect: Expect::Plaintext("hello, test-aead".to_string()),
                    },
                    post(&b, sealed("#v", &b, 2, "and back"), accept()),
                    Step::Read {
                        step: 3,
                        expect: Expect::Plaintext("and back".to_string()),
                    },
                ],
            ),
            case(
                "ciphertext bound to another channel or author does not read",
                vec![
                    submit(&a, ChannelCreate, Unencrypted, create.clone(), accept()),
                    post(&a, sealed("#elsewhere", &a, 3, "moved"), accept()),
                    Step::Read {
                        step: 1,
                        expect: Expect::Unreadable,
                    },
                    post(&b, sealed("#v", &a, 4, "forged"), accept()),
                    Step::Read {
                        step: 3,
                        expect: Expect::Unreadable,
                    },
                ],
            ),
            case(
                "a restricted channel cannot use the test suite",
                vec![submit(
                    &a,
                    ChannelCreate,
                    Unencrypted,
                    json!({"slug": "#v", "suite": "test-aead", "visibility": "restricted"}),
                    refuse("RESTRICTED_REQUIRES_MLS"),
                )],
            ),
            case(
                "a direct message cannot use the test suite",
                vec![submit(
                    &a,
                    ChannelCreate,
                    Unencrypted,
                    json!({"slug": jig_core::dm::dm_slug(&a.did, &b.did), "suite": "test-aead",
                           "visibility": "restricted", "dm_peer": b.did, "locked": true}),
                    refuse("MLS_REJECTED"),
                )],
            ),
            case(
                "content needs the payload, and no plaintext beside it",
                vec![
                    submit(&a, ChannelCreate, Unencrypted, create.clone(), accept()),
                    submit(
                        &a,
                        TextRender,
                        TestAead,
                        json!({"channel": "#v"}),
                        refuse("MISSING_METADATA"),
                    ),
                    submit(
                        &a,
                        TextRender,
                        TestAead,
                        json!({"channel": "#v", "test_ciphertext": "not base64!"}),
                        refuse("MISSING_METADATA"),
                    ),
                    submit(
                        &a,
                        TextRender,
                        TestAead,
                        json!({"channel": "#v", "test_ciphertext": sealed("#v", &a, 5, "hi"),
                               "body": "hi"}),
                        refuse("SUITE_MISMATCH"),
                    ),
                ],
            ),
            case(
                "content under another suite is refused",
                vec![
                    submit(&a, ChannelCreate, Unencrypted, create.clone(), accept()),
                    submit(
                        &a,
                        TextRender,
                        Unencrypted,
                        json!({"channel": "#v", "body": "hi"}),
                        refuse("SUITE_MISMATCH"),
                    ),
                    submit(
                        &a,
                        TextRender,
                        Mls,
                        json!({"channel": "#v", "mls_message": "AAAA"}),
                        refuse("SUITE_MISMATCH"),
                    ),
                ],
            ),
            case(
                "membership on a test-aead channel is a plain control block",
                vec![
                    submit(&a, ChannelCreate, Unencrypted, create.clone(), accept()),
                    submit(
                        &a,
                        MemberAdd,
                        Unencrypted,
                        json!({"channel": "#v", "member_did": b.did}),
                        accept(),
                    ),
                    submit(
                        &a,
                        MemberRemove,
                        Unencrypted,
                        json!({"channel": "#v", "member_did": b.did}),
                        accept(),
                    ),
                ],
            ),
            control_blocks_are_plaintext(&a, create, TestAead),
        ],
    }
}

fn mls_vectors() -> VectorFile {
    let (a, b, c) = (who(1), who(2), who(3));

    // An encrypted channel `#v` created by `a`, as a case's first step.
    let genesis = |owner: &Member, visibility: &str| {
        let created = owner.create_group().unwrap();
        let step = submit(
            &a,
            ChannelCreate,
            Unencrypted,
            json!({"slug": "#v", "visibility": visibility, "suite": "mls",
                   "mls_group_info": b64(&created.group_info),
                   "mls_ratchet_tree": b64(&created.ratchet_tree)}),
            accept(),
        );
        (created, step)
    };
    let commit_meta = |commit: &jig_mls::member::Commit, member: &str| {
        let mut m = json!({"channel": "#v", "member_did": member,
                           "mls_commit": b64(&commit.commit), "mls_epoch": commit.epoch});
        if let Some(w) = &commit.welcome {
            m["mls_welcome"] = json!(b64(w));
        }
        if let Some(i) = &commit.group_info {
            m["mls_group_info"] = json!(b64(i));
        }
        m
    };
    let message = |msg: &[u8], epoch: u64| json!({"channel": "#v", "mls_message": b64(msg), "mls_epoch": epoch});

    let mut cases = Vec::new();

    // A restricted channel's life: create, add, talk, remove.
    {
        let (ma, mb) = (member(&a), member(&b));
        let (created, create) = genesis(&ma, "restricted");
        let gid = created.group_id;
        let kp = mb.key_packages(1, false).unwrap().remove(0);
        let add = ma.add(&gid, &kp, &b.did).unwrap();
        ma.confirm(&gid).unwrap();
        let bgid = mb.join_welcome(add.welcome.as_ref().unwrap()).unwrap();
        let (from_a, ea) = ma.encrypt(&gid, b"hello").unwrap();
        let (from_b, eb) = mb.encrypt(&bgid, b"hi").unwrap();
        let remove = ma.remove(&gid, &b.did).unwrap();
        ma.confirm(&gid).unwrap();
        cases.push(case(
            "a restricted channel: create, add with a welcome, talk, remove",
            vec![
                create,
                submit(
                    &a,
                    MemberAdd,
                    Unencrypted,
                    commit_meta(&add, &b.did),
                    accept(),
                ),
                submit(&a, TextRender, Mls, message(&from_a, ea), accept()),
                submit(&b, TextRender, Mls, message(&from_b, eb), accept()),
                submit(
                    &a,
                    MemberRemove,
                    Unencrypted,
                    commit_meta(&remove, &b.did),
                    accept(),
                ),
            ],
        ));
    }

    // An open channel: anyone joins by external commit; a commit built on a
    // passed epoch is stale.
    {
        let (ma, mb, mc) = (member(&a), member(&b), member(&c));
        let (created, create) = genesis(&ma, "open");
        let (_, join_b) = mb.join_external(&created.group_info).unwrap();
        let (_, join_c) = mc.join_external(&created.group_info).unwrap();
        cases.push(case(
            "an open channel: external join, then a commit on a passed epoch is stale",
            vec![
                create,
                submit(
                    &b,
                    MemberAdd,
                    Unencrypted,
                    commit_meta(&join_b, &b.did),
                    accept(),
                ),
                submit(
                    &c,
                    MemberAdd,
                    Unencrypted,
                    commit_meta(&join_c, &c.did),
                    refuse("STALE_EPOCH"),
                ),
            ],
        ));
    }

    // A commit must do exactly what its block says.
    {
        let (ma, mb) = (member(&a), member(&b));
        let (created, create) = genesis(&ma, "restricted");
        let kp = mb.key_packages(1, false).unwrap().remove(0);
        let add = ma.add(&created.group_id, &kp, &b.did).unwrap();
        let mut no_welcome = commit_meta(&add, &b.did);
        no_welcome.as_object_mut().unwrap().remove("mls_welcome");
        cases.push(case(
            "a commit does exactly what its block says, and an add carries its welcome",
            vec![
                create,
                submit(
                    &a,
                    MemberAdd,
                    Unencrypted,
                    commit_meta(&add, &c.did),
                    refuse("MLS_REJECTED"),
                ),
                submit(
                    &a,
                    MemberAdd,
                    Unencrypted,
                    no_welcome,
                    refuse("MISSING_METADATA"),
                ),
                submit(
                    &a,
                    MemberRemove,
                    Unencrypted,
                    commit_meta(&add, &b.did),
                    refuse("MLS_REJECTED"),
                ),
            ],
        ));
    }

    // A member leaves without a commit; it cannot commit its own removal.
    {
        let (ma, mb) = (member(&a), member(&b));
        let (created, create) = genesis(&ma, "open");
        let (_, join_b) = mb.join_external(&created.group_info).unwrap();
        cases.push(case(
            "a member leaves without a commit",
            vec![
                create,
                submit(
                    &b,
                    MemberAdd,
                    Unencrypted,
                    commit_meta(&join_b, &b.did),
                    accept(),
                ),
                submit(
                    &b,
                    MemberRemove,
                    Unencrypted,
                    json!({"channel": "#v", "member_did": b.did, "mls_commit": "AAAA"}),
                    refuse("MLS_REJECTED"),
                ),
                submit(
                    &b,
                    MemberRemove,
                    Unencrypted,
                    json!({"channel": "#v", "member_did": b.did}),
                    accept(),
                ),
            ],
        ));
    }

    // Content: ciphertext for this group only, and nothing in the clear.
    {
        let ma = member(&a);
        let (created, create) = genesis(&ma, "restricted");
        let (ok, e) = ma.encrypt(&created.group_id, b"hello").unwrap();
        let other = ma.create_group().unwrap();
        let (foreign, fe) = ma.encrypt(&other.group_id, b"elsewhere").unwrap();
        let mut leaky = message(&ok, e);
        leaky["body"] = json!("hello");
        cases.push(case(
            "content is an application message for this group, with no plaintext",
            vec![
                create,
                submit(
                    &a,
                    TextRender,
                    Mls,
                    message(&foreign, fe),
                    refuse("MLS_REJECTED"),
                ),
                submit(&a, TextRender, Mls, leaky, refuse("SUITE_MISMATCH")),
                submit(
                    &a,
                    TextRender,
                    Mls,
                    json!({"channel": "#v"}),
                    refuse("MISSING_METADATA"),
                ),
                submit(
                    &a,
                    TextRender,
                    Unencrypted,
                    json!({"channel": "#v", "body": "hello"}),
                    refuse("SUITE_MISMATCH"),
                ),
                submit(&a, TextRender, Mls, message(&ok, e), accept()),
            ],
        ));
    }

    // A direct message is restricted, locked and `mls`, under its pair's slug.
    {
        let ma = member(&a);
        let created = ma.create_group().unwrap();
        let dm = jig_core::dm::dm_slug(&a.did, &b.did);
        let meta = |slug: &str, peer: &str| {
            json!({"slug": slug, "visibility": "restricted", "suite": "mls", "locked": true,
                   "dm_peer": peer,
                   "mls_group_info": b64(&created.group_info),
                   "mls_ratchet_tree": b64(&created.ratchet_tree)})
        };
        cases.push(case(
            "a direct message is created only under its pair's slug",
            vec![
                submit(
                    &a,
                    ChannelCreate,
                    Unencrypted,
                    meta(&dm, &c.did),
                    refuse("MLS_REJECTED"),
                ),
                submit(&a, ChannelCreate, Unencrypted, meta(&dm, &b.did), accept()),
            ],
        ));
    }

    {
        let ma = member(&a);
        let created = ma.create_group().unwrap();
        cases.push(control_blocks_are_plaintext(
            &a,
            json!({"slug": "#v", "suite": "mls",
                   "mls_group_info": b64(&created.group_info),
                   "mls_ratchet_tree": b64(&created.ratchet_tree)}),
            Mls,
        ));
    }

    VectorFile {
        format: FORMAT,
        suite: "mls".to_string(),
        description: format!(
            "MLS (RFC 9420), {:?}. Gate cases only: MLS reading depends on member secrets, \
             covered by RFC 9420's own vectors. Leaves expire at {MLS_NOT_AFTER} \
             (Unix seconds); regenerate before then.",
            jig_mls::CIPHERSUITE
        ),
        suite_params: Value::Null,
        cases,
    }
}

#[test]
#[ignore = "writes jig-spec/vectors/suites; run by hand, then commit the files"]
fn regenerate() {
    let dir = vectors_dir();
    std::fs::create_dir_all(&dir).unwrap();
    for file in [none_vectors(), mls_vectors(), test_aead_vectors()] {
        let failures = check(&file);
        assert!(failures.is_empty(), "\n{}", failures.join("\n"));
        let mut text = serde_json::to_string_pretty(&file).unwrap();
        text.push('\n');
        std::fs::write(dir.join(format!("{}.json", file.suite)), text).unwrap();
    }
}
