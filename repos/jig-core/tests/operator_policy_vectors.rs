//! Conformance vectors for operator policy (JEP-0011 §5.1), in
//! `jig-spec/vectors/operator-policy/vectors.json`.
//!
//! Each policy is given as its deterministic-CBOR payload. A conforming host decodes it, refuses
//! it unless it re-encodes to the same bytes, and then answers each case: does the policy let the
//! server run this program, and every pinned child, each on its own?
//!
//! The cases pin the rule's edges: another server's text-block runs by component; a bot, a
//! renderer that requests a capability, and a renderer that pins a child are not allowed by
//! component alone; `programs` and `authors` admit any world; an author's allowance does not
//! cover children by other authors.
//!
//! `JIG_BLESS_OPERATOR_POLICY_VECTORS=1` rewrites the file from the cases below.

use std::path::PathBuf;

use cid::Cid;
use jig_core::operator_policy::{Allow, ComponentHash, OperatorPolicy, ProgramFacts};
use serde_json::{Value, json};

const RENDERER: &str = "jig:block/renderer@0.1.0";
const BOT: &str = "jig:block/bot@0.1.0";
const TEXT_BLOCK: ComponentHash = [0x7b; 32];
const OTHER: ComponentHash = [0x09; 32];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../jig-spec/vectors/operator-policy/vectors.json")
}

fn cid(label: &str) -> Cid {
    jig_core::canonical_cid::of(label.as_bytes())
}

struct Program {
    cid: Cid,
    author: &'static str,
    world: &'static str,
    component: ComponentHash,
    requests_none: bool,
    children_none: bool,
}

impl Program {
    fn renderer(label: &str, author: &'static str, component: ComponentHash) -> Self {
        Self {
            cid: cid(label),
            author,
            world: RENDERER,
            component,
            requests_none: true,
            children_none: true,
        }
    }

    fn facts(&self) -> ProgramFacts<'_> {
        ProgramFacts {
            program: &self.cid,
            author: self.author,
            world: self.world,
            component: &self.component,
            requests_none: self.requests_none,
            children_none: self.children_none,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "program": self.cid.to_string(),
            "author": self.author,
            "world": self.world,
            "component": hex::encode(self.component),
            "requests_none": self.requests_none,
            "children_none": self.children_none,
        })
    }
}

fn policies() -> Vec<(&'static str, OperatorPolicy)> {
    let default = OperatorPolicy::default_for("did:jig:zserverY", &[TEXT_BLOCK]);
    let mut by_program = default.clone();
    by_program.seq = 1;
    by_program.allow.programs = vec![cid("an allowed bot")];
    let mut by_author = default.clone();
    by_author.seq = 2;
    by_author.allow = Allow {
        authors: vec!["did:jig:ztrusted".into()],
        ..default.allow.clone()
    };
    vec![
        ("default", default),
        ("by-program", by_program),
        ("by-author", by_author),
    ]
}

/// (name, policy, root, children, allowed)
fn cases() -> Vec<(&'static str, &'static str, Program, Vec<Program>, bool)> {
    vec![
        (
            "another-servers-text-block-runs-by-component",
            "default",
            Program::renderer(
                "server X's text-block program",
                "did:jig:zserverX",
                TEXT_BLOCK,
            ),
            vec![],
            true,
        ),
        (
            "a-bot-is-not-allowed-by-component",
            "default",
            Program {
                world: BOT,
                ..Program::renderer("a bot", "did:jig:zstranger", TEXT_BLOCK)
            },
            vec![],
            false,
        ),
        (
            "a-renderer-requesting-a-capability-is-not-allowed-by-component",
            "default",
            Program {
                requests_none: false,
                ..Program::renderer("a requesting renderer", "did:jig:zstranger", TEXT_BLOCK)
            },
            vec![],
            false,
        ),
        (
            "a-renderer-pinning-a-child-is-not-allowed-by-component",
            "default",
            Program {
                children_none: false,
                ..Program::renderer("a parent renderer", "did:jig:zstranger", TEXT_BLOCK)
            },
            vec![],
            false,
        ),
        (
            "an-unlisted-component-is-refused",
            "default",
            Program::renderer("another renderer", "did:jig:zstranger", OTHER),
            vec![],
            false,
        ),
        (
            "a-listed-program-runs-in-any-world",
            "by-program",
            Program {
                world: BOT,
                requests_none: false,
                children_none: false,
                ..Program::renderer("an allowed bot", "did:jig:zstranger", OTHER)
            },
            vec![],
            true,
        ),
        (
            "an-allowed-author-runs-in-any-world",
            "by-author",
            Program {
                world: BOT,
                ..Program::renderer("a trusted bot", "did:jig:ztrusted", OTHER)
            },
            vec![],
            true,
        ),
        (
            "an-authors-allowance-does-not-cover-a-strangers-child",
            "by-author",
            Program {
                children_none: false,
                ..Program::renderer("a trusted parent", "did:jig:ztrusted", OTHER)
            },
            vec![Program::renderer(
                "a strangers child",
                "did:jig:zstranger",
                OTHER,
            )],
            false,
        ),
        (
            "a-text-block-child-is-allowed-on-its-own",
            "by-author",
            Program {
                children_none: false,
                ..Program::renderer("a trusted parent", "did:jig:ztrusted", OTHER)
            },
            vec![Program::renderer(
                "a text-block child",
                "did:jig:zstranger",
                TEXT_BLOCK,
            )],
            true,
        ),
    ]
}

fn generate() -> Value {
    let policies: Vec<Value> = policies()
        .into_iter()
        .map(|(name, p)| json!({ "name": name, "payload": hex::encode(p.to_payload()) }))
        .collect();
    let cases: Vec<Value> = cases()
        .into_iter()
        .map(|(name, policy, root, children, allowed)| {
            json!({
                "name": name,
                "policy": policy,
                "program": root.to_json(),
                "children": children.iter().map(Program::to_json).collect::<Vec<_>>(),
                "allowed": allowed,
            })
        })
        .collect();
    json!({ "version": 1, "policies": policies, "cases": cases })
}

fn program_from(v: &Value) -> Program {
    let leak =
        |s: &Value| -> &'static str { Box::leak(s.as_str().unwrap().to_string().into_boxed_str()) };
    Program {
        cid: v["program"].as_str().unwrap().parse().unwrap(),
        author: leak(&v["author"]),
        world: leak(&v["world"]),
        component: hex::decode(v["component"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        requests_none: v["requests_none"].as_bool().unwrap(),
        children_none: v["children_none"].as_bool().unwrap(),
    }
}

#[test]
fn operator_policy_vectors() {
    let path = vectors_path();
    if std::env::var_os("JIG_BLESS_OPERATOR_POLICY_VECTORS").is_some() {
        let mut text = serde_json::to_string_pretty(&generate()).unwrap();
        text.push('\n');
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
    }
    let file: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("vectors file")).unwrap();
    assert_eq!(file, generate(), "the vectors file is stale; bless it");

    let policies: Vec<(String, OperatorPolicy)> = file["policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let payload = hex::decode(p["payload"].as_str().unwrap()).unwrap();
            let policy = OperatorPolicy::from_payload(&payload).expect("the payload decodes");
            assert_eq!(
                policy.to_payload(),
                payload,
                "the payload re-encodes to itself"
            );
            (p["name"].as_str().unwrap().to_string(), policy)
        })
        .collect();

    for case in file["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let policy = &policies
            .iter()
            .find(|(n, _)| n == case["policy"].as_str().unwrap())
            .unwrap()
            .1;
        let root = program_from(&case["program"]);
        let children: Vec<Program> = case["children"]
            .as_array()
            .unwrap()
            .iter()
            .map(program_from)
            .collect();
        let child_facts: Vec<ProgramFacts<'_>> = children.iter().map(Program::facts).collect();
        assert_eq!(
            policy.allows_closure(&root.facts(), &child_facts),
            case["allowed"].as_bool().unwrap(),
            "case {name}"
        );
    }
}
