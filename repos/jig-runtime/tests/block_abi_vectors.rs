//! The `jig:block` conformance vectors (JEP-0006, first-slice step 8).
//!
//! Each vector in `jig-spec/vectors/block-abi/vectors.json` names a component, an invocation and
//! the expected outcome. This suite runs every vector on both backends, native Cranelift and
//! Pulley, and requires the outcome class, trap code or incomplete reason, and outcome hash to
//! match. CI runs it on x86_64 and aarch64 Linux, so a pass means four engine and architecture
//! pairs agree.
//!
//! An `incomplete` vector asserts only the class and reason. Stack use differs by backend and
//! architecture, so a stack vector may not even exhaust at the same depth.
//!
//! To add a vector, write its class (and trap code or reason) by hand, then run
//!
//! ```text
//! JIG_BLESS_BLOCK_ABI_VECTORS=1 cargo test -p jig-runtime --test block_abi_vectors
//! ```
//!
//! That compiles each guest's `.wat` to its `.wasm`, and fills in `component_hash`,
//! `invocation_hash` and the outcome hash from a native run. It refuses to bless a vector whose
//! run lands in a different class from the one written down.

use std::path::{Path, PathBuf};
use std::time::Duration;

use jig_runtime::component::{
    Backend, ComponentRuntime, ErrorOutcome, Hlc, IncompleteReason, Invocation, Payload,
    RenderLimits, RunOutcome, invocation_hash,
};
use serde::{Deserialize, Serialize};

const BLESS_VAR: &str = "JIG_BLESS_BLOCK_ABI_VECTORS";

#[derive(Debug, Serialize, Deserialize)]
struct VectorFile {
    format: String,
    vectors: Vec<Vector>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Vector {
    name: String,
    /// Relative to the vectors directory.
    component: String,
    #[serde(default)]
    component_hash: String,
    world: String,
    max_memory_pages: u32,
    fuel: u64,
    timeout_ms: u64,
    invocation: VectorInvocation,
    #[serde(default)]
    invocation_hash: String,
    expected: Expected,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct VectorInvocation {
    block_cid: String,
    sender_did: String,
    channel_cid: String,
    ingest_seq: u64,
    ingest_hlc: VectorHlc,
    input: VectorPayload,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct VectorHlc {
    wall_ms: u64,
    logical: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct VectorPayload {
    media_type: String,
    /// Lowercase hex.
    body_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case", deny_unknown_fields)]
enum Expected {
    Ok {
        #[serde(default)]
        hash: String,
    },
    Error {
        /// Present when the guest trapped rather than returned `err`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trap: Option<String>,
        #[serde(default)]
        hash: String,
    },
    Incomplete {
        reason: String,
    },
}

impl Expected {
    /// What `outcome` should read as, from a run.
    fn observed(outcome: &RunOutcome) -> Self {
        let hash = outcome.hash().unwrap_or_default();
        match outcome {
            RunOutcome::Ok(_) => Expected::Ok { hash },
            RunOutcome::Error(ErrorOutcome::Guest(_)) => Expected::Error { trap: None, hash },
            RunOutcome::Error(ErrorOutcome::Trap(code)) => Expected::Error {
                trap: Some(code.as_str().to_string()),
                hash,
            },
            RunOutcome::Incomplete(reason) => Expected::Incomplete {
                reason: match reason {
                    IncompleteReason::FuelExhausted => "fuel-exhausted",
                    IncompleteReason::StackExhausted => "stack-exhausted",
                    IncompleteReason::DeadlineExceeded => "deadline-exceeded",
                    IncompleteReason::HostFault(_) => "host-fault",
                }
                .to_string(),
            },
        }
    }

    /// The same class, trap code and reason, ignoring the hash.
    fn same_class(&self, other: &Expected) -> bool {
        match (self, other) {
            (Expected::Ok { .. }, Expected::Ok { .. }) => true,
            (Expected::Error { trap: a, .. }, Expected::Error { trap: b, .. }) => a == b,
            (Expected::Incomplete { reason: a }, Expected::Incomplete { reason: b }) => a == b,
            _ => false,
        }
    }
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../jig-spec/vectors/block-abi")
}

fn load() -> VectorFile {
    let path = vectors_dir().join("vectors.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn blessing() -> bool {
    std::env::var_os(BLESS_VAR).is_some()
}

fn hex_decode(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd-length hex {hex:?}");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect()
}

impl VectorInvocation {
    fn to_invocation(&self) -> Invocation {
        Invocation {
            block_cid: self.block_cid.clone(),
            sender_did: self.sender_did.clone(),
            channel_cid: self.channel_cid.clone(),
            ingest_seq: self.ingest_seq,
            ingest_hlc: Hlc {
                wall_ms: self.ingest_hlc.wall_ms,
                logical: self.ingest_hlc.logical,
            },
            input: Payload {
                media_type: self.input.media_type.clone(),
                body: hex_decode(&self.input.body_hex),
            },
        }
    }
}

impl Vector {
    fn component_path(&self) -> PathBuf {
        vectors_dir().join(&self.component)
    }

    fn limits(&self) -> RenderLimits {
        RenderLimits {
            fuel: self.fuel,
            timeout: Duration::from_millis(self.timeout_ms),
        }
    }

    fn run(&self, runtime: &ComponentRuntime) -> RunOutcome {
        assert_eq!(
            self.world, "renderer",
            "{}: only the renderer world runs yet",
            self.name
        );
        let bytes = std::fs::read(self.component_path())
            .unwrap_or_else(|e| panic!("{}: {e}", self.component_path().display()));
        let renderer = runtime
            .compile_renderer(&bytes, self.max_memory_pages)
            .unwrap_or_else(|e| panic!("{}: does not compile: {e}", self.name));
        runtime
            .render(&renderer, &self.invocation.to_invocation(), &self.limits())
            .outcome
    }
}

fn component_hash(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

/// The `.wat` a guest's `.wasm` is built from, if it has one. `text-block` does not.
fn wat_source(component: &Path) -> Option<PathBuf> {
    let wat = component.with_extension("wat");
    wat.exists().then_some(wat)
}

fn check(backend: Backend) {
    if blessing() {
        // One writer: the native test blesses, the Pulley test stands aside.
        if backend == Backend::Native {
            bless();
        }
        return;
    }
    let runtime = ComponentRuntime::with_backend(backend).expect("runtime builds");
    let file = load();
    assert!(!file.vectors.is_empty());
    let mut failures = Vec::new();
    for v in &file.vectors {
        if component_hash(&v.component_path()) != v.component_hash {
            failures.push(format!("{}: component bytes changed; re-bless", v.name));
            continue;
        }
        let inv_hash = invocation_hash(&v.invocation.to_invocation());
        if inv_hash != v.invocation_hash {
            failures.push(format!("{}: invocation hash {inv_hash}", v.name));
        }
        let observed = Expected::observed(&v.run(&runtime));
        let matches = match &v.expected {
            Expected::Incomplete { .. } => observed.same_class(&v.expected),
            _ => observed == v.expected,
        };
        if !matches {
            failures.push(format!(
                "{}: expected {:?}, got {observed:?}",
                v.name, v.expected
            ));
        }
    }
    assert!(failures.is_empty(), "{backend:?}:\n{}", failures.join("\n"));
}

fn bless() {
    let runtime = ComponentRuntime::new().expect("runtime builds");
    let mut file = load();
    for v in &mut file.vectors {
        let path = v.component_path();
        if let Some(wat) = wat_source(&path) {
            let bytes = wat::parse_file(&wat).unwrap_or_else(|e| panic!("{}: {e}", wat.display()));
            std::fs::write(&path, bytes).expect("writing the guest's wasm");
        }
        v.component_hash = component_hash(&path);
        v.invocation_hash = invocation_hash(&v.invocation.to_invocation());
        let observed = Expected::observed(&v.run(&runtime));
        assert!(
            observed.same_class(&v.expected),
            "{}: written as {:?}, runs as {observed:?}",
            v.name,
            v.expected
        );
        if !matches!(v.expected, Expected::Incomplete { .. }) {
            v.expected = observed;
        }
    }
    let mut text = serde_json::to_string_pretty(&file).expect("vectors serialize");
    text.push('\n');
    std::fs::write(vectors_dir().join("vectors.json"), text).expect("writing vectors.json");
}

#[test]
fn vectors_pass_on_native() {
    check(Backend::Native);
}

#[test]
fn vectors_pass_on_pulley() {
    check(Backend::Pulley);
}

/// Every guest's committed `.wasm` is what its `.wat` compiles to.
#[test]
fn guests_match_their_sources() {
    if blessing() {
        return;
    }
    for v in load().vectors {
        let path = v.component_path();
        if let Some(wat) = wat_source(&path) {
            let built = wat::parse_file(&wat).unwrap_or_else(|e| panic!("{}: {e}", wat.display()));
            let committed =
                std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert!(built == committed, "{}: stale; re-bless", path.display());
        }
    }
}

/// Every guest under `guests/` has a vector, so none is committed without being run.
#[test]
fn every_guest_has_a_vector() {
    let named: Vec<PathBuf> = load()
        .vectors
        .iter()
        .map(|v| v.component_path().with_extension("wat"))
        .collect();
    for entry in std::fs::read_dir(vectors_dir().join("guests")).expect("guests directory") {
        let path = entry.expect("directory entry").path();
        if path.extension().is_some_and(|e| e == "wat") {
            assert!(
                named.iter().any(|n| n.file_name() == path.file_name()),
                "{}: no vector",
                path.display()
            );
        }
    }
}

/// One expected hash rebuilt from bytes written by hand, so the vectors do not rest only on the
/// encoder that blessed them.
///
/// `ok-empty` returns `ok({media-type: "", body: []})`. Its canonical CBOR is the array
/// `["ok", {"body": h'', "media-type": ""}]`, with the map's keys in encoded-byte order: `"body"`
/// (`64 …`) sorts before `"media-type"` (`6a …`).
#[test]
fn an_expected_hash_matches_hand_written_cbor() {
    let cbor: &[u8] = &[
        0x82, // array(2)
        0x62, b'o', b'k', // "ok"
        0xa2, // map(2)
        0x64, b'b', b'o', b'd', b'y', // "body"
        0x40, // h''
        0x6a, b'm', b'e', b'd', b'i', b'a', b'-', b't', b'y', b'p', b'e', // "media-type"
        0x60, // ""
    ];
    let mut hasher = blake3::Hasher::new_derive_key("jig:block outcome v1");
    hasher.update(cbor);
    let by_hand = format!("blake3:{}", hasher.finalize().to_hex());

    let file = load();
    let vector = file
        .vectors
        .iter()
        .find(|v| v.name == "ok-empty")
        .expect("the ok-empty vector");
    assert_eq!(
        vector.expected,
        Expected::Ok { hash: by_hand },
        "the encoder and the hand-written bytes disagree"
    );
}
