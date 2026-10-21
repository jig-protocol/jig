//! `jig block run` and `jig block test` for `jig:block` components.
//!
//! Both execute through jig-runtime's [`ComponentRuntime`], the one component path the server and
//! the client use (JEP-0006 decision A4), under the same engine profile. Sharing code is not what
//! makes the results identical, though: the conformance vectors are. A local run synthesizes its
//! `invocation`, so it says nothing about any real message.
//!
//! Hashes come from jig-runtime ([`invocation_hash`], [`RunOutcome::hash`]), the one
//! implementation of JEP-0006's canonical encoding that the server and client also use.

#![cfg(feature = "local-runtime")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use jig_core::grant::Grant;
use jig_runtime::component::{
    BlockError, ComponentRuntime, ErrorOutcome, Hlc, IncompleteReason, Invocation, Payload,
    RenderLimits, RunOutcome, invocation_hash,
};
use serde::{Deserialize, Serialize};

use crate::cmd::block_project::{DEFAULT_MEMORY_PAGES, Project};

/// Fuel for a local run unless `--fuel` says otherwise.
pub const DEFAULT_FUEL: u64 = 50_000_000;
/// Wall-clock limit for a local run unless `--timeout` says otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// The invocation a local run passes in. Every field has a fixed default, so the same command
/// always gives the same run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct InvocationSpec {
    pub block_cid: String,
    pub sender: String,
    pub channel: String,
    pub seq: u64,
    pub wall_ms: u64,
    pub logical: u32,
    pub media_type: String,
    /// The input body as text. Ignored when `input_hex` is set.
    pub input: String,
    /// The input body as hex, for binary input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_hex: Option<String>,
}

impl Default for InvocationSpec {
    fn default() -> Self {
        Self {
            block_cid: "local".into(),
            sender: "did:jig:local".into(),
            channel: "local".into(),
            seq: 0,
            wall_ms: 0,
            logical: 0,
            media_type: "text/plain".into(),
            input: String::new(),
            input_hex: None,
        }
    }
}

impl InvocationSpec {
    pub fn to_invocation(&self) -> Result<Invocation> {
        let body = match &self.input_hex {
            Some(h) => decode_hex(h).context("input_hex is not hex")?,
            None => self.input.clone().into_bytes(),
        };
        Ok(Invocation {
            block_cid: self.block_cid.clone(),
            sender_did: self.sender.clone(),
            channel_cid: self.channel.clone(),
            ingest_seq: self.seq,
            ingest_hlc: Hlc {
                wall_ms: self.wall_ms,
                logical: self.logical,
            },
            input: Payload {
                media_type: self.media_type.clone(),
                body,
            },
        })
    }
}

/// The comparable part of an outcome, as a vector records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    /// `ok` or `error`.
    pub outcome: String,
    /// `blake3:<hex>` outcome hash. Every comparable outcome has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// The JEP-0006 trap code, for an `error` that is a trap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap: Option<String>,
}

/// One run, ready to print.
#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub component: String,
    pub invocation_hash: String,
    /// `ok`, `error` or `incomplete`.
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trap: Option<String>,
    /// For `incomplete`: why the run asserts nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<OutputView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub fuel_used: u64,
    pub wasmtime: String,
    pub config_fingerprint: String,
}

/// The returned payload, shown as text when it is text.
#[derive(Debug, Clone, Serialize)]
pub struct OutputView {
    pub media_type: String,
    pub len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
}

impl RunReport {
    /// The part two executors compare, or `None` for `incomplete`.
    pub fn expected(&self) -> Option<Expected> {
        (self.outcome != "incomplete").then(|| Expected {
            outcome: self.outcome.clone(),
            hash: self.hash.clone(),
            trap: self.trap.clone(),
        })
    }

    pub fn render(&self) -> String {
        let mut out = format!("outcome    {}\n", self.outcome);
        if let Some(h) = &self.hash {
            out.push_str(&format!("hash       {h}\n"));
        }
        if let Some(t) = &self.trap {
            out.push_str(&format!("trap       {t}\n"));
        }
        if let Some(r) = &self.reason {
            out.push_str(&format!(
                "reason     {r} (an incomplete run asserts nothing and is never compared)\n"
            ));
        }
        if let Some(e) = &self.error {
            out.push_str(&format!("error      {e}\n"));
        }
        if let Some(o) = &self.output {
            out.push_str(&format!("media-type {} ({} bytes)\n", o.media_type, o.len));
            match (&o.text, &o.hex) {
                (Some(t), _) => out.push_str(&format!("output     {t}\n")),
                (None, Some(h)) => out.push_str(&format!("output     0x{h}\n")),
                _ => {}
            }
        }
        out.push_str(&format!(
            "invocation {}\ncomponent  {}\nfuel       {} (local telemetry, never compared)\n\
             engine     wasmtime {} {}\n",
            self.invocation_hash,
            self.component,
            self.fuel_used,
            self.wasmtime,
            self.config_fingerprint
        ));
        out
    }
}

/// A component and the memory limit it runs under.
pub struct Target {
    pub bytes: Vec<u8>,
    pub max_memory_pages: u32,
    /// The project it came from, if any (for its vectors).
    pub project_dir: Option<PathBuf>,
}

/// Resolve `path`: a project directory (its built component) or a component file.
pub fn load_target(path: &Path) -> Result<Target> {
    if path.is_dir() {
        let project = Project::load(path)?;
        let file = project.component_path();
        let bytes = std::fs::read(&file).with_context(|| {
            format!(
                "{} has not been built; run `jig block build` first",
                path.display()
            )
        })?;
        return Ok(Target {
            bytes,
            max_memory_pages: project.file.limits.memory_max_pages,
            project_dir: Some(project.dir),
        });
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(Target {
        bytes,
        max_memory_pages: DEFAULT_MEMORY_PAGES,
        project_dir: None,
    })
}

/// Whether `bytes` are a component rather than a core module.
pub fn is_component(bytes: &[u8]) -> bool {
    wasmparser::Parser::is_component(bytes)
}

/// Compiles once and runs many invocations.
pub struct Executor {
    runtime: ComponentRuntime,
    renderer: jig_runtime::component::CompiledRenderer,
    limits: RenderLimits,
}

impl Executor {
    pub fn new(target: &Target, limits: RenderLimits) -> Result<Self> {
        let runtime = ComponentRuntime::new().context("starting the component runtime")?;
        // A renderer is granted nothing beyond jig:block/types.
        let renderer = runtime
            .compile_renderer(&target.bytes, &Grant::empty(), target.max_memory_pages)
            .context("the component was refused; `jig block lint` explains why")?;
        Ok(Self {
            runtime,
            renderer,
            limits,
        })
    }

    pub fn run(&self, spec: &InvocationSpec) -> Result<RunReport> {
        let invocation = spec.to_invocation()?;
        let invocation_hash = invocation_hash(&invocation);
        let run = self
            .runtime
            .render(&self.renderer, &invocation, &self.limits);
        let identity = self.runtime.engine_identity();
        let mut report = RunReport {
            component: self.renderer.component_hash().to_string(),
            invocation_hash,
            outcome: String::new(),
            trap: None,
            reason: None,
            output: None,
            error: None,
            hash: run.outcome.hash(),
            fuel_used: run.fuel_used,
            wasmtime: identity.wasmtime,
            config_fingerprint: identity.config_fingerprint,
        };
        match &run.outcome {
            RunOutcome::Ok(payload) => {
                report.outcome = "ok".into();
                report.output = Some(view(payload));
            }
            RunOutcome::Error(ErrorOutcome::Guest(e)) => {
                report.outcome = "error".into();
                report.error = Some(match e {
                    BlockError::InvalidInput(m) => format!("invalid-input: {m}"),
                    BlockError::Failed(m) => format!("failed: {m}"),
                });
            }
            RunOutcome::Error(ErrorOutcome::Trap(code)) => {
                // JEP-0006: a deterministic trap is an `error` outcome carrying its trap code.
                report.outcome = "error".into();
                report.trap = Some(code.as_str().to_string());
            }
            RunOutcome::Incomplete(reason) => {
                report.outcome = "incomplete".into();
                report.reason = Some(match reason {
                    IncompleteReason::FuelExhausted => "fuel exhausted".into(),
                    IncompleteReason::StackExhausted => "stack exhausted".into(),
                    IncompleteReason::DeadlineExceeded => "deadline exceeded".into(),
                    IncompleteReason::HostFault(d) => format!("host fault: {d}"),
                });
            }
        }
        Ok(report)
    }
}

/// The limits for a run, from the command line.
pub fn limits(fuel: Option<u64>, timeout_ms: Option<u64>) -> RenderLimits {
    RenderLimits {
        fuel: fuel.unwrap_or(DEFAULT_FUEL),
        timeout: timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_TIMEOUT),
    }
}

fn view(p: &Payload) -> OutputView {
    let text = std::str::from_utf8(&p.body).ok().map(str::to_string);
    OutputView {
        media_type: p.media_type.clone(),
        len: p.body.len(),
        hex: text.is_none().then(|| encode_hex(&p.body)),
        text,
    }
}

fn encode_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().trim_start_matches("0x");
    if !s.len().is_multiple_of(2) {
        bail!("odd number of hex digits");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}

// ---- Vectors (`jig block test`) ----

/// The directory a project keeps its vectors in.
pub const VECTORS_DIR: &str = "tests/vectors";

/// One vector file: an invocation and, once blessed, its expected outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vector {
    #[serde(default)]
    pub invocation: InvocationSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<Expected>,
}

/// What `test` found for one vector.
#[derive(Debug)]
pub enum VectorResult {
    Pass,
    /// Expected one comparable outcome, got another.
    Fail {
        expected: Expected,
        got: RunReport,
    },
    /// The run was incomplete: no verdict, as for any executor.
    Incomplete(RunReport),
    /// No `[expect]` yet; `--bless` records one.
    Unblessed(RunReport),
    Blessed(Expected),
}

/// Run every vector in `project_dir`. With `bless`, record the outcome of each vector that has
/// none, or whose outcome changed.
pub fn test_vectors(
    exec: &Executor,
    project_dir: &Path,
    bless: bool,
) -> Result<Vec<(PathBuf, VectorResult)>> {
    let dir = project_dir.join(VECTORS_DIR);
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect(),
        Err(_) => Vec::new(),
    };
    files.sort();
    let mut results = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let mut vector: Vector =
            toml::from_str(&text).with_context(|| format!("reading {}", path.display()))?;
        let report = exec.run(&vector.invocation)?;
        let result = match (report.expected(), &vector.expect) {
            (None, _) => VectorResult::Incomplete(report),
            (Some(got), Some(want)) if &got == want => VectorResult::Pass,
            (Some(got), _) if bless => {
                vector.expect = Some(got.clone());
                std::fs::write(&path, toml::to_string(&vector)?)
                    .with_context(|| format!("writing {}", path.display()))?;
                VectorResult::Blessed(got)
            }
            (Some(_), None) => VectorResult::Unblessed(report),
            (Some(_), Some(want)) => VectorResult::Fail {
                expected: want.clone(),
                got: report,
            },
        };
        results.push((path, result));
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_spec_fills_every_invocation_field() {
        let spec = InvocationSpec {
            block_cid: "b".into(),
            sender: "did:jig:s".into(),
            channel: "c".into(),
            seq: 7,
            wall_ms: 8,
            logical: 9,
            media_type: "text/x".into(),
            input: "in".into(),
            input_hex: None,
        };
        let inv = spec.to_invocation().unwrap();
        assert_eq!(
            (
                inv.block_cid.as_str(),
                inv.sender_did.as_str(),
                inv.channel_cid.as_str()
            ),
            ("b", "did:jig:s", "c")
        );
        assert_eq!(
            (
                inv.ingest_seq,
                inv.ingest_hlc.wall_ms,
                inv.ingest_hlc.logical
            ),
            (7, 8, 9)
        );
        assert_eq!(
            (inv.input.media_type.as_str(), inv.input.body.as_slice()),
            ("text/x", &b"in"[..])
        );
    }

    /// Every JEP-0006 conformance vector, run through this executor, gives the pinned
    /// invocation hash and outcome. This is what makes `jig block run` agree with the server and
    /// the client, not the shared code alone.
    #[test]
    fn the_cli_executor_passes_the_block_abi_vectors() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../jig-spec/vectors/block-abi");
        let file: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{dir}/vectors.json")).expect("vectors.json"),
        )
        .unwrap();
        let vectors = file["vectors"].as_array().expect("a vectors array");
        assert!(vectors.len() >= 20, "the vector set looks truncated");
        for v in vectors {
            let name = v["name"].as_str().unwrap();
            let inv = &v["invocation"];
            let spec = InvocationSpec {
                block_cid: inv["block-cid"].as_str().unwrap().into(),
                sender: inv["sender-did"].as_str().unwrap().into(),
                channel: inv["channel-cid"].as_str().unwrap().into(),
                seq: inv["ingest-seq"].as_u64().unwrap(),
                wall_ms: inv["ingest-hlc"]["wall-ms"].as_u64().unwrap(),
                logical: inv["ingest-hlc"]["logical"].as_u64().unwrap() as u32,
                media_type: inv["input"]["media-type"].as_str().unwrap().into(),
                input: String::new(),
                input_hex: Some(inv["input"]["body-hex"].as_str().unwrap().into()),
            };
            let target = Target {
                bytes: std::fs::read(format!("{dir}/{}", v["component"].as_str().unwrap()))
                    .unwrap_or_else(|e| panic!("{name}: {e}")),
                max_memory_pages: v["max-memory-pages"].as_u64().unwrap() as u32,
                project_dir: None,
            };
            let lim = limits(v["fuel"].as_u64(), v["timeout-ms"].as_u64());
            let report = Executor::new(&target, lim)
                .unwrap_or_else(|e| panic!("{name}: {e:#}"))
                .run(&spec)
                .unwrap();
            assert_eq!(
                Some(report.invocation_hash.as_str()),
                v["invocation-hash"].as_str(),
                "{name}: invocation hash"
            );
            let want = &v["expected"];
            assert_eq!(report.outcome, want["outcome"].as_str().unwrap(), "{name}");
            assert_eq!(
                report.hash.as_deref(),
                want["hash"].as_str(),
                "{name}: hash"
            );
            assert_eq!(
                report.trap.as_deref(),
                want["trap"].as_str(),
                "{name}: trap"
            );
        }
    }

    /// The committed text-block component, the reference renderer (JEP-0006 step 5).
    fn text_block() -> Target {
        Target {
            bytes: std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../text-block/artifacts/text_block.component.wasm"
            ))
            .expect("the committed text-block component"),
            max_memory_pages: DEFAULT_MEMORY_PAGES,
            project_dir: None,
        }
    }

    #[test]
    fn text_block_runs_through_the_shared_component_path() {
        let target = text_block();
        assert!(is_component(&target.bytes));
        let exec = Executor::new(&target, limits(None, None)).unwrap();
        let spec = InvocationSpec {
            input: "hello".into(),
            ..InvocationSpec::default()
        };
        let a = exec.run(&spec).unwrap();
        assert_eq!(a.outcome, "ok", "{}", a.render());
        assert!(a.hash.as_deref().is_some_and(|h| h.starts_with("blake3:")));
        let b = exec.run(&spec).unwrap();
        assert_eq!(
            a.expected(),
            b.expected(),
            "the same run gives the same outcome"
        );

        let other = exec
            .run(&InvocationSpec {
                input: "goodbye".into(),
                ..InvocationSpec::default()
            })
            .unwrap();
        assert_ne!(a.hash, other.hash);
        assert_ne!(a.invocation_hash, other.invocation_hash);
    }

    #[test]
    fn too_little_fuel_is_incomplete_and_has_no_verdict() {
        let exec = Executor::new(&text_block(), limits(Some(10), None)).unwrap();
        let r = exec.run(&InvocationSpec::default()).unwrap();
        assert_eq!(r.outcome, "incomplete");
        assert!(r.hash.is_none());
        assert!(r.expected().is_none());
    }

    #[test]
    fn hex_input_round_trips() {
        let spec = InvocationSpec {
            input_hex: Some("0x00ff10".into()),
            ..InvocationSpec::default()
        };
        assert_eq!(spec.to_invocation().unwrap().input.body, vec![0, 255, 16]);
        let bad = InvocationSpec {
            input_hex: Some("abc".into()),
            ..InvocationSpec::default()
        };
        assert!(bad.to_invocation().is_err());
    }

    #[test]
    fn the_template_vector_parses_as_a_vector() {
        let text = include_str!("../../templates/renderer/vector.toml");
        let v: Vector = toml::from_str(text).unwrap();
        assert_eq!(v.invocation.input, "hello");
        assert!(v.expect.is_none());
    }
}
