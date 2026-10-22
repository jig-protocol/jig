//! Executes canonical block modules on the ingest path.
//!
//! # Why this type exists at all
//!
//! Compiling a Wasm module is the dominant cost of running one: ~16 ms for the
//! 178 KB canonical text-block, against ~85 µs to execute an already-compiled
//! one. Calling `Runtime::execute_payload` per block would cap a server near 62
//! messages/second where the protocol targets 10,000. So the compile happens
//! once, here, and every message reuses the result.
//!
//! # Why the server runs its OWN module
//!
//! A block bundle can carry code (`bundle.code_bytes`), and it is tempting to
//! execute that. For a *canonical* kind like `text-render` it would be wrong:
//! whoever sent the block would then choose the code that computes their own
//! `render_hash`, so two servers could "agree" on a value that has nothing to do
//! with the message text — and the sender would be running arbitrary code in the
//! server's sandbox. The `render_hash` is only meaningful because every server
//! independently renders the same text with a module it picked itself.
//!
//! Sender-supplied code is a separate feature with a separate trust story; it is
//! not this path.

use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(any(test, feature = "test-support"))]
use std::sync::{Arc, OnceLock};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use cid::Cid;
use ed25519_dalek::SigningKey;
use jig_core::block_receipt::{self, Body, Exec, Receipt, Role};
use jig_core::did::Did;
use jig_core::grant::Grant;
use jig_core::operator_policy::{ComponentHash, OperatorPolicy, SignedOperatorPolicy};
use jig_core::program::{self, ProgramManifest, SignedProgram};
use jig_runtime::component::{
    self, Backend, CompiledRenderer, ComponentRuntime, Hlc, Invocation, Payload, RenderLimits,
    RunOutcome,
};
use text_block::canonical;

/// The world text-block's program manifest declares.
pub const RENDERER_WORLD: &str = "jig:block/renderer@0.1.0";

/// The media type of the message text a text-render invocation carries.
const TEXT_MEDIA_TYPE: &str = "text/plain";

/// Bounds how many executions may be in flight against one engine.
///
/// Wasmtime's pooling allocator has a hard ceiling on concurrent instances
/// (`max_concurrent_instances`). Past it, instantiation *fails* rather than
/// queueing — so without this gate a burst of concurrent messages would drop all
/// but the first few with an opaque "maximum concurrent limit reached". Waiting a
/// few microseconds for a slot is the right answer; failing a message is not.
///
/// Deliberately a blocking permit rather than a tokio semaphore: execution itself
/// is synchronous and short (~85 µs for a text render in release), and making the
/// gate async would force `render_text` to be async for every caller while the
/// work underneath stays blocking regardless.
struct Slots {
    available: Mutex<usize>,
    freed: Condvar,
    /// Peak simultaneous holders, for the diagnostic in `in_flight_peak`.
    peak: AtomicUsize,
    limit: usize,
}

impl Slots {
    fn new(limit: usize) -> Self {
        Self {
            available: Mutex::new(limit),
            freed: Condvar::new(),
            peak: AtomicUsize::new(0),
            limit,
        }
    }

    fn acquire(&self) -> SlotGuard<'_> {
        let mut available = self
            .available
            .lock()
            .expect("slot mutex poisoned by a panicking execution");
        while *available == 0 {
            available = self
                .freed
                .wait(available)
                .expect("slot mutex poisoned by a panicking execution");
        }
        *available -= 1;
        let in_flight = self.limit - *available;
        self.peak.fetch_max(in_flight, Ordering::Relaxed);
        SlotGuard { slots: self }
    }
}

/// Returns the permit on drop, including on a panic or an early `?` return —
/// otherwise one failed execution would permanently shrink the pool.
struct SlotGuard<'a> {
    slots: &'a Slots,
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut available) = self.slots.available.lock() {
            *available += 1;
            self.slots.freed.notify_one();
        }
    }
}

/// Failures from executing a canonical block.
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("runtime construction failed: {0}")]
    Runtime(String),
    #[error("compiling the {module} component failed: {source_msg}")]
    Compile { module: String, source_msg: String },
    #[error("the operator policy does not allow the {module} program")]
    NotAllowed { module: String },
    #[error("the {module} program manifest does not name the compiled component")]
    WrongProgram { module: String },
    #[error("signing the {module} program manifest failed: {source_msg}")]
    Program { module: String, source_msg: String },
    #[error("executing the {module} component failed: {source_msg}")]
    Execute { module: String, source_msg: String },
    #[error("the {module} component returned output that did not decode: {source_msg}")]
    DecodeOutput { module: String, source_msg: String },
}

/// One rendered block: the guest's output plus what it took to produce it.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// The guest's decoded result. `render_hash` inside is the protocol-relevant
    /// value — computed *inside* the sandbox, so any conforming runtime on any
    /// host produces it.
    pub output: text_block::Output,
    /// Fully-qualified identity of the component that produced `output`:
    /// `text-block@<version>/blake3:<hash>`.
    ///
    /// Without this a `render_hash` mismatch between two servers is
    /// unattributable — "we rendered different text" and "we ran different code"
    /// look identical. It belongs in the SIGNED receipt payload, not a bare
    /// column, because an unsigned provenance claim is not worth having.
    pub module_id: String,
    /// Wasm fuel consumed.
    ///
    /// **Local telemetry, never a protocol quantity.** There is no cross-runtime
    /// metering standard and no published conversion between engines, and fuel is
    /// not stable across wasmtime's own versions — so this number is only
    /// comparable against one produced by the same engine at the same version.
    /// Cross-server agreement rests on the outcome hash alone. See
    /// `docs/investigations/2026-08-11-fuel-portability.md`.
    pub fuel_used: u64,
    /// The engine, configuration and fuel schedule `fuel_used` was measured
    /// under. It is what makes the number comparable at all.
    pub engine_identity: jig_runtime::EngineIdentity,
}

/// One run of the text-render component, whatever its outcome, with everything its `exec`
/// receipt states.
#[derive(Debug, Clone)]
pub struct ExecRun {
    pub outcome: RunOutcome,
    /// The receipt body: component, program, world, invocation hash, operator policy, outcome,
    /// limits and engine.
    pub exec: Exec,
}

impl ExecRun {
    /// The decoded text-render output, if the run returned `ok`.
    pub fn text_output(&self) -> Result<text_block::Output, ExecutorError> {
        let module = || canonical::MODULE_NAME.to_string();
        let payload = match &self.outcome {
            RunOutcome::Ok(payload) => payload,
            other => {
                return Err(ExecutorError::Execute {
                    module: module(),
                    source_msg: format!("{other:?}"),
                });
            }
        };
        if payload.media_type != canonical::COMPONENT_OUTPUT_MEDIA_TYPE {
            return Err(ExecutorError::DecodeOutput {
                module: module(),
                source_msg: format!("unexpected media type {:?}", payload.media_type),
            });
        }
        postcard::from_bytes(&payload.body).map_err(|e| ExecutorError::DecodeOutput {
            module: module(),
            source_msg: e.to_string(),
        })
    }

    /// The server's `exec` receipt for `block_cid`, unsigned. `executor` must be the DID of the
    /// key that signs it, and of the server that signed the operator policy it names.
    pub fn receipt(&self, block_cid: Cid, executor: String, produced_at: u64) -> Receipt {
        Receipt {
            block_cid,
            executor,
            role: Role::Server,
            produced_at,
            body: Body::Exec(Box::new(self.exec.clone())),
        }
    }
}

/// Holds the compiled canonical components for the lifetime of a server.
pub struct BlockExecutor {
    runtime: ComponentRuntime,
    text_render: CompiledRenderer,
    text_render_component: ComponentHash,
    text_render_module_id: String,
    program: SignedProgram,
    policy: SignedOperatorPolicy,
    render_limits: RenderLimits,
    receipt_limits: block_receipt::Limits,
    slots: Slots,
}

impl BlockExecutor {
    /// Build a runtime under operator-supplied limits, compile the canonical components, and sign
    /// the server's default operator policy (JEP-0011 §5.1) with `server_key`. Do this once, at
    /// boot.
    ///
    /// The concurrency gate is sized from `config.limits.max_concurrent_instances`,
    /// so lowering that in config lowers both the engine's pooling ceiling and the
    /// gate that keeps callers under it. They must move together: a gate wider
    /// than the pool reintroduces the hard instantiation failure the gate exists
    /// to prevent.
    ///
    /// Every run is bounded by the effective limits: the smaller of the program manifest's
    /// `limits` and the operator's config, for fuel and memory; the deadline is the operator's
    /// alone, since a manifest states none. Receipts state the effective limits.
    pub fn with_config(
        config: jig_runtime::RuntimeConfig,
        server_key: &SigningKey,
        program: SignedProgram,
    ) -> Result<Self, ExecutorError> {
        let concurrency = config.limits.max_concurrent_instances.max(1) as usize;
        let declared = program.manifest.limits;
        let memory_max_pages = config
            .limits
            .memory_max_mb
            .saturating_mul(16)
            .min(declared.memory_max_pages);
        let fuel = config.limits.fuel_max.min(declared.fuel_max);
        let render_limits = RenderLimits {
            fuel,
            timeout: Duration::from_millis(config.limits.execution_timeout_ms),
        };
        let receipt_limits = block_receipt::Limits {
            fuel,
            max_wasm_stack: jig_runtime::MAX_WASM_STACK as u64,
            memory_max_pages,
            timeout_ms: config.limits.execution_timeout_ms,
        };
        let runtime = ComponentRuntime::with_config(&config, Backend::Native)
            .map_err(|e| ExecutorError::Runtime(e.to_string()))?;
        // text-block's manifest requests nothing, so it is compiled against the empty grant.
        let text_render = runtime
            .compile_renderer(
                canonical::CANONICAL_COMPONENT,
                &Grant::empty(),
                memory_max_pages,
            )
            .map_err(|e| ExecutorError::Compile {
                module: canonical::MODULE_NAME.to_string(),
                source_msg: e.to_string(),
            })?;
        let text_render_component = component::hash_bytes(text_render.component_hash());
        if program.manifest.component != text_render_component
            || program.manifest.world != RENDERER_WORLD
        {
            return Err(ExecutorError::WrongProgram {
                module: canonical::MODULE_NAME.to_string(),
            });
        }

        let server = Did::from_ed25519_pubkey(&server_key.verifying_key().to_bytes());
        let policy = SignedOperatorPolicy::sign(
            OperatorPolicy::default_for(server.to_did_jig_string(), &[text_render_component]),
            server_key,
        );

        let executor = Self {
            runtime,
            text_render,
            text_render_component,
            text_render_module_id: canonical::component_id(),
            program,
            policy,
            render_limits,
            receipt_limits,
            // Matched to the engine's pooling ceiling: the gate exists to keep us
            // strictly under it, so a mismatch here reintroduces the failure it
            // prevents.
            slots: Slots::new(concurrency),
        };
        // A server whose own policy refuses its own renderer cannot render anything; say so at
        // boot rather than on every message.
        if !executor
            .policy
            .policy
            .allows(&executor.program.manifest.facts(&executor.program.cid))
        {
            return Err(ExecutorError::NotAllowed {
                module: canonical::MODULE_NAME.to_string(),
            });
        }
        Ok(executor)
    }

    /// Highest number of simultaneous executions observed. Diagnostic only —
    /// a value at the configured ceiling means callers are queueing.
    pub fn in_flight_peak(&self) -> usize {
        self.slots.peak.load(Ordering::Relaxed)
    }

    /// A process-wide executor for **tests**, compiled on first use.
    ///
    /// Exists so the many tests that build an `IngestContext` don't each pay the
    /// component compile; the executor is immutable after construction, so sharing
    /// is safe.
    ///
    /// Its operator policy and program manifest are signed by a fixed, public test key, so it
    /// exists only under `cfg(test)` or the `test-support` feature, which only
    /// `[dev-dependencies]` enable.
    ///
    /// **Panics** if the canonical component fails to compile. That is acceptable in
    /// a test binary and not in a server, which is why production code must use
    /// [`BlockExecutor::with_config`] and propagate the error — a server that cannot
    /// compile its component should report why, not abort. `jig-server` does this in
    /// `AppState::new`.
    ///
    /// Note the sharing is per-process, so it does not amortize under
    /// `cargo nextest`, which runs a process per test.
    ///
    /// Tests that measure [`BlockExecutor::in_flight_peak`] must build their own:
    /// `peak` is per-executor, so a shared one accumulates other tests' concurrency
    /// and an assertion on it would not be measuring the test that made it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn shared() -> Arc<Self> {
        static SHARED: OnceLock<Arc<BlockExecutor>> = OnceLock::new();
        SHARED
            .get_or_init(|| {
                Arc::new(
                    Self::for_tests(jig_runtime::RuntimeConfig::default()).expect(
                        "the canonical text-block component must compile; it is embedded \
                     at build time and covered by jig-runtime's component tests",
                    ),
                )
            })
            .clone()
    }

    /// An executor with a test key and test program identity, under `config`. For tests only;
    /// see [`BlockExecutor::shared`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests(config: jig_runtime::RuntimeConfig) -> Result<Self, ExecutorError> {
        let key = test_server_key();
        let program = text_block_program(&key, &config)?;
        Self::with_config(config, &key, program)
    }

    /// The signed text-block program manifest this executor runs.
    pub fn program(&self) -> &SignedProgram {
        &self.program
    }

    /// Identity of the text-render component this executor will run.
    pub fn text_render_module_id(&self) -> &str {
        &self.text_render_module_id
    }

    /// The signed operator policy every render is checked against.
    pub fn operator_policy(&self) -> &SignedOperatorPolicy {
        &self.policy
    }

    /// Run the text-render component once on `invocation`, after checking the operator policy.
    ///
    /// Every outcome, including a guest error, a trap or an incomplete run, comes back as an
    /// [`ExecRun`], since each one gets an `exec` receipt. Only a refusal by the policy is an
    /// error.
    pub fn render(&self, invocation: &Invocation) -> Result<ExecRun, ExecutorError> {
        if !self
            .policy
            .policy
            .allows(&self.program.manifest.facts(&self.program.cid))
        {
            return Err(ExecutorError::NotAllowed {
                module: canonical::MODULE_NAME.to_string(),
            });
        }
        let invocation_hash = component::hash_bytes(&component::invocation_hash(invocation));

        // Held across the execution only; released by Drop on every path.
        let run = {
            let _slot = self.slots.acquire();
            self.runtime
                .render(&self.text_render, invocation, &self.render_limits)
        };

        let identity = self.runtime.engine_identity();
        let exec = Exec {
            component: self.text_render_component,
            program: self.program.cid,
            world: self.program.manifest.world.clone(),
            invocation_hash,
            operator_policy_cid: Some(self.policy.cid),
            outcome: run.outcome.to_receipt(),
            limits: self.receipt_limits,
            engine: block_receipt::Engine {
                name: "wasmtime".to_string(),
                version: identity.wasmtime,
                profile: "jig-det-1".to_string(),
                config_fingerprint: identity.config_fingerprint,
                fuel_used: run.fuel_used,
            },
        };
        Ok(ExecRun {
            outcome: run.outcome,
            exec,
        })
    }

    /// Render a chat message through the canonical text-render component, and return its output
    /// only if the run returned `ok`.
    ///
    /// The invocation carries no block CID or ingest sequence, so it is not the one a receipt
    /// names; use [`BlockExecutor::render`] for that. `render_hash` depends on the body alone, so
    /// it is unaffected.
    pub fn render_text(&self, input: &text_block::Input) -> Result<Rendered, ExecutorError> {
        let run = self.render(&text_invocation(input, String::new(), 0))?;
        let output = run.text_output()?;
        Ok(Rendered {
            output,
            module_id: self.text_render_module_id.clone(),
            fuel_used: run.exec.engine.fuel_used,
            engine_identity: self.runtime.engine_identity(),
        })
    }
}

/// text-block's program manifest (JEP-0011 §2), built in and signed by `author_key`, with the
/// limits `config` sets.
///
/// Who authors built-ins is the caller's choice. JEP-0011 §5.1 currently has each server sign
/// its own, which gives a per-server program CID; comparison keys on the component either way.
pub fn text_block_program(
    author_key: &SigningKey,
    config: &jig_runtime::RuntimeConfig,
) -> Result<SignedProgram, ExecutorError> {
    let author = Did::from_ed25519_pubkey(&author_key.verifying_key().to_bytes());
    let manifest = ProgramManifest::builtin_renderer(
        author.to_did_jig_string(),
        canonical::MODULE_NAME,
        canonical::MODULE_VERSION,
        RENDERER_WORLD,
        canonical::CANONICAL_COMPONENT,
        program::Limits {
            memory_max_pages: config.limits.memory_max_mb.saturating_mul(16),
            fuel_max: config.limits.fuel_max,
        },
    );
    SignedProgram::sign(manifest, author_key, canonical::CANONICAL_COMPONENT).map_err(|e| {
        ExecutorError::Program {
            module: canonical::MODULE_NAME.to_string(),
            source_msg: e.to_string(),
        }
    })
}

/// The text-render input a block's manifest gives: its body, author, channel name, clock and
/// version. `None` when the manifest has no `body`, since rendering the empty string would hash a
/// message nobody sent.
///
/// The server and every re-executing client build the input with this one function, so they
/// cannot disagree on what was rendered.
pub fn text_input(manifest: &jig_core::BlockManifest) -> Option<text_block::Input> {
    let body = manifest.metadata.get("body")?.as_str()?;
    let channel = manifest
        .metadata
        .get("channel")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let hlc = manifest.hlc_ts.as_ref();
    Some(text_block::Input {
        sender_did: manifest
            .authors
            .first()
            .map(|a| a.did.to_string())
            .unwrap_or_default(),
        channel_id: channel.to_string(),
        body_raw: body.to_string(),
        hlc_wall_ms: hlc.map(|h| h.wall_ms).unwrap_or(0),
        hlc_logical: hlc.map(|h| h.logical).unwrap_or(0),
        hlc_origin: hlc.map(|h| h.server_did.to_string()).unwrap_or_default(),
        client_version: manifest.version.to_string(),
    })
}

/// The invocation an `exec` receipt names for a landed chat message: the message text, and the
/// block's ingest record's sequence, clock and channel CID (JEP-0006). A client rebuilds it from
/// the same record to check the receipt.
pub fn text_render_invocation(
    input: &text_block::Input,
    block_cid: &str,
    record: &crate::ingest_record::IngestRecord,
) -> Invocation {
    let mut invocation = text_invocation(input, block_cid.to_string(), record.seq);
    invocation.channel_cid = record.channel_id.clone();
    invocation.ingest_hlc = Hlc {
        wall_ms: record.ingest_wall_ms,
        logical: record.ingest_logical,
    };
    invocation
}

/// The `jig:block` invocation for a chat message: the message text as the input, and the ingest
/// record's block CID, sequence and clock.
pub fn text_invocation(
    input: &text_block::Input,
    block_cid: String,
    ingest_seq: u64,
) -> Invocation {
    Invocation {
        block_cid,
        sender_did: input.sender_did.clone(),
        channel_cid: input.channel_id.clone(),
        ingest_seq,
        ingest_hlc: Hlc {
            wall_ms: input.hlc_wall_ms,
            logical: input.hlc_logical,
        },
        input: Payload {
            media_type: TEXT_MEDIA_TYPE.to_string(),
            body: input.body_raw.as_bytes().to_vec(),
        },
    }
}

/// The fixed key behind [`BlockExecutor::shared`]'s operator policy. Tests only.
#[cfg(any(test, feature = "test-support"))]
fn test_server_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5a; 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(body: &str) -> text_block::Input {
        text_block::Input {
            sender_did: "did:jig:zSender".into(),
            channel_id: "#hello".into(),
            body_raw: body.into(),
            hlc_wall_ms: 1_747_680_000_000,
            hlc_logical: 0,
            hlc_origin: "did:jig:zOrigin".into(),
            client_version: "test".into(),
        }
    }

    #[test]
    fn rendering_produces_the_same_hash_as_the_native_reference() {
        let ex = BlockExecutor::shared();
        for body in ["hello", "", "hi @deji https://jig.onl", "<b>&</b> 'x'"] {
            let got = ex.render_text(&input(body)).expect("render");
            let native = text_block::execute_pure(&input(body));
            assert_eq!(
                got.output.render_hash, native.render_hash,
                "Wasm and native disagreed for {body:?}"
            );
            assert_eq!(got.output, native);
        }
    }

    #[test]
    fn a_changed_body_changes_the_render_hash() {
        let ex = BlockExecutor::shared();
        let a = ex.render_text(&input("same-ish")).unwrap();
        let b = ex.render_text(&input("same-ish.")).unwrap();
        assert_ne!(a.output.render_hash, b.output.render_hash);
    }

    /// Fields other than `body_raw` must not move the hash. This is what makes
    /// two servers agree: they see the same text but different local context
    /// (their own clock skew, their own view of the sender).
    #[test]
    fn only_the_body_affects_the_render_hash() {
        let ex = BlockExecutor::shared();
        let base = ex.render_text(&input("fixed body")).unwrap();

        let mut other = input("fixed body");
        other.sender_did = "did:jig:zSomeoneElse".into();
        other.channel_id = "#different".into();
        other.hlc_wall_ms = 9_999_999_999_999;
        other.hlc_logical = 42;
        other.hlc_origin = "did:jig:zAnotherServer".into();
        other.client_version = "jig-cli/9.9.9".into();

        assert_eq!(
            ex.render_text(&other).unwrap().output.render_hash,
            base.output.render_hash,
            "render_hash must depend only on the body, or servers cannot agree"
        );
    }

    #[test]
    fn the_component_renders_what_the_abi_1_module_rendered() {
        // render_hash must not move across the switch, or servers on mixed versions disagree.
        let ex = BlockExecutor::shared();
        for body in ["hello", "", "hi @deji https://jig.onl", "<b>&</b> 'x'"] {
            let via_component = ex.render_text(&input(body)).expect("render").output;
            let encoded = postcard::to_allocvec(&input(body)).unwrap();
            let abi1 = jig_runtime::Runtime::new()
                .unwrap()
                .execute_payload(canonical::CANONICAL_WASM, canonical::ENTRY_POINT, &encoded)
                .expect("ABI 1 render");
            let abi1: text_block::Output = postcard::from_bytes(&abi1.bytes).unwrap();
            assert_eq!(via_component.render_hash, abi1.render_hash, "body {body:?}");
        }
    }

    #[test]
    fn a_render_yields_a_server_exec_receipt_that_verifies() {
        let ex = BlockExecutor::shared();
        let block_cid = jig_core::canonical_cid::of(b"a block");
        let run = ex
            .render(&text_invocation(&input("hello"), block_cid.to_string(), 7))
            .expect("render");
        assert!(matches!(run.outcome, RunOutcome::Ok(_)));

        let exec = &run.exec;
        assert_eq!(exec.world, RENDERER_WORLD);
        assert_eq!(exec.operator_policy_cid, Some(ex.operator_policy().cid));
        assert_eq!(
            exec.limits.max_wasm_stack,
            jig_runtime::MAX_WASM_STACK as u64
        );
        assert!(matches!(exec.outcome, block_receipt::Outcome::Ok { .. }));

        let key = test_server_key();
        let server = Did::from_ed25519_pubkey(&key.verifying_key().to_bytes()).to_did_jig_string();
        let signed = block_receipt::SignedReceipt::sign(run.receipt(block_cid, server, 1), &key)
            .expect("the policy's signer signs the receipt");
        let opened = block_receipt::SignedReceipt::open(&signed.envelope).expect("verifies");
        assert_eq!(opened.receipt, signed.receipt);
    }

    #[test]
    fn the_operator_policy_allows_text_block_by_component_and_is_signed_by_the_server() {
        let ex = BlockExecutor::shared();
        let policy = ex.operator_policy();
        let reopened = SignedOperatorPolicy::open(&policy.envelope).expect("policy verifies");
        assert_eq!(reopened.cid, policy.cid);
        assert_eq!(
            policy.policy.allow.components,
            vec![ex.text_render_component]
        );
        assert!(policy.policy.allow.programs.is_empty());
        assert!(policy.policy.allow.authors.is_empty());
    }

    /// Two servers sign different program manifests for text-block (their own DID as author),
    /// yet their receipts for the same invocation agree: comparison keys on the component.
    #[test]
    fn servers_with_different_program_cids_agree_on_the_same_invocation() {
        let x = BlockExecutor::shared();
        let y_key = SigningKey::from_bytes(&[0x17; 32]);
        let config = jig_runtime::RuntimeConfig::default();
        let y_program = text_block_program(&y_key, &config).unwrap();
        let y = BlockExecutor::with_config(config, &y_key, y_program).unwrap();
        let inv = text_invocation(&input("same message"), "bafyblock".into(), 3);
        let (rx, ry) = (x.render(&inv).unwrap(), y.render(&inv).unwrap());
        assert_ne!(rx.exec.program, ry.exec.program);
        assert_eq!(rx.exec.component, ry.exec.component);
        assert_eq!(rx.exec.invocation_hash, ry.exec.invocation_hash);
        assert_eq!(rx.exec.outcome, ry.exec.outcome);
        assert_eq!(
            block_receipt::compare(&rx.exec, &ry.exec),
            block_receipt::Comparison::Agree
        );
    }

    /// The effective limits are the smaller of the manifest's and the operator's, and the
    /// receipt states them.
    #[test]
    fn a_run_is_bounded_by_the_smaller_of_manifest_and_operator_limits() {
        let key = test_server_key();
        let operator = jig_runtime::RuntimeConfig::default();
        let mut tight = operator.clone();
        tight.limits.fuel_max = operator.limits.fuel_max / 2;
        tight.limits.memory_max_mb = operator.limits.memory_max_mb / 2;
        // The manifest declares less than the operator allows: the manifest wins.
        let program = text_block_program(&key, &tight).unwrap();
        let ex = BlockExecutor::with_config(operator.clone(), &key, program).unwrap();
        let run = ex
            .render(&text_invocation(&input("x"), "bafyblock".into(), 1))
            .unwrap();
        assert_eq!(run.exec.limits.fuel, tight.limits.fuel_max);
        assert_eq!(
            run.exec.limits.memory_max_pages,
            tight.limits.memory_max_mb * 16
        );

        // The operator allows less than the manifest declares: the operator wins.
        let program = text_block_program(&key, &operator).unwrap();
        let ex = BlockExecutor::with_config(tight.clone(), &key, program).unwrap();
        let run = ex
            .render(&text_invocation(&input("x"), "bafyblock".into(), 1))
            .unwrap();
        assert_eq!(run.exec.limits.fuel, tight.limits.fuel_max);
        assert_eq!(
            run.exec.limits.timeout_ms,
            tight.limits.execution_timeout_ms
        );
    }

    /// A memory cap below what the component itself declares would let `memory.grow` fail on one
    /// executor and succeed on another, both reporting `ok` with different outcomes. The
    /// validator refuses any memory whose maximum exceeds the cap, so such an executor never
    /// builds.
    #[test]
    fn an_executor_whose_memory_cap_is_below_the_component_declared_maximum_does_not_build() {
        let mut config = jig_runtime::RuntimeConfig::default();
        config.limits.memory_max_mb = 1; // 16 pages, below text-block's declared maximum
        let err = BlockExecutor::for_tests(config)
            .err()
            .expect("a cap below the component's own maximum must refuse to build");
        assert!(matches!(err, ExecutorError::Compile { .. }), "{err:?}");
    }

    #[test]
    fn the_module_id_names_the_canonical_block_and_its_content_hash() {
        let ex = BlockExecutor::shared();
        let id = ex.text_render_module_id().to_string();
        assert!(id.starts_with("text-block@"), "unexpected module id: {id}");
        assert!(
            id.contains("/blake3:"),
            "module id must carry a content hash: {id}"
        );
        assert_eq!(
            ex.render_text(&input("x")).unwrap().module_id,
            id,
            "a render must report the executor's module identity"
        );
    }

    /// The shared executor is the same instance, so the compile really is paid
    /// once. If this regressed, every test building an IngestContext would add
    /// ~16ms.
    #[test]
    fn the_shared_executor_is_reused() {
        assert!(Arc::ptr_eq(
            &BlockExecutor::shared(),
            &BlockExecutor::shared()
        ));
    }

    /// Concurrent renders must all succeed.
    ///
    /// This is the test that matters most here, and the one a sequential
    /// throughput benchmark cannot replace. Wasmtime's pooling allocator has a
    /// hard ceiling on live instances; it was sized from `max_instances`
    /// (default **1**), so the second simultaneous execution failed with
    /// "maximum concurrent limit of 1 for core instances reached". Every
    /// sequential test and the 11,771 msg/s benchmark passed regardless — the
    /// defect only appears when two renders overlap, which on a real server is
    /// the normal case.
    ///
    /// Deliberately oversubscribed: more threads than the configured ceiling, so
    /// the slot gate is exercised rather than merely present.
    ///
    /// Nothing here depends on timing. The wall-clock deadline is raised far
    /// above any render: under the default 250 ms, a full `cargo nextest` run on
    /// a loaded machine could push one debug-build render past it, and the test
    /// would fail on CPU contention rather than on a concurrency defect. The
    /// overlap is proved by [`an_execution_runs_while_another_holds_a_slot`],
    /// not by hoping the scheduler interleaves these threads.
    #[test]
    fn many_concurrent_renders_all_succeed() {
        let ex = Arc::new(executor_without_wall_clock_pressure());
        let threads = 64;
        let per_thread = 8;

        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let ex = Arc::clone(&ex);
                std::thread::spawn(move || {
                    for i in 0..per_thread {
                        let body = format!("thread {t} message {i}");
                        let got = ex
                            .render_text(&input(&body))
                            .unwrap_or_else(|e| panic!("concurrent render failed: {e}"));
                        // Each render must be correct, not merely non-erroring —
                        // a shared-state bug would show up as a hash belonging to
                        // some other thread's message.
                        assert_eq!(
                            got.output.render_hash,
                            text_block::execute_pure(&input(&body)).render_hash,
                            "wrong render_hash under concurrency for {body:?}"
                        );
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("no thread should panic");
        }
    }

    /// A render succeeds while another execution holds a slot, and the gate
    /// records both: two executions really were in flight at once.
    ///
    /// Deterministic where an assertion on `in_flight_peak()` after a burst of
    /// threads is not. Holding a slot ourselves forces the overlap instead of
    /// waiting for the scheduler to produce one.
    #[test]
    fn an_execution_runs_while_another_holds_a_slot() {
        // Its OWN executor, not `shared()`: `peak` is per-executor, so a shared
        // one would carry other tests' concurrency into this assertion.
        let ex = executor_without_wall_clock_pressure();
        let held = ex.slots.acquire();

        let got = ex
            .render_text(&input("rendered while a slot is held"))
            .expect("a render must not need the slot another execution holds");
        assert_eq!(
            got.output.render_hash,
            text_block::execute_pure(&input("rendered while a slot is held")).render_hash
        );
        assert_eq!(
            ex.in_flight_peak(),
            2,
            "the held slot and the render must have been in flight together"
        );
        drop(held);
    }

    /// A default-limits executor whose wall-clock deadline cannot fire in a
    /// test, so a loaded CI machine cannot fail a render on time alone.
    fn executor_without_wall_clock_pressure() -> BlockExecutor {
        let mut config = jig_runtime::RuntimeConfig::default();
        config.limits.execution_timeout_ms = 60_000;
        BlockExecutor::for_tests(config).expect("executor construction")
    }

    /// `with_config` must actually apply the limits it is handed.
    ///
    /// This is the far end of the operator-config chain: `[execution]` ->
    /// `ExecutionConfig` -> `runtime_config_from` -> here. A starved fuel budget
    /// is the cheapest limit to prove, because a render that would otherwise
    /// succeed must now fail. Without this, `with_config` could ignore its
    /// argument entirely and every other test would still pass.
    #[test]
    fn a_configured_fuel_limit_is_enforced() {
        let mut config = jig_runtime::RuntimeConfig::default();
        config.limits.fuel_max = 100; // far below what a real render costs
        let ex = BlockExecutor::for_tests(config).expect("executor builds");

        let err = ex
            .render_text(&input("this render cannot fit in 100 fuel"))
            .expect_err("a starved fuel budget must fail the render");

        assert!(
            matches!(err, ExecutorError::Execute { .. }),
            "expected an execution failure, got {err:?}"
        );

        // And the same executor at a normal budget succeeds, so the failure above
        // is attributable to the limit rather than to anything else.
        let ok = BlockExecutor::for_tests(jig_runtime::RuntimeConfig::default())
            .expect("executor builds")
            .render_text(&input("this render cannot fit in 100 fuel"))
            .expect("a default budget must succeed");
        assert!(!ok.output.render_hash.is_empty());
    }
}
