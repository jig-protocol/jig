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
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use jig_runtime::{CompiledBlock, Runtime};
use text_block::canonical;

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
    #[error("compiling the {module} module failed: {source_msg}")]
    Compile { module: String, source_msg: String },
    #[error("encoding block input failed: {0}")]
    EncodeInput(String),
    #[error("executing the {module} module failed: {source_msg}")]
    Execute { module: String, source_msg: String },
    #[error("the {module} module returned output that did not decode: {source_msg}")]
    DecodeOutput { module: String, source_msg: String },
}

/// One rendered block: the guest's output plus what it took to produce it.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// The guest's decoded result. `render_hash` inside is the protocol-relevant
    /// value — computed *inside* the sandbox, so any conforming runtime on any
    /// host produces it.
    pub output: text_block::Output,
    /// Fully-qualified identity of the module that produced `output`:
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
    /// Cross-server agreement rests on `render_hash` alone. See
    /// `docs/investigations/2026-08-11-fuel-portability.md`.
    pub fuel_used: u64,
}

/// Holds the compiled canonical modules for the lifetime of a server.
pub struct BlockExecutor {
    runtime: Runtime,
    text_render: CompiledBlock,
    text_render_module_id: String,
    slots: Slots,
}

impl BlockExecutor {
    /// Build a runtime and compile the canonical modules. Do this once, at boot.
    ///
    /// Uses the default [`jig_runtime::RuntimeConfig`]. A server that lets an
    /// operator configure execution limits should call
    /// [`BlockExecutor::with_config`] instead and pass the same config it gives
    /// every other execution path — otherwise the ingest render path silently
    /// runs under different limits from the rest of the server.
    pub fn new() -> Result<Self, ExecutorError> {
        Self::with_config(jig_runtime::RuntimeConfig::default())
    }

    /// Build a runtime under operator-supplied limits and compile the canonical
    /// modules.
    ///
    /// The concurrency gate is sized from `config.limits.max_concurrent_instances`,
    /// so lowering that in config lowers both the engine's pooling ceiling and the
    /// gate that keeps callers under it. They must move together: a gate wider
    /// than the pool reintroduces the hard instantiation failure the gate exists
    /// to prevent.
    pub fn with_config(config: jig_runtime::RuntimeConfig) -> Result<Self, ExecutorError> {
        let concurrency = config.limits.max_concurrent_instances.max(1) as usize;
        let runtime =
            Runtime::with_config(config).map_err(|e| ExecutorError::Runtime(e.to_string()))?;
        let text_render =
            runtime
                .precompile(canonical::CANONICAL_WASM)
                .map_err(|e| ExecutorError::Compile {
                    module: canonical::MODULE_NAME.to_string(),
                    source_msg: e.to_string(),
                })?;
        Ok(Self {
            runtime,
            text_render,
            text_render_module_id: canonical::module_id(),
            // Matched to the engine's pooling ceiling: the gate exists to keep us
            // strictly under it, so a mismatch here reintroduces the failure it
            // prevents.
            slots: Slots::new(concurrency),
        })
    }

    /// Highest number of simultaneous executions observed. Diagnostic only —
    /// a value at the configured ceiling means callers are queueing.
    pub fn in_flight_peak(&self) -> usize {
        self.slots.peak.load(Ordering::Relaxed)
    }

    /// A process-wide executor for **tests**, compiled on first use.
    ///
    /// Exists so the many tests that build an `IngestContext` don't each pay the
    /// module compile; the executor is immutable after construction, so sharing
    /// is safe.
    ///
    /// **Panics** if the canonical module fails to compile. That is acceptable in
    /// a test binary and not in a server, which is why production code must use
    /// [`BlockExecutor::new`] or [`BlockExecutor::with_config`] and propagate the
    /// error — a server that cannot compile its module should report why, not
    /// abort. `jig-server` does this in `AppState::new`.
    ///
    /// Note the sharing is per-process, so it does not amortize under
    /// `cargo nextest`, which runs a process per test.
    ///
    /// Tests that measure [`BlockExecutor::in_flight_peak`] must build their own
    /// via `new()`: `peak` is per-executor, so a shared one accumulates other
    /// tests' concurrency and an assertion on it would not be measuring the test
    /// that made it.
    pub fn shared() -> Arc<Self> {
        static SHARED: OnceLock<Arc<BlockExecutor>> = OnceLock::new();
        SHARED
            .get_or_init(|| {
                Arc::new(Self::new().expect(
                    "the canonical text-block module must compile; it is embedded \
                     at build time and covered by jig-runtime's payload tests",
                ))
            })
            .clone()
    }

    /// Identity of the text-render module this executor will run.
    pub fn text_render_module_id(&self) -> &str {
        &self.text_render_module_id
    }

    /// Render a chat message through the canonical text-render module.
    pub fn render_text(&self, input: &text_block::Input) -> Result<Rendered, ExecutorError> {
        let encoded =
            postcard::to_allocvec(input).map_err(|e| ExecutorError::EncodeInput(e.to_string()))?;

        // Held across the execution only; released by Drop on every path.
        let _slot = self.slots.acquire();
        let result = self
            .runtime
            .execute_precompiled(&self.text_render, canonical::ENTRY_POINT, &encoded)
            .map_err(|e| ExecutorError::Execute {
                module: canonical::MODULE_NAME.to_string(),
                source_msg: e.to_string(),
            })?;

        let output: text_block::Output =
            postcard::from_bytes(&result.bytes).map_err(|e| ExecutorError::DecodeOutput {
                module: canonical::MODULE_NAME.to_string(),
                source_msg: e.to_string(),
            })?;

        Ok(Rendered {
            output,
            module_id: self.text_render_module_id.clone(),
            fuel_used: result.fuel_used,
        })
    }
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
    #[test]
    fn many_concurrent_renders_all_succeed() {
        // Its OWN executor, not `shared()`. `peak` is per-executor, so a shared
        // one accumulates every other test's concurrency in this process — and
        // the `in_flight_peak() > 1` assertion below would then pass on someone
        // else's overlap rather than this test's, which is precisely the evidence
        // it is supposed to provide.
        let ex = Arc::new(BlockExecutor::new().expect("executor construction"));
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

        assert!(
            ex.in_flight_peak() > 1,
            "peak in-flight was {} — the test did not actually overlap any \
             executions, so it is not testing concurrency",
            ex.in_flight_peak()
        );
    }
}
