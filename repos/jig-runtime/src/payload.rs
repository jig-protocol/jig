//! Byte-payload calling convention for jig blocks.
//!
//! [`Runtime::execute`](crate::Runtime::execute) runs a module for its *side
//! effects*: it looks for `run`/`_start`/`main`, calls it with no arguments, and
//! reports fuel and timing. That is enough to prove a module executed, but it
//! cannot pass a message body in or read a rendered result out — so it cannot
//! produce a `render_hash` that depends on the message. (Its receipt's
//! `render_hash` is the hash of the module bytes, which is constant for a given
//! module and therefore identical for every message.)
//!
//! This module adds the missing half: a data-in/data-out convention.
//!
//! # The convention
//!
//! A participating module exports:
//!
//! ```text
//! jig_alloc(len: i32) -> i32                       // returns a guest address
//! jig_dealloc(ptr: i32, len: i32)
//! <export>(in_ptr: i32, in_len: i32, out_ptr: i32, out_len_ptr: i32) -> i32
//! ```
//!
//! and a linear memory named `memory`. The entry point returns `0` on success,
//! or [`RC_OUTPUT_TOO_SMALL`] to mean "the buffer was too small; I have written
//! the required length to `*out_len_ptr`" — which is what makes a single retry
//! sufficient regardless of output size.
//!
//! The allocator exports are the load-bearing part. Without them a host has to
//! invent a guest address, which can land on the shadow stack or on live
//! allocator state; the guest owns its address space and must be asked.
//!
//! # Deliberately no host imports
//!
//! Modules are instantiated with an empty import list, so a module that imports
//! anything at all — including WASI — fails here by construction. Pure
//! render-style blocks need nothing from the host, and refusing imports keeps
//! that true as the block ecosystem grows rather than trusting each new module
//! to behave.

use crate::api::Runtime;
use crate::engine::StoreLimits;
use crate::error::{Result, RuntimeError};

/// The store type `create_store_with_limits` hands back. Aliased so the helpers
/// below do not have to restate it.
type LimitedStore = wasmtime::Store<StoreLimits>;

/// The guest ran but its output did not fit; `*out_len_ptr` now holds the
/// required length.
pub const RC_OUTPUT_TOO_SMALL: i32 = 3;

/// First-attempt output buffer size. Sized so a typical `text-block` render
/// lands in one call and the retry path stays an exception rather than the norm.
/// Its 4 KiB body cap can still exceed this once HTML escaping expands the text,
/// which is exactly why the retry path exists and is tested.
const INITIAL_OUTPUT_CAPACITY: i32 = 16 * 1024;

/// Hard ceiling on a retry allocation, so a guest cannot demand an arbitrary
/// amount of host-driven memory by reporting a huge required length.
const MAX_OUTPUT_CAPACITY: i32 = 4 * 1024 * 1024;

/// Result of a byte-payload execution.
#[derive(Debug, Clone)]
pub struct PayloadOutput {
    /// Raw bytes the guest wrote. Interpreting them is the caller's business —
    /// this layer is deliberately format-agnostic.
    pub bytes: Vec<u8>,
    /// Fuel consumed, or 0 when fuel metering is disabled in config.
    pub fuel_used: u64,
    /// blake3 of the module bytes, hex. Identifies WHICH module produced
    /// `bytes` — the thing that makes a hash mismatch attributable to "we ran
    /// different code" rather than "we rendered different text".
    pub module_hash: String,
}

/// A validated, compiled module, ready to execute repeatedly.
///
/// Compilation is the dominant cost of running a block: measured at ~16 ms for
/// the 178 KB canonical text-block on an M-series laptop in release mode, which
/// is ~62 messages/second if you pay it per message. The protocol targets 10,000
/// messages/second, so anything on the ingest path must compile once at startup
/// and instantiate per message. That is the entire reason this type exists.
///
/// Tied to the [`Runtime`] that produced it — a `Module` belongs to its `Engine`.
/// Executing one against a different `Runtime` fails at instantiation rather than
/// silently misbehaving, but don't rely on that: keep them together.
pub struct CompiledBlock {
    module: wasmtime::Module,
    module_hash: String,
}

impl CompiledBlock {
    /// blake3 of the module bytes this was compiled from, hex.
    pub fn module_hash(&self) -> &str {
        &self.module_hash
    }
}

impl std::fmt::Debug for CompiledBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The Module itself has no useful Debug and is large; the hash identifies
        // it exactly, which is what a log line actually wants.
        f.debug_struct("CompiledBlock")
            .field("module_hash", &self.module_hash)
            .finish_non_exhaustive()
    }
}

impl Runtime {
    /// Validate and compile a module once, for repeated execution.
    ///
    /// Do this at startup for any block on a hot path; see [`CompiledBlock`] for
    /// the measurement that motivates it.
    pub fn precompile(&self, wasm_bytes: &[u8]) -> Result<CompiledBlock> {
        self.validate_module(wasm_bytes)?;
        Ok(CompiledBlock {
            module: self.engine.compile_module(wasm_bytes)?,
            module_hash: blake3::hash(wasm_bytes).to_hex().to_string(),
        })
    }

    /// Compile and execute in one call.
    ///
    /// Convenient for tests and one-shot tooling. **Not for a hot path** — it
    /// recompiles on every invocation. Use [`Runtime::precompile`] plus
    /// [`Runtime::execute_precompiled`] there.
    pub fn execute_payload(
        &self,
        wasm_bytes: &[u8],
        export: &str,
        input: &[u8],
    ) -> Result<PayloadOutput> {
        let compiled = self.precompile(wasm_bytes)?;
        self.execute_precompiled(&compiled, export, input)
    }

    /// Execute `export` on an already-compiled block under the byte-payload
    /// convention, passing `input` and returning whatever the guest wrote.
    ///
    /// Fails if the module imports anything, lacks `memory`, lacks the
    /// allocator exports, or reports a nonzero code other than a single
    /// recoverable [`RC_OUTPUT_TOO_SMALL`].
    pub fn execute_precompiled(
        &self,
        block: &CompiledBlock,
        export: &str,
        input: &[u8],
    ) -> Result<PayloadOutput> {
        let module_hash = block.module_hash.clone();
        let module = &block.module;

        let limits = &self.config.limits;
        let timeout = std::time::Duration::from_millis(limits.execution_timeout_ms);
        let mut store =
            self.engine
                .create_store_with_limits(limits.fuel_max, limits.memory_max_mb, timeout)?;
        // The store's epoch deadline is driven by the engine's shared ticker;
        // nothing to schedule or cancel per execution.

        let fuel_before = store.get_fuel().unwrap_or(0);

        // Empty import list: a module with imports cannot instantiate here, by design.
        let instance = wasmtime::Instance::new(&mut store, module, &[]).map_err(|e| {
            RuntimeError::InstantiationError(format!(
                "{e} (this convention instantiates with no host imports; \
                 a module importing WASI or anything else cannot be used here)"
            ))
        })?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| RuntimeError::ExecutionError("module exports no `memory`".into()))?;

        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "jig_alloc")
            .map_err(|e| {
                RuntimeError::ExecutionError(format!("missing `jig_alloc` export: {e}"))
            })?;
        let dealloc = instance
            .get_typed_func::<(i32, i32), ()>(&mut store, "jig_dealloc")
            .map_err(|e| {
                RuntimeError::ExecutionError(format!("missing `jig_dealloc` export: {e}"))
            })?;
        let entry = instance
            .get_typed_func::<(i32, i32, i32, i32), i32>(&mut store, export)
            .map_err(|e| RuntimeError::ExecutionError(format!("missing `{export}` export: {e}")))?;

        let input_len = i32::try_from(input.len()).map_err(|_| {
            RuntimeError::ValidationError(format!("input of {} bytes exceeds i32", input.len()))
        })?;

        // Guest allocations, released on every exit path below.
        let input_ptr = call_alloc(&alloc, &mut store, input_len)?;
        // A 4-byte cell holding the output capacity on the way in and the
        // written (or required) length on the way out.
        let out_len_ptr = call_alloc(&alloc, &mut store, 4)?;

        let write_result = memory
            .write(&mut store, input_ptr as usize, input)
            .map_err(|e| RuntimeError::ExecutionError(format!("writing input to guest: {e}")));
        if let Err(e) = write_result {
            let _ = dealloc.call(&mut store, (input_ptr, input_len));
            let _ = dealloc.call(&mut store, (out_len_ptr, 4));
            return Err(e);
        }

        let mut capacity = INITIAL_OUTPUT_CAPACITY;
        let mut out_ptr = call_alloc(&alloc, &mut store, capacity)?;

        let mut attempt = 0;
        let output_bytes = loop {
            attempt += 1;

            // Publish the capacity for this attempt.
            if let Err(e) = memory.write(
                &mut store,
                out_len_ptr as usize,
                &(capacity as u32).to_le_bytes(),
            ) {
                let _ = dealloc.call(&mut store, (out_ptr, capacity));
                let _ = dealloc.call(&mut store, (input_ptr, input_len));
                let _ = dealloc.call(&mut store, (out_len_ptr, 4));
                return Err(RuntimeError::ExecutionError(format!(
                    "writing output capacity to guest: {e}"
                )));
            }

            let rc = entry.call(&mut store, (input_ptr, input_len, out_ptr, out_len_ptr));

            let rc = match rc {
                Ok(rc) => rc,
                Err(trap) => {
                    let _ = dealloc.call(&mut store, (out_ptr, capacity));
                    let _ = dealloc.call(&mut store, (input_ptr, input_len));
                    let _ = dealloc.call(&mut store, (out_len_ptr, 4));
                    return Err(RuntimeError::Trap(trap.to_string()));
                }
            };

            let reported = read_u32(&memory, &mut store, out_len_ptr)?;

            if rc == 0 {
                if reported > capacity as u32 {
                    let _ = dealloc.call(&mut store, (out_ptr, capacity));
                    let _ = dealloc.call(&mut store, (input_ptr, input_len));
                    let _ = dealloc.call(&mut store, (out_len_ptr, 4));
                    return Err(RuntimeError::ExecutionError(format!(
                        "guest reported {reported} bytes written into a {capacity}-byte buffer"
                    )));
                }
                let mut buf = vec![0u8; reported as usize];
                let read = memory.read(&mut store, out_ptr as usize, &mut buf);
                let _ = dealloc.call(&mut store, (out_ptr, capacity));
                let _ = dealloc.call(&mut store, (input_ptr, input_len));
                let _ = dealloc.call(&mut store, (out_len_ptr, 4));
                read.map_err(|e| {
                    RuntimeError::ExecutionError(format!("reading output from guest: {e}"))
                })?;
                break buf;
            }

            if rc == RC_OUTPUT_TOO_SMALL && attempt == 1 {
                // Grow to exactly what the guest asked for and try once more.
                let needed = i32::try_from(reported).ok().filter(|n| *n > 0);
                let Some(needed) = needed else {
                    let _ = dealloc.call(&mut store, (out_ptr, capacity));
                    let _ = dealloc.call(&mut store, (input_ptr, input_len));
                    let _ = dealloc.call(&mut store, (out_len_ptr, 4));
                    return Err(RuntimeError::ExecutionError(format!(
                        "guest requested an unusable output length: {reported}"
                    )));
                };
                if needed > MAX_OUTPUT_CAPACITY {
                    let _ = dealloc.call(&mut store, (out_ptr, capacity));
                    let _ = dealloc.call(&mut store, (input_ptr, input_len));
                    let _ = dealloc.call(&mut store, (out_len_ptr, 4));
                    return Err(RuntimeError::ExecutionError(format!(
                        "guest requested {needed} output bytes, over the \
                         {MAX_OUTPUT_CAPACITY}-byte ceiling"
                    )));
                }
                let _ = dealloc.call(&mut store, (out_ptr, capacity));
                capacity = needed;
                out_ptr = call_alloc(&alloc, &mut store, capacity)?;
                continue;
            }

            let _ = dealloc.call(&mut store, (out_ptr, capacity));
            let _ = dealloc.call(&mut store, (input_ptr, input_len));
            let _ = dealloc.call(&mut store, (out_len_ptr, 4));
            return Err(RuntimeError::ExecutionError(format!(
                "`{export}` returned {rc} (attempt {attempt})"
            )));
        };

        let fuel_after = store.get_fuel().unwrap_or(0);

        Ok(PayloadOutput {
            bytes: output_bytes,
            fuel_used: fuel_before.saturating_sub(fuel_after),
            module_hash,
        })
    }
}

/// Call the guest allocator, rejecting a null return rather than writing to
/// address 0 — which is valid linear memory and would silently corrupt the guest.
fn call_alloc(
    alloc: &wasmtime::TypedFunc<i32, i32>,
    store: &mut LimitedStore,
    len: i32,
) -> Result<i32> {
    let ptr = alloc
        .call(&mut *store, len)
        .map_err(|e| RuntimeError::ExecutionError(format!("jig_alloc({len}) trapped: {e}")))?;
    if ptr == 0 {
        return Err(RuntimeError::ExecutionError(format!(
            "jig_alloc({len}) returned null"
        )));
    }
    Ok(ptr)
}

fn read_u32(memory: &wasmtime::Memory, store: &mut LimitedStore, ptr: i32) -> Result<u32> {
    let mut cell = [0u8; 4];
    memory
        .read(&mut *store, ptr as usize, &mut cell)
        .map_err(|e| RuntimeError::ExecutionError(format!("reading length cell: {e}")))?;
    Ok(u32::from_le_bytes(cell))
}
