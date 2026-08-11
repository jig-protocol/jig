//! Canonical module identity for the `text-render` block.
//!
//! # Why an identity and not just bytes
//!
//! A `render_hash` only means something if you know which module produced it.
//! Given two servers reporting different hashes for the same message, "we
//! rendered different text" and "we ran different code" are very different
//! problems — one is a bug or an attack, the other is a version skew — and
//! without a module identity in the receipt they are indistinguishable.
//!
//! So the embedded artifact is not an anonymous blob. It carries a name, a
//! version, and the blake3 of its own bytes, and callers are expected to record
//! that alongside any hash they derive from it.
//!
//! # Where this is going
//!
//! Today [`CANONICAL_WASM`] is compiled in, which makes parity automatic for
//! servers on the same release and is the reason a fresh install needs no
//! artifact-provisioning step. That does not scale to many block types from many
//! authors across many servers, where a server must be able to say *which*
//! modules it runs and pin exact versions — a nameserver-advertised convention
//! rather than a hardcoded constant.
//!
//! The triple below ([`MODULE_NAME`], [`MODULE_VERSION`], [`module_hash`]) is
//! deliberately the shape such a convention needs, so the resolution step can
//! move behind a registry later without changing what a receipt records or what
//! a verifier compares. Treat this module as the built-in default of a future
//! resolver, not as the permanent mechanism.

/// The compiled `text-render` module.
///
/// Built from this crate for `wasm32-unknown-unknown` — **not** `wasm32-wasip1`.
/// The pure render path needs nothing from the host, and the
/// unknown-unknown target produces a module with no imports at all, so it
/// instantiates under a no-imports policy. A wasip1 build imports
/// `wasi_snapshot_preview1` and would drag a WASI surface into a block that has
/// no use for one.
///
/// Excluded when compiling this crate *to* Wasm: the module must not embed a
/// previous copy of itself.
#[cfg(not(target_arch = "wasm32"))]
pub const CANONICAL_WASM: &[u8] = include_bytes!("../artifacts/text_block.wasm");

/// Stable name for this block type. The left-hand side of a future
/// "when I say `text-block`, I mean …" mapping.
pub const MODULE_NAME: &str = "text-block";

/// Version of the module, tracking the crate version so a release bump is the
/// single place it changes.
pub const MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Name of the entry point implementing the byte-payload calling convention.
pub const ENTRY_POINT: &str = "execute";

/// blake3 of [`CANONICAL_WASM`], hex — the content address of the exact bytes
/// this build will execute.
///
/// Computed rather than hardcoded so it cannot drift from the embedded artifact.
/// A hardcoded constant would be a second source of truth, and the failure mode
/// (a hash that describes bytes you are not running) is exactly what this exists
/// to prevent.
#[cfg(not(target_arch = "wasm32"))]
pub fn module_hash() -> String {
    blake3::hash(CANONICAL_WASM).to_hex().to_string()
}

/// Fully-qualified module identifier: `text-block@<version>/blake3:<hash>`.
///
/// Carries all three parts of the identity in one string, so a receipt or a
/// federation handshake can record provenance in a single field. The version is
/// human-facing; the hash is what a verifier should actually compare, since two
/// builds of the same version can differ.
#[cfg(not(target_arch = "wasm32"))]
pub fn module_id() -> String {
    format!("{MODULE_NAME}@{MODULE_VERSION}/blake3:{}", module_hash())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_artifact_is_a_wasm_module() {
        assert!(
            CANONICAL_WASM.starts_with(b"\0asm"),
            "embedded artifact is not a Wasm module — check artifacts/text_block.wasm"
        );
        assert!(
            CANONICAL_WASM.len() > 1024,
            "embedded artifact is implausibly small ({} bytes)",
            CANONICAL_WASM.len()
        );
    }

    /// The no-imports property is what lets the host instantiate this module
    /// without granting it anything. A wasip1 rebuild would silently reintroduce
    /// `wasi_snapshot_preview1`, so assert the absence at the byte level here and
    /// again for real at instantiation time in jig-runtime's payload tests.
    #[test]
    fn the_embedded_artifact_names_no_wasi_imports() {
        let needle = b"wasi_snapshot_preview1";
        let found = CANONICAL_WASM.windows(needle.len()).any(|w| w == needle);
        assert!(
            !found,
            "embedded artifact references wasi_snapshot_preview1 — it was probably \
             rebuilt for wasm32-wasip1 instead of wasm32-unknown-unknown"
        );
    }

    #[test]
    fn module_id_carries_name_version_and_hash() {
        let id = module_id();
        assert!(id.starts_with("text-block@"), "unexpected module id: {id}");
        assert!(
            id.contains(MODULE_VERSION),
            "id must carry the version: {id}"
        );
        assert!(
            id.contains(&module_hash()),
            "id must carry the content hash: {id}"
        );
    }

    #[test]
    fn module_hash_is_stable_across_calls() {
        assert_eq!(module_hash(), module_hash());
        assert_eq!(module_hash().len(), 64, "blake3 hex is 64 chars");
    }
}
