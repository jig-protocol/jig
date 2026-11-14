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
//! Today [`CANONICAL_COMPONENT`] is compiled in, which makes parity automatic for
//! servers on the same release and is the reason a fresh install needs no
//! artifact-provisioning step. That does not scale to many block types from many
//! authors across many servers, where a server must be able to say *which*
//! modules it runs and pin exact versions — a nameserver-advertised convention
//! rather than a hardcoded constant.
//!
//! The triple below ([`MODULE_NAME`], [`MODULE_VERSION`], and the blake3 in [`component_id`]) is
//! deliberately the shape such a convention needs, so the resolution step can
//! move behind a registry later without changing what a receipt records or what
//! a verifier compares. Treat this module as the built-in default of a future
//! resolver, not as the permanent mechanism.

/// Stable name for this block type. The left-hand side of a future
/// "when I say `text-block`, I mean …" mapping.
pub const MODULE_NAME: &str = "text-block";

/// Version of the module, tracking the crate version so a release bump is the
/// single place it changes.
pub const MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The `text-render` block as a `jig:block/renderer@0.1.0` component (JEP-0006), built by
/// `build-artifact.sh` from this crate with `--features component`.
///
/// Excluded when compiling this crate *to* Wasm: the component must not embed a previous copy
/// of itself.
#[cfg(not(target_arch = "wasm32"))]
pub const CANONICAL_COMPONENT: &[u8] = include_bytes!("../artifacts/text_block.component.wasm");

/// A build of this component other than [`CANONICAL_COMPONENT`], with the BLAKE3 hash it is
/// pinned to.
#[derive(Debug, Clone, Copy)]
pub struct KnownBuild {
    /// `blake3:<hex>`, as a receipt's component hash names it.
    pub blake3: &'static str,
    pub bytes: &'static [u8],
}

/// Builds a client may also verify against, besides [`CANONICAL_COMPONENT`]. Servers never
/// render with these.
///
/// A text-block change that alters render output ships in two steps. In release N the next
/// build is listed here, so clients can verify a server that has moved to it, while servers
/// keep rendering with the canonical one. In N+1 servers switch, and the previous canonical
/// build may stay here for servers that have not. A build here cannot be rebuilt from this
/// tree, whose crate matches the canonical build. It is pinned by its hash (checked below) and
/// by its block-ABI vectors' outcome hashes (`jig-spec/vectors/block-abi`).
#[cfg(not(target_arch = "wasm32"))]
pub const OTHER_BUILDS: &[KnownBuild] = &[KnownBuild {
    // unicode-normalization 0.1.26 (Unicode 18), wit-bindgen 0.57.
    blake3: "blake3:99593614ee82449902364ae342cc9d4d671e39c9da0c2d236394908e3c351fb8",
    bytes: include_bytes!("../artifacts/text_block.next.component.wasm"),
}];

/// Media type of the component's output body: the postcard-encoded [`crate::Output`].
pub const COMPONENT_OUTPUT_MEDIA_TYPE: &str = "application/x.jig-text-render+postcard";

/// `text-block@<version>/blake3:<hash>` for [`CANONICAL_COMPONENT`].
#[cfg(not(target_arch = "wasm32"))]
pub fn component_id() -> String {
    format!(
        "{MODULE_NAME}@{MODULE_VERSION}/blake3:{}",
        blake3::hash(CANONICAL_COMPONENT).to_hex()
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_artifact_is_a_wasm_component() {
        // A component's preamble is `\0asm` followed by version 0x0d and layer 0x01; a core
        // module has version 1 and layer 0.
        assert!(
            CANONICAL_COMPONENT.starts_with(b"\0asm\x0d\0\x01\0"),
            "embedded artifact is not a Wasm component — check artifacts/text_block.component.wasm"
        );
    }

    /// Each other build is exactly the bytes it is pinned to, is a component, and is not the
    /// canonical build.
    #[test]
    fn other_builds_match_their_pinned_hashes() {
        let canonical = format!("blake3:{}", blake3::hash(CANONICAL_COMPONENT).to_hex());
        for build in OTHER_BUILDS {
            assert_eq!(
                format!("blake3:{}", blake3::hash(build.bytes).to_hex()),
                build.blake3,
                "an other build's bytes moved"
            );
            assert!(build.bytes.starts_with(b"\0asm\x0d\0\x01\0"));
            assert_ne!(build.blake3, canonical);
        }
    }

    #[test]
    fn component_id_carries_name_version_and_hash() {
        let id = component_id();
        let hash = blake3::hash(CANONICAL_COMPONENT).to_hex().to_string();
        assert_eq!(id, format!("{MODULE_NAME}@{MODULE_VERSION}/blake3:{hash}"));
    }
}
