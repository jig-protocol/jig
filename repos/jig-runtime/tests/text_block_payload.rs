//! Executes the real `text-block` Wasm module through the byte-payload
//! convention.
//!
//! Every existing text-block test calls `execute_pure` — the native Rust
//! function — so until now nothing in the repo had ever run the compiled module.
//! That mattered: the native path and the Wasm path could disagree (a
//! target-dependent `usize`, a differing allocator, a serde feature that behaves
//! differently under `wasm32`) and no test would notice.
//!
//! The assertion that carries the most weight here is
//! `wasm_and_native_agree_on_render_hash`: it pins the two implementations
//! together, which is what makes the native function a legitimate oracle for the
//! Wasm one.

use jig_runtime::Runtime;
use text_block::{Input, Output, canonical, execute_pure};

/// Which module bytes to exercise.
///
/// Defaults to the committed artifact. CI also runs this whole suite with
/// `JIG_TEXT_BLOCK_WASM` pointing at a freshly-built module, which is how the
/// committed artifact is held to the source without requiring bit-identical
/// builds — Wasm output here is not reproducible across hosts (an identical tree
/// differs by ~1.4 KB between aarch64 macOS and CI's x86_64 Linux, and
/// `--remap-path-prefix` does not close it).
///
/// Both runs assert agreement with `execute_pure`, so the native function is the
/// shared oracle: if the committed artifact and a fresh build both match it,
/// they are functionally equivalent on this corpus.
fn module_bytes() -> std::borrow::Cow<'static, [u8]> {
    let Some(raw) = std::env::var_os("JIG_TEXT_BLOCK_WASM") else {
        return std::borrow::Cow::Borrowed(canonical::CANONICAL_WASM);
    };

    // A relative path is resolved against the WORKSPACE root, not the process
    // cwd: cargo runs a test binary with cwd set to the package directory
    // (repos/jig-runtime), so a sensible-looking `target/…` would otherwise miss.
    let path = std::path::PathBuf::from(&raw);
    let resolved = if path.is_relative() {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("package dir has a parent")
            .join(&path)
    } else {
        path
    };

    let bytes = std::fs::read(&resolved).unwrap_or_else(|e| {
        panic!("JIG_TEXT_BLOCK_WASM={raw:?} (resolved to {resolved:?}) could not be read: {e}")
    });
    std::borrow::Cow::Owned(bytes)
}

fn input_with_body(body: &str) -> Input {
    Input {
        sender_did: "did:jig:zabc".to_string(),
        channel_id: "#hello".to_string(),
        body_raw: body.to_string(),
        hlc_wall_ms: 1_747_680_000_000,
        hlc_logical: 0,
        hlc_origin: "did:jig:zorigin".to_string(),
        client_version: "jig-cli/0.0.2".to_string(),
    }
}

/// Run the canonical module against `body` and decode its output.
fn run_wasm(body: &str) -> Output {
    let runtime = Runtime::new().expect("runtime construction");
    let input = postcard::to_allocvec(&input_with_body(body)).expect("input encodes");
    let result = runtime
        .execute_payload(&module_bytes(), canonical::ENTRY_POINT, &input)
        .expect("canonical text-block module must execute");
    postcard::from_bytes(&result.bytes).expect("guest output decodes as Output")
}

/// The headline property: the compiled module produces the same `render_hash`
/// as the native function. Without this, using `execute_pure` as an oracle
/// anywhere else is an assumption rather than a fact.
#[test]
fn wasm_and_native_agree_on_render_hash() {
    // The corpus must exercise every branch of `render_safe_html`, or a real
    // render change slips through. An earlier version of this list had no
    // apostrophe in any body, so swapping `&#39;` for `&apos;` in the escaper
    // left all of these green — a change to the rendered output that the gate
    // could not see. Every escaped character now appears at least once.
    for body in [
        "hello world",
        "hi @deji! check https://jig.onl",
        "", // empty body — still a valid render
        "unicode: café ﬁ ½ 🎻",
        "<script>alert(1)</script> & \"quotes\"",
        "it's a 'quoted' apostrophe test",
        "all five at once: < > & \" '",
    ] {
        let from_wasm = run_wasm(body);
        let from_native = execute_pure(&input_with_body(body));
        assert_eq!(
            from_wasm.render_hash, from_native.render_hash,
            "render_hash diverged between Wasm and native for body {body:?}"
        );
        assert_eq!(
            from_wasm, from_native,
            "full Output diverged between Wasm and native for body {body:?}"
        );
    }
}

/// Issue #5's acceptance criterion: mutating the body must change the hash.
/// This is the property a module-bytes hash would silently fail.
#[test]
fn a_different_body_produces_a_different_render_hash() {
    let a = run_wasm("first real message on the VPS");
    let b = run_wasm("first real message on the VPS.");
    assert_ne!(
        a.render_hash, b.render_hash,
        "a one-character change must change render_hash"
    );
}

/// The other half of that criterion: identical input is identical output, which
/// is what makes cross-server parity meaningful.
#[test]
fn the_same_body_produces_the_same_render_hash_across_runs() {
    let first = run_wasm("deterministic?");
    for _ in 0..5 {
        assert_eq!(run_wasm("deterministic?").render_hash, first.render_hash);
    }
}

/// `render_hash` is documented as blake3 of `canonical_text`. Verify against an
/// independent computation rather than trusting the guest's own claim.
#[test]
fn render_hash_is_blake3_of_the_canonical_text() {
    let out = run_wasm("hi @deji! check https://jig.onl");
    let expected = blake3::hash(out.canonical_text.as_bytes())
        .to_hex()
        .to_string();
    assert_eq!(out.render_hash, expected);
}

/// The retry path: a body large enough that the guest's encoded output exceeds
/// the host's first-attempt buffer, forcing the `RC_OUTPUT_TOO_SMALL` round trip.
///
/// `render_html` escapes every `<` to `&lt;` (4x), so a body of many `<`
/// characters inflates the output well past the initial 16 KiB guess while
/// staying under text-block's 4 KiB input cap.
#[test]
fn a_large_output_survives_the_grow_and_retry_path() {
    let body = "<".repeat(4000);
    let out = run_wasm(&body);
    let native = execute_pure(&input_with_body(&body));
    assert_eq!(
        out.render_hash, native.render_hash,
        "the retry path must not corrupt the result"
    );

    // Assert on the ENCODED size, since that is what has to fit in the host's
    // buffer — `render_html.len()` alone is 16_000 here and would sit just under
    // the 16 KiB first attempt, making the test pass without exercising a retry.
    //
    // Reaching this line at all is the real evidence: a first attempt that does
    // not fit returns RC_OUTPUT_TOO_SMALL, which `execute_payload` surfaces as an
    // error unless it successfully grows and re-runs. A correct hash on an
    // over-sized output means the grow-and-retry round trip worked.
    let encoded = postcard::to_allocvec(&out).expect("output re-encodes");
    assert!(
        encoded.len() > 16 * 1024,
        "test no longer exercises the retry path: encoded output is {} bytes, \
         within the first-attempt buffer",
        encoded.len()
    );
    // 4000 bytes is under the 4 KiB cap, so nothing should be truncated.
    assert!(
        !out.warnings.iter().any(|w| w == "truncated"),
        "unexpected truncation: {:?}",
        out.warnings
    );
}

/// Execution reports which module ran. This is what makes a hash mismatch
/// attributable — "different code" vs "different text" — and it must match the
/// artifact's own declared identity.
#[test]
fn execution_reports_the_canonical_module_hash() {
    let runtime = Runtime::new().expect("runtime construction");
    let input = postcard::to_allocvec(&input_with_body("hi")).unwrap();
    let result = runtime
        .execute_payload(&module_bytes(), canonical::ENTRY_POINT, &input)
        .expect("execution");
    let expected = blake3::hash(&module_bytes()).to_hex().to_string();
    assert_eq!(
        result.module_hash, expected,
        "reported module hash must match the bytes that were executed"
    );
    if std::env::var_os("JIG_TEXT_BLOCK_WASM").is_none() {
        // Default run: the executed bytes ARE the embedded artifact, so the
        // identity helper must agree too.
        assert_eq!(
            result.module_hash,
            canonical::module_hash(),
            "committed artifact's declared identity must match its own bytes"
        );
    }
}

/// Malformed input must surface as a clean error, not a trap or a silent
/// success. text-block returns code 1 for input it cannot decode.
#[test]
fn malformed_input_is_reported_as_an_error() {
    let runtime = Runtime::new().expect("runtime construction");
    let err = runtime
        .execute_payload(
            &module_bytes(),
            canonical::ENTRY_POINT,
            b"\xff\xff not a valid Input encoding",
        )
        .expect_err("unparseable input must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("returned 1"),
        "error should report the guest's return code, got: {msg}"
    );
}

/// A missing entry point is a clear error naming the export, not a panic.
#[test]
fn a_missing_entry_point_names_the_export() {
    let runtime = Runtime::new().expect("runtime construction");
    let input = postcard::to_allocvec(&input_with_body("hi")).unwrap();
    let err = runtime
        .execute_payload(&module_bytes(), "no_such_export", &input)
        .expect_err("a missing export must fail");
    assert!(
        err.to_string().contains("no_such_export"),
        "error should name the missing export, got: {err}"
    );
}
