//! Canonical text-render Wasm block for jig-protocol v0.0.2.
//!
//! Pure, deterministic, zero capability requests. The Phase B ingest
//! pipeline (jig-pipeline) executes one of these per submitted chat
//! message, hashes the output as `render_hash`, and uses that hash as
//! the federation-side parity check.

pub mod canonical;

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

const MAX_BODY_BYTES: usize = 4096;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Input {
    pub sender_did: String,
    pub channel_id: String,
    pub body_raw: String,
    pub hlc_wall_ms: u64,
    pub hlc_logical: u32,
    pub hlc_origin: String,
    pub client_version: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Output {
    pub canonical_text: String,
    pub render_html: String,
    pub mentions: Vec<Mention>,
    pub links: Vec<Link>,
    pub length_bytes: u32,
    pub render_hash: String, // hex blake3 of canonical_text
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Mention {
    pub handle_raw: String,
    pub byte_offset: u32,
    pub byte_len: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Link {
    pub url: String,
    pub byte_offset: u32,
    pub byte_len: u32,
}

/// Pure Rust entry point used by both:
/// - the host (jig-pipeline) when executing this block in-process for tests
/// - the Wasm `execute` extern when running under wasmtime
pub fn execute_pure(input: &Input) -> Output {
    let mut warnings = vec![];

    // 1. NFKC-normalize body
    let nfkc: String = input.body_raw.nfkc().collect();

    // 2. Truncate at 4 KiB on a UTF-8 char boundary
    let (canonical_text, truncated) = if nfkc.len() > MAX_BODY_BYTES {
        let safe_end = (0..=MAX_BODY_BYTES)
            .rev()
            .find(|&i| nfkc.is_char_boundary(i))
            .unwrap_or(0);
        (nfkc[..safe_end].to_string(), true)
    } else {
        (nfkc, false)
    };
    if truncated {
        warnings.push("truncated".to_string());
    }

    // 3. Extract mentions, links
    let mentions = extract_mentions(&canonical_text);
    let links = extract_links(&canonical_text);

    // 4. Safe-subset HTML render
    let render_html = render_safe_html(&canonical_text);

    // 5. Length + hash
    let length_bytes = canonical_text.len() as u32;
    let render_hash = blake3::hash(canonical_text.as_bytes()).to_hex().to_string();

    Output {
        canonical_text,
        render_html,
        mentions,
        links,
        length_bytes,
        render_hash,
        warnings,
    }
}

fn extract_mentions(text: &str) -> Vec<Mention> {
    let mut out = vec![];
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'-')
            {
                i += 1;
            }
            if i - start > 1 {
                out.push(Mention {
                    handle_raw: text[start..i].to_string(),
                    byte_offset: start as u32,
                    byte_len: (i - start) as u32,
                });
            }
        } else {
            i += 1;
        }
    }
    out
}

fn extract_links(text: &str) -> Vec<Link> {
    let mut out = vec![];
    for prefix in &["https://", "http://"] {
        let mut start_search = 0;
        while let Some(pos) = text[start_search..].find(prefix) {
            let absolute = start_search + pos;
            let end_rel = text[absolute..]
                .find(char::is_whitespace)
                .unwrap_or(text.len() - absolute);
            out.push(Link {
                url: text[absolute..absolute + end_rel].to_string(),
                byte_offset: absolute as u32,
                byte_len: end_rel as u32,
            });
            start_search = absolute + end_rel;
        }
    }
    out.sort_by_key(|l| l.byte_offset);
    out
}

fn render_safe_html(text: &str) -> String {
    let mut html = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '<' => html.push_str("&lt;"),
            '>' => html.push_str("&gt;"),
            '&' => html.push_str("&amp;"),
            '"' => html.push_str("&quot;"),
            '\'' => html.push_str("&#39;"),
            c => html.push(c),
        }
    }
    html
}

/// Guest-side allocator exports.
///
/// [`execute`] documents that the caller owns the input and output buffers, but
/// a host cannot honour that without a way to obtain an address inside this
/// module's linear memory. Picking a raw address and hoping it is unused is
/// unsound — it can land on the shadow stack or on live allocator state. These
/// two exports are the supported way in.
///
/// Deliberately named `jig_alloc`/`jig_dealloc` rather than `alloc`/`free`, so
/// they cannot be confused with (or shadowed by) the WASI libc symbols that
/// `wasm32-wasip1` links in.
///
/// Every pointer returned here must be released with [`jig_dealloc`] using the
/// SAME length that was passed to [`jig_alloc`]: the allocation is made with an
/// explicit `Layout`, so a mismatched size is undefined behaviour rather than a
/// tolerated leak.
mod abi {
    use std::alloc::{Layout, alloc, dealloc};

    /// Reserve `len` bytes and hand the host the address. Returns null on a
    /// zero length or an invalid layout, which the host must treat as failure.
    #[unsafe(no_mangle)]
    pub extern "C" fn jig_alloc(len: usize) -> *mut u8 {
        if len == 0 {
            return std::ptr::null_mut();
        }
        // Align 1: these are opaque byte buffers (JSON), never typed values.
        match Layout::from_size_align(len, 1) {
            // SAFETY: layout has non-zero size, checked above.
            Ok(layout) => unsafe { alloc(layout) },
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// Release a buffer from [`jig_alloc`].
    ///
    /// # Safety
    ///
    /// `ptr` must have come from `jig_alloc(len)` with the same `len`, and must
    /// not have been freed already.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn jig_dealloc(ptr: *mut u8, len: usize) {
        if ptr.is_null() || len == 0 {
            return;
        }
        if let Ok(layout) = Layout::from_size_align(len, 1) {
            // SAFETY: caller guarantees ptr came from jig_alloc with this len.
            unsafe { dealloc(ptr, layout) };
        }
    }
}

/// Wasm entry point.
///
/// Reads serialized [`Input`] JSON from `input_ptr/input_len`, writes
/// serialized [`Output`] JSON to `out_ptr/out_len`. Returns 0 on success,
/// nonzero on failure. The host caller is responsible for the memory layout;
/// see [`abi`] for the allocator exports that make that possible.
///
/// Return codes are part of the ABI contract, not just diagnostics:
/// `0` success, `1` input did not decode as an `Input`, `2` output failed to
/// encode, `3` the output buffer was too small — in which case `*out_len_ptr`
/// is overwritten with the REQUIRED length so the host can retry with a
/// correctly sized buffer.
///
/// This is a thin wrapper around [`execute_pure`]; pure-Rust unit tests
/// exercise `execute_pure` directly, and the Wasm runtime exercises this
/// function from inside the sandbox.
///
/// # Encoding
///
/// postcard, not JSON. `serde_json`'s number parser links f64 code into any
/// module that uses it, and jig-core's determinism validator rejects modules
/// containing float instructions — so a JSON ABI made this module unrunnable
/// despite [`Input`] and [`Output`] holding no floats. postcard keeps the same
/// derive-based ergonomics and emits none.
///
/// This choice cannot move any `render_hash`: the hash is taken over
/// `canonical_text`, not over the encoded bytes.
///
/// # Safety
///
/// - `input_ptr` must point to `input_len` readable bytes (a postcard-encoded `Input`).
/// - `out_ptr` must point to a buffer of at least `*out_len_ptr` bytes.
/// - `out_len_ptr` must be a valid mutable pointer to a `usize`.
/// - All pointers must remain valid for the duration of this call.
/// - Caller is responsible for allocating and freeing the output buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execute(
    input_ptr: *const u8,
    input_len: usize,
    out_ptr: *mut u8,
    out_len_ptr: *mut usize,
) -> i32 {
    // SAFETY: caller guarantees input_ptr..input_ptr+input_len is valid for reads
    let input_slice = unsafe { std::slice::from_raw_parts(input_ptr, input_len) };
    let input: Input = match postcard::from_bytes(input_slice) {
        Ok(i) => i,
        Err(_) => return 1,
    };
    let output = execute_pure(&input);
    let bytes = match postcard::to_allocvec(&output) {
        Ok(b) => b,
        Err(_) => return 2,
    };
    // SAFETY: caller guarantees out_len_ptr is a valid mutable usize pointer
    let cap = unsafe { *out_len_ptr };
    if bytes.len() > cap {
        // SAFETY: same as above
        unsafe { *out_len_ptr = bytes.len() };
        return 3;
    }
    // SAFETY: caller guarantees out_ptr points to a buffer of at least cap bytes
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, bytes.len());
        *out_len_ptr = bytes.len();
    }
    0
}
