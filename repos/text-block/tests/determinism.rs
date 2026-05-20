use text_block::*;

fn sample_input() -> Input {
    Input {
        sender_did: "did:jig:zabc".to_string(),
        channel_id: "ch_hello".to_string(),
        body_raw: "hi @deji! check https://jig.onl".to_string(),
        hlc_wall_ms: 1747680000000,
        hlc_logical: 0,
        hlc_origin: "did:jig:zorigin".to_string(),
        client_version: "jig-cli/0.0.2".to_string(),
    }
}

#[test]
fn execute_is_deterministic_across_100_runs() {
    let input = sample_input();
    let first = execute_pure(&input);
    for _ in 0..100 {
        assert_eq!(execute_pure(&input), first);
    }
}

#[test]
fn render_hash_is_blake3_of_canonical_text() {
    let input = sample_input();
    let out = execute_pure(&input);
    let expected = blake3::hash(out.canonical_text.as_bytes())
        .to_hex()
        .to_string();
    assert_eq!(out.render_hash, expected);
}

#[test]
fn unicode_normalization_is_nfkc() {
    let mut input = sample_input();
    input.body_raw = "café".to_string(); // composed
    let out_composed = execute_pure(&input);
    input.body_raw = "cafe\u{0301}".to_string(); // decomposed
    let out_decomposed = execute_pure(&input);
    assert_eq!(out_composed.canonical_text, out_decomposed.canonical_text);
    assert_eq!(out_composed.render_hash, out_decomposed.render_hash);
}

#[test]
fn extracts_mentions() {
    let input = Input {
        body_raw: "hi @deji and @brian".to_string(),
        ..sample_input()
    };
    let out = execute_pure(&input);
    assert_eq!(out.mentions.len(), 2);
    assert_eq!(out.mentions[0].handle_raw, "@deji");
    assert_eq!(out.mentions[1].handle_raw, "@brian");
}

#[test]
fn extracts_links() {
    let input = Input {
        body_raw: "https://jig.onl and http://example.com/x".to_string(),
        ..sample_input()
    };
    let out = execute_pure(&input);
    assert_eq!(out.links.len(), 2);
    assert!(out.links[0].url.starts_with("https://"));
}

#[test]
fn render_html_escapes_safely() {
    let input = Input {
        body_raw: "<script>alert(1)</script>".to_string(),
        ..sample_input()
    };
    let out = execute_pure(&input);
    assert!(!out.render_html.contains("<script"));
    assert!(out.render_html.contains("&lt;script"));
}

#[test]
fn length_bytes_is_utf8_byte_count() {
    let input = Input {
        body_raw: "café".to_string(),
        ..sample_input()
    };
    let out = execute_pure(&input);
    assert_eq!(out.length_bytes, 5); // "café" NFKC = 5 UTF-8 bytes
}

#[test]
fn over_4kib_input_warns_truncated() {
    let big = "x".repeat(5000);
    let input = Input {
        body_raw: big,
        ..sample_input()
    };
    let out = execute_pure(&input);
    assert!(out.warnings.contains(&"truncated".to_string()));
    assert_eq!(out.length_bytes, 4096);
}
