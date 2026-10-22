//! `jig receipt view` and `jig receipt compare`: check v0.3 block receipts from files.
//!
//! A receipt is the `COSE_Sign1` envelope a server or member signs over a deterministic-CBOR
//! payload (`jig_core::block_receipt`). A file may hold the raw envelope, or its base64, as the
//! server delivers it in `receipt_bytes_b64`. Either way the receipt is opened with its
//! signature checked against the executor it names, before anything is shown.
//!
//! A signature that checks out proves only that the DID inside the receipt signed it: anyone
//! can mint a key and sign a receipt naming any block. So every receipt is shown with its
//! signer and whether this device has that DID pinned as a server (`~/.jig/pins.json`), and
//! nothing is ever called just "verified".

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jig_client::pins::Pins;
use jig_core::block_receipt::{Body, Comparison, Exec, Outcome, Role, SignedReceipt, compare};

/// Show a receipt, once its signature verifies, with its signer's standing on this device.
pub fn view_receipt(path: &str, json_output: bool, pins: &Path) -> Result<()> {
    let signed = load(path)?;
    let pins = Pins::load(pins)?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&to_json(&signed, &pins))?
        );
    } else {
        print!("{}", pretty(&signed, &pins));
    }
    Ok(())
}

/// Compare two `exec` receipts on what executors must agree on: component, world, invocation
/// and outcome. Says which of them differ and whether each signer is a pinned server. A
/// divergence is an error, so a script can tell.
pub fn compare_receipts(path_a: &str, path_b: &str, pins: &Path) -> Result<()> {
    let (a, b) = (load(path_a)?, load(path_b)?);
    let pins = Pins::load(pins)?;
    print!("{}", comparison(&a, path_a, &b, path_b, &pins)?);
    let (ea, eb) = (exec(&a, path_a)?, exec(&b, path_b)?);
    if compare(&ea, &eb) == Comparison::Diverge {
        anyhow::bail!("the receipts diverge: one of their executors is wrong");
    }
    Ok(())
}

/// The comparison of two exec receipts, as printed.
fn comparison(
    a: &SignedReceipt,
    path_a: &str,
    b: &SignedReceipt,
    path_b: &str,
    pins: &Pins,
) -> Result<String> {
    let (ea, eb) = (exec(a, path_a)?, exec(b, path_b)?);
    let mut out = format!(
        "A: {path_a}\n   {}\nB: {path_b}\n   {}\n",
        signer(&a.receipt.executor, pins),
        signer(&b.receipt.executor, pins),
    );
    let field = |name: &str, same: bool, shown: String| {
        if same {
            format!("  {name:<11} same: {shown}\n")
        } else {
            format!("  {name:<11} DIFFERS\n")
        }
    };
    out.push_str(&field(
        "block",
        a.receipt.block_cid == b.receipt.block_cid,
        a.receipt.block_cid.to_string(),
    ));
    out.push_str(&field(
        "component",
        ea.component == eb.component,
        hex(&ea.component),
    ));
    out.push_str(&field("world", ea.world == eb.world, ea.world.clone()));
    out.push_str(&field(
        "invocation",
        ea.invocation_hash == eb.invocation_hash,
        hex(&ea.invocation_hash),
    ));
    out.push_str(&field(
        "outcome",
        ea.outcome == eb.outcome,
        outcome(&ea.outcome),
    ));
    if ea.outcome != eb.outcome {
        out.push_str(&format!(
            "    A: {}\n    B: {}\n",
            outcome(&ea.outcome),
            outcome(&eb.outcome)
        ));
    }
    out.push_str(match compare(&ea, &eb) {
        Comparison::Agree => "verdict: agree\n",
        Comparison::NotComparable => "verdict: not comparable: an incomplete run asserts nothing\n",
        Comparison::DifferentRuns => {
            "verdict: different runs: the component, world or invocation differs, so the \
             outcomes are not evidence about the same run\n"
        }
        Comparison::Diverge => "verdict: DIVERGE: the same run reached different outcomes\n",
    });
    Ok(out)
}

/// The exec payload of `s`, or why it has none.
fn exec(s: &SignedReceipt, path: &str) -> Result<Exec> {
    match &s.receipt.body {
        Body::Exec(exec) => Ok((**exec).clone()),
        body => anyhow::bail!(
            "{path} is a {} receipt; only exec receipts carry an outcome to compare",
            kind(body)
        ),
    }
}

/// Read `path` and open the receipt in it: the raw envelope, or its base64.
fn load(path: &str) -> Result<SignedReceipt> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    let envelope = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| STANDARD.decode(text.trim()).ok())
        .unwrap_or(bytes);
    SignedReceipt::open(&envelope).with_context(|| {
        format!("{path} is not a v0.3 receipt whose signature verifies against its executor")
    })
}

/// Who signed, and whether this device knows that DID as a server.
fn signer(did: &str, pins: &Pins) -> String {
    let servers = pins.servers_pinned_to(did);
    if servers.is_empty() {
        format!("valid signature by {did}, NOT a pinned server")
    } else {
        format!(
            "valid, signed by {did} (pinned server {})",
            servers.join(", ")
        )
    }
}

fn kind(body: &Body) -> &'static str {
    match body {
        Body::Exec(_) => "exec",
        Body::Sealed => "sealed",
        Body::Accepted => "accepted",
    }
}

fn role(role: Role) -> &'static str {
    match role {
        Role::Server => "server",
        Role::Member => "member",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn outcome(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Ok { hash } => format!("ok {}", hex(hash)),
        Outcome::Error { trap: None, hash } => format!("error {}", hex(hash)),
        Outcome::Error {
            trap: Some(trap),
            hash,
        } => format!("trap {trap} {}", hex(hash)),
        Outcome::Incomplete { reason } => format!("incomplete ({reason})"),
    }
}

fn pretty(signed: &SignedReceipt, pins: &Pins) -> String {
    let r = &signed.receipt;
    let mut out = format!(
        "Receipt {}\n  {}\n  kind:       {}\n  block:      {}\n  role:       {}\n  \
         produced:   {}\n",
        signed.cid(),
        signer(&r.executor, pins),
        kind(&r.body),
        r.block_cid,
        role(r.role),
        r.produced_at,
    );
    if let Body::Exec(exec) = &r.body {
        out.push_str(&pretty_exec(exec));
    }
    out
}

fn pretty_exec(e: &Exec) -> String {
    let mut out = format!(
        "  outcome:    {}\n  component:  {}\n  program:    {}\n  world:      {}\n  \
         invocation: {}\n  limits:     fuel {}, memory {} pages, stack {}, timeout {} ms\n  \
         engine:     {} {} ({}), fuel used {}\n",
        outcome(&e.outcome),
        hex(&e.component),
        e.program,
        e.world,
        hex(&e.invocation_hash),
        e.limits.fuel,
        e.limits.memory_max_pages,
        e.limits.max_wasm_stack,
        e.limits.timeout_ms,
        e.engine.name,
        e.engine.version,
        e.engine.profile,
        e.engine.fuel_used,
    );
    if let Some(policy) = &e.operator_policy_cid {
        out.push_str(&format!("  policy:     {policy}\n"));
    }
    out
}

fn to_json(signed: &SignedReceipt, pins: &Pins) -> serde_json::Value {
    let r = &signed.receipt;
    let mut v = serde_json::json!({
        "cid": signed.cid().to_string(),
        "signature_valid": true,
        "signer": r.executor,
        "signer_pinned_servers": pins.servers_pinned_to(&r.executor),
        "kind": kind(&r.body),
        "block_cid": r.block_cid.to_string(),
        "role": role(r.role),
        "produced_at": r.produced_at,
    });
    if let Body::Exec(e) = &r.body {
        v["exec"] = serde_json::json!({
            "outcome": outcome(&e.outcome),
            "component": hex(&e.component),
            "program": e.program.to_string(),
            "world": e.world,
            "invocation_hash": hex(&e.invocation_hash),
            "operator_policy_cid": e.operator_policy_cid.map(|c| c.to_string()),
            "limits": {
                "fuel": e.limits.fuel,
                "max_wasm_stack": e.limits.max_wasm_stack,
                "memory_max_pages": e.limits.memory_max_pages,
                "timeout_ms": e.limits.timeout_ms,
            },
            "engine": {
                "name": e.engine.name,
                "version": e.engine.version,
                "profile": e.engine.profile,
                "config_fingerprint": e.engine.config_fingerprint,
                "fuel_used": e.engine.fuel_used,
            },
        });
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use jig_core::block_receipt::{Engine, Limits, Receipt};
    use jig_core::canonical_cid;
    use std::io::Write;

    fn did_of(key: &SigningKey) -> String {
        jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    fn exec_body(component: u8, outcome: Outcome) -> Body {
        Body::Exec(Box::new(Exec {
            component: [component; 32],
            program: canonical_cid::of(b"program"),
            world: "jig:block/renderer@0.1.0".into(),
            invocation_hash: [2; 32],
            operator_policy_cid: Some(canonical_cid::of(b"policy")),
            outcome,
            limits: Limits {
                fuel: 1_000_000,
                max_wasm_stack: 1 << 20,
                memory_max_pages: 16,
                timeout_ms: 250,
            },
            engine: Engine {
                name: "wasmtime".into(),
                version: "49".into(),
                profile: "jig-det-1".into(),
                config_fingerprint: "f".into(),
                fuel_used: 1234,
            },
        }))
    }

    fn ok(hash: u8) -> Body {
        exec_body(1, Outcome::Ok { hash: [hash; 32] })
    }

    fn signed(key: &SigningKey, body: Body) -> SignedReceipt {
        SignedReceipt::sign(
            Receipt {
                block_cid: canonical_cid::of(b"block"),
                executor: did_of(key),
                role: Role::Server,
                produced_at: 1_800_000_000,
                body,
            },
            key,
        )
        .unwrap()
    }

    fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f
    }

    fn path(f: &tempfile::NamedTempFile) -> &str {
        f.path().to_str().unwrap()
    }

    /// A pin store in `dir` with `server` pinned to `key`'s DID.
    fn pins_with(dir: &Path, server: &str, key: &SigningKey) -> Pins {
        let mut pins = Pins::load(&dir.join("pins.json")).unwrap();
        pins.check_server_did(server, &did_of(key)).unwrap();
        pins
    }

    #[test]
    fn a_receipt_from_a_pinned_server_names_it() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let pins = pins_with(dir.path(), "https://jig.example", &key);
        let receipt = signed(&key, ok(3));
        for f in [
            file(&receipt.envelope),
            file(format!("{}\n", STANDARD.encode(&receipt.envelope)).as_bytes()),
        ] {
            let loaded = load(path(&f)).unwrap();
            assert_eq!(loaded, receipt);
            let text = pretty(&loaded, &pins);
            assert!(
                text.contains(&format!(
                    "valid, signed by {} (pinned server jig.example)",
                    did_of(&key)
                )),
                "{text}"
            );
            assert!(text.contains(&format!("ok {}", hex(&[3; 32]))), "{text}");
            assert!(
                !text.contains("verified"),
                "never a bare 'verified': {text}"
            );
            let json = to_json(&loaded, &pins);
            assert_eq!(json["signer_pinned_servers"][0], "jig.example");
            assert_eq!(json["exec"]["engine"]["fuel_used"], 1234);
        }
    }

    #[test]
    fn a_receipt_signed_by_an_unpinned_key_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let pinned = SigningKey::from_bytes(&[7; 32]);
        let pins = pins_with(dir.path(), "https://jig.example", &pinned);
        // Anyone can mint a key and sign a receipt that names any block.
        let stranger = SigningKey::from_bytes(&[9; 32]);
        let loaded = load(path(&file(&signed(&stranger, ok(3)).envelope))).unwrap();
        let text = pretty(&loaded, &pins);
        assert!(
            text.contains(&format!(
                "valid signature by {}, NOT a pinned server",
                did_of(&stranger)
            )),
            "{text}"
        );
        assert!(
            to_json(&loaded, &pins)["signer_pinned_servers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_tampered_receipt_is_refused() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut envelope = signed(&key, Body::Accepted).envelope;
        let last = envelope.len() - 1;
        envelope[last] ^= 1;
        let err = load(path(&file(&envelope))).unwrap_err();
        assert!(
            format!("{err:#}").contains("signature verifies against its executor"),
            "{err:#}"
        );
        assert!(load(path(&file(b"{\"not\": \"a receipt\"}"))).is_err());
    }

    #[test]
    fn compare_names_the_fields_that_differ_and_each_signers_pin() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (
            SigningKey::from_bytes(&[7; 32]),
            SigningKey::from_bytes(&[8; 32]),
        );
        let pins = pins_with(dir.path(), "https://a.example", &a);
        let ra = signed(&a, ok(3));

        let same = comparison(&ra, "a", &signed(&b, ok(3)), "b", &pins).unwrap();
        assert!(same.contains("verdict: agree"), "{same}");
        assert!(same.contains("(pinned server a.example)"), "{same}");
        assert!(same.contains("NOT a pinned server"), "{same}");

        let diverged = comparison(&ra, "a", &signed(&b, ok(4)), "b", &pins).unwrap();
        assert!(diverged.contains("outcome     DIFFERS"), "{diverged}");
        assert!(diverged.contains("component   same"), "{diverged}");
        assert!(diverged.contains("verdict: DIVERGE"), "{diverged}");

        let other = signed(&b, exec_body(5, Outcome::Ok { hash: [3; 32] }));
        let different = comparison(&ra, "a", &other, "b", &pins).unwrap();
        assert!(different.contains("component   DIFFERS"), "{different}");
        assert!(different.contains("verdict: different runs"), "{different}");

        let incomplete = signed(
            &b,
            exec_body(
                1,
                Outcome::Incomplete {
                    reason: "fuel-exhausted".into(),
                },
            ),
        );
        let skipped = comparison(&ra, "a", &incomplete, "b", &pins).unwrap();
        assert!(skipped.contains("verdict: not comparable"), "{skipped}");

        let err = comparison(&ra, "a", &signed(&b, Body::Accepted), "b", &pins).unwrap_err();
        assert!(err.to_string().contains("only exec receipts"), "{err}");
    }

    #[test]
    fn compare_exits_non_zero_on_a_divergence() {
        let dir = tempfile::tempdir().unwrap();
        let pins = dir.path().join("pins.json");
        let (a, b) = (
            SigningKey::from_bytes(&[7; 32]),
            SigningKey::from_bytes(&[8; 32]),
        );
        let fa = file(&signed(&a, ok(3)).envelope);
        compare_receipts(path(&fa), path(&file(&signed(&b, ok(3)).envelope)), &pins)
            .expect("agreeing receipts");
        let err = compare_receipts(path(&fa), path(&file(&signed(&b, ok(4)).envelope)), &pins)
            .unwrap_err();
        assert!(err.to_string().contains("diverge"), "{err}");
    }
}
