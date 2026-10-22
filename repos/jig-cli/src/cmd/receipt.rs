//! `jig receipt view` and `jig receipt compare`: verify v0.3 block receipts from files.
//!
//! A receipt is the `COSE_Sign1` envelope a server or member signs over a deterministic-CBOR
//! payload (`jig_core::block_receipt`). A file may hold the raw envelope, or its base64, as the
//! server delivers it in `receipt_bytes_b64`. Either way the receipt is opened with its
//! signature checked against the executor it names, before anything is shown.

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jig_core::block_receipt::{Body, Comparison, Exec, Outcome, Role, SignedReceipt, compare};

/// Show a receipt, once its signature verifies.
pub fn view_receipt(path: &str, json_output: bool) -> Result<()> {
    let signed = load(path)?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&to_json(&signed))?);
    } else {
        print!("{}", pretty(&signed));
    }
    Ok(())
}

/// Compare two `exec` receipts on what executors must agree on: component, world, invocation
/// and outcome. A divergence is an error, so a script can tell.
pub fn compare_receipts(path_a: &str, path_b: &str) -> Result<()> {
    let (a, b) = (load(path_a)?, load(path_b)?);
    let exec = |s: &SignedReceipt, path: &str| match &s.receipt.body {
        Body::Exec(exec) => Ok((**exec).clone()),
        _ => anyhow::bail!(
            "{path} is a {} receipt; only exec receipts carry an outcome to compare",
            kind(&s.receipt.body)
        ),
    };
    let (ea, eb) = (exec(&a, path_a)?, exec(&b, path_b)?);
    if a.receipt.block_cid != b.receipt.block_cid {
        println!(
            "note: the receipts are for different blocks ({} and {})",
            a.receipt.block_cid, b.receipt.block_cid
        );
    }
    match compare(&ea, &eb) {
        Comparison::Agree => {
            println!("agree: {}", outcome(&ea.outcome));
            Ok(())
        }
        Comparison::NotComparable => {
            println!(
                "not comparable: an incomplete run asserts nothing ({} / {})",
                outcome(&ea.outcome),
                outcome(&eb.outcome)
            );
            Ok(())
        }
        Comparison::DifferentRuns => {
            println!(
                "different runs: the component, world or invocation differs, so the outcomes \
                 are not evidence about the same run"
            );
            Ok(())
        }
        Comparison::Diverge => anyhow::bail!(
            "diverge: {} ({}) and {} ({}) reached different outcomes for the same run",
            a.receipt.executor,
            outcome(&ea.outcome),
            b.receipt.executor,
            outcome(&eb.outcome)
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
    SignedReceipt::open(&envelope)
        .with_context(|| format!("{path} is not a v0.3 receipt that verifies"))
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

fn pretty(signed: &SignedReceipt) -> String {
    let r = &signed.receipt;
    let mut out = format!(
        "Receipt {}  (signature verifies)\n  kind:      {}\n  block:     {}\n  executor:  {} ({})\n  \
         produced:  {}\n",
        signed.cid(),
        kind(&r.body),
        r.block_cid,
        r.executor,
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
        "  outcome:   {}\n  component: {}\n  program:   {}\n  world:     {}\n  \
         invocation: {}\n  limits:    fuel {}, memory {} pages, stack {}, timeout {} ms\n  \
         engine:    {} {} ({}), fuel used {}\n",
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
        out.push_str(&format!("  policy:    {policy}\n"));
    }
    out
}

fn to_json(signed: &SignedReceipt) -> serde_json::Value {
    let r = &signed.receipt;
    let mut v = serde_json::json!({
        "cid": signed.cid().to_string(),
        "kind": kind(&r.body),
        "block_cid": r.block_cid.to_string(),
        "executor": r.executor,
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

    fn exec(outcome: Outcome) -> Body {
        Body::Exec(Box::new(Exec {
            component: [1; 32],
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

    #[test]
    fn a_receipt_loads_from_raw_bytes_or_base64_and_shows_what_it_states() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let receipt = signed(&key, exec(Outcome::Ok { hash: [3; 32] }));
        for f in [
            file(&receipt.envelope),
            file(format!("{}\n", STANDARD.encode(&receipt.envelope)).as_bytes()),
        ] {
            let loaded = load(path(&f)).unwrap();
            assert_eq!(loaded, receipt);
            let text = pretty(&loaded);
            assert!(text.contains("kind:      exec"), "{text}");
            assert!(text.contains(&did_of(&key)), "{text}");
            assert!(text.contains(&format!("ok {}", hex(&[3; 32]))), "{text}");
            assert_eq!(to_json(&loaded)["exec"]["engine"]["fuel_used"], 1234);
        }
    }

    #[test]
    fn a_receipt_whose_signature_does_not_verify_is_refused() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut envelope = signed(&key, Body::Accepted).envelope;
        let last = envelope.len() - 1;
        envelope[last] ^= 1;
        let err = load(path(&file(&envelope))).unwrap_err();
        assert!(
            format!("{err:#}").contains("not a v0.3 receipt that verifies"),
            "{err:#}"
        );
        assert!(load(path(&file(b"{\"not\": \"a receipt\"}"))).is_err());
    }

    #[test]
    fn compare_agrees_refuses_a_divergence_and_skips_what_cannot_be_compared() {
        let (a, b) = (
            SigningKey::from_bytes(&[7; 32]),
            SigningKey::from_bytes(&[8; 32]),
        );
        let ok = |k| file(&signed(k, exec(Outcome::Ok { hash: [3; 32] })).envelope);
        let other = file(&signed(&b, exec(Outcome::Ok { hash: [4; 32] })).envelope);
        let incomplete = file(
            &signed(
                &b,
                exec(Outcome::Incomplete {
                    reason: "fuel-exhausted".into(),
                }),
            )
            .envelope,
        );
        let accepted = file(&signed(&b, Body::Accepted).envelope);
        let (fa, fb) = (ok(&a), ok(&b));

        compare_receipts(path(&fa), path(&fb)).expect("the same outcome agrees");
        let err = compare_receipts(path(&fa), path(&other)).unwrap_err();
        assert!(err.to_string().starts_with("diverge:"), "{err}");
        compare_receipts(path(&fa), path(&incomplete)).expect("incomplete is not evidence");
        let err = compare_receipts(path(&fa), path(&accepted)).unwrap_err();
        assert!(err.to_string().contains("only exec receipts"), "{err}");
    }
}
