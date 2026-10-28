//! Checking a server's render: execute the block here and compare (JEP-0006 step 7).
//!
//! A server's `exec` receipt states which component it ran, on which invocation, and what came
//! out. For an open channel this client holds everything the run depended on: the block, its
//! ingest record and the component (text-block ships with the client). So it runs the same
//! invocation itself and compares.
//!
//! - Comparison keys on the component, the invocation and the outcome, never the program CID,
//!   which differs between servers ([`jig_core::block_receipt::compare`]).
//! - An `incomplete` outcome asserts nothing. A server receipt that says `incomplete` is not run
//!   again, and a local run that ends `incomplete` is not compared.
//! - A comparable disagreement is a [`Verification::Diverge`], which the caller shows the user.
//!   Nothing here resolves it.
//!
//! Encrypted channels are out of scope: a server never runs their content, so there is no `exec`
//! receipt to check, and members compare among themselves inside the group.

use std::sync::OnceLock;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use jig_core::block_receipt::{Body, Exec, Outcome};
use jig_pipeline::jig_runtime;
use jig_pipeline::receipts::ReadReceipt;
use jig_pipeline::text_block::canonical;
use jig_runtime::component::{self, CompiledRenderer, ComponentRuntime, RenderLimits, RunOutcome};

use crate::DeliveredBlock;
use crate::open::OpenedBlock;

/// What checking a block's server render found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// This client ran the same component on the same invocation and got the same outcome.
    Agree,
    /// The server's receipt and this client disagree on a comparable outcome.
    Diverge(Divergence),
    /// A run asserted nothing, so there is nothing to compare: the server's or this client's run
    /// ended `incomplete`.
    NotComparable(String),
    /// The block could not be checked here: no `exec` receipt, no ingest record, or a component
    /// this client does not have.
    Unverified(String),
}

/// How a server's `exec` receipt disagrees with this client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// The receipt names an invocation other than the one the block and its ingest record give.
    Invocation,
    /// Same component and invocation, different outcome.
    Outcome { ours: Outcome, theirs: Outcome },
}

/// The most this client spends on one run, whatever a receipt says the server used. A server
/// that ran with more and got a result this client cannot reach is [`Verification::NotComparable`],
/// not a divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientLimits {
    pub fuel: u64,
    pub timeout: Duration,
}

impl Default for ClientLimits {
    fn default() -> Self {
        let limits = jig_runtime::RuntimeConfig::default().limits;
        Self {
            fuel: limits.fuel_max,
            timeout: Duration::from_secs(1),
        }
    }
}

/// Check `delivered`'s server render under [`ClientLimits::default`].
pub fn verify(delivered: &DeliveredBlock, opened: &OpenedBlock) -> Verification {
    verify_with(delivered, opened, ClientLimits::default())
}

/// Check `delivered`'s server render under `limits`.
pub fn verify_with(
    delivered: &DeliveredBlock,
    opened: &OpenedBlock,
    limits: ClientLimits,
) -> Verification {
    let Some((exec, exec_signer, receipt_block)) = exec_receipt(delivered) else {
        return Verification::Unverified("no server exec receipt".into());
    };
    // A receipt for another block says nothing about this one: it is not a divergence.
    if receipt_block != opened.cid {
        return Verification::Unverified("the exec receipt names another block".into());
    }
    if !exec.outcome.is_comparable() {
        return Verification::NotComparable("the server's run was incomplete".into());
    }
    let Some(record) = &delivered.ingest else {
        return Verification::Unverified("no ingest record to rebuild the invocation".into());
    };
    if record.block_cid != opened.cid {
        return Verification::Unverified("the ingest record names another block".into());
    }
    // The invocation's sequence and clock come from the record, so it must be the receipt
    // signer's own record. A forged one would turn into a false divergence.
    if record.verify(&exec_signer).is_err() {
        return Verification::Unverified("the ingest record is not signed by the server".into());
    }
    let Some(local) = local_renderer() else {
        return Verification::Unverified("the text-block component did not compile here".into());
    };
    if exec.component != local.component {
        return Verification::Unverified(
            "the server ran a component this client does not have".into(),
        );
    }
    let Some(input) = jig_pipeline::executor::text_input(&opened.manifest) else {
        return Verification::Unverified("the block has no body".into());
    };

    let invocation = jig_pipeline::executor::text_render_invocation(&input, &opened.cid, record);
    if component::hash_bytes(&component::invocation_hash(&invocation)) != exec.invocation_hash {
        return Verification::Diverge(Divergence::Invocation);
    }

    let run = local.runtime.render(
        &local.renderer,
        &invocation,
        &RenderLimits {
            fuel: limits.fuel.min(exec.limits.fuel),
            timeout: limits.timeout,
        },
    );
    if let RunOutcome::Incomplete(reason) = &run.outcome {
        return Verification::NotComparable(format!(
            "this client's run was incomplete: {}",
            reason.as_str()
        ));
    }
    let ours = run.outcome.to_receipt();
    if ours == exec.outcome {
        Verification::Agree
    } else {
        Verification::Diverge(Divergence::Outcome {
            ours,
            theirs: exec.outcome,
        })
    }
}

/// The first server `exec` receipt that verifies and is signed by the server its `ReceiptRef`
/// names, with that signer's DID.
fn exec_receipt(delivered: &DeliveredBlock) -> Option<(Exec, String, String)> {
    delivered.receipts.iter().find_map(|r| {
        let bytes = STANDARD.decode(&r.receipt_bytes_b64).ok()?;
        let ReadReceipt::V03(signed) = jig_pipeline::receipts::read(&bytes).ok()? else {
            return None;
        };
        if !jig_pipeline::handshake::same_did(&signed.receipt.executor, &r.server_did) {
            return None;
        }
        match signed.receipt.body {
            Body::Exec(exec) => Some((
                *exec,
                signed.receipt.executor,
                signed.receipt.block_cid.to_string(),
            )),
            _ => None,
        }
    })
}

struct LocalRenderer {
    runtime: ComponentRuntime,
    renderer: CompiledRenderer,
    component: [u8; 32],
}

/// text-block compiled once per process. The memory cap is this client's default: any cap at or
/// above the component's own declared maximum gives the same runs (the validator refuses a cap
/// below it), so it need not match the server's.
fn local_renderer() -> Option<&'static LocalRenderer> {
    static LOCAL: OnceLock<Option<LocalRenderer>> = OnceLock::new();
    LOCAL
        .get_or_init(|| {
            let config = jig_runtime::RuntimeConfig::default();
            let runtime =
                ComponentRuntime::with_config(&config, component::Backend::Native).ok()?;
            let renderer = runtime
                .compile_renderer(
                    canonical::CANONICAL_COMPONENT,
                    &jig_core::grant::Grant::empty(),
                    config.limits.memory_max_mb.saturating_mul(16),
                )
                .ok()?;
            let component = component::hash_bytes(renderer.component_hash());
            Some(LocalRenderer {
                runtime,
                renderer,
                component,
            })
        })
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use ed25519_dalek::SigningKey;
    use jig_core::block_receipt::{Receipt, Role};
    use jig_pipeline::envelope::ReceiptRef;
    use jig_pipeline::executor::{BlockExecutor, text_input, text_render_invocation};

    fn server_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn server_did() -> String {
        jig_pipeline::receipts::executor(&server_key())
    }

    /// The server's signed ingest record for `block_cid` at `seq`.
    fn signed_record(seq: u64, block_cid: &str) -> jig_pipeline::ingest_record::IngestRecord {
        jig_pipeline::ingest_record::RecordSigner {
            channel_id: jig_pipeline::ingest_record::label_cid("#hello"),
            key: &server_key(),
            ingest_wall_ms: 1_700_000_000_123,
            ingest_logical: 1,
        }
        .sign(seq, block_cid, [0; 32])
        .expect("the record signs")
    }

    /// A delivered text-render block, its ingest record, and the server's `exec` body for it.
    fn delivered(body: &str) -> (DeliveredBlock, OpenedBlock, Exec) {
        let sender = Identity::from_signing_key(SigningKey::from_bytes(&[7; 32]));
        let hlc = jig_core::HlcTimestamp {
            wall_ms: 1_700_000_000_000,
            logical: 0,
            server_did: sender.did().clone(),
        };
        let built = crate::blocks::build_text_render(&sender, "#hello", body, hlc);
        let mut delivered = DeliveredBlock {
            bundle_b64: STANDARD.encode(built.canonical_bytes()),
            sig_b64: Some(STANDARD.encode(&built.sender_sig)),
            receipts: vec![],
            delivery_cid: String::new(),
            ingest: None,
        };
        let opened = crate::open::open(&delivered).expect("the block opens");
        let record = signed_record(3, &opened.cid);
        let input = text_input(&opened.manifest).expect("the block has a body");
        let server =
            BlockExecutor::for_tests(jig_pipeline::executor::test_runtime_config()).unwrap();
        let run = server
            .render(&text_render_invocation(&input, &opened.cid, &record))
            .unwrap();
        delivered.ingest = Some(record);
        (delivered, opened, run.exec)
    }

    /// Attach `exec` as the server's signed receipt.
    fn with_receipt(delivered: DeliveredBlock, exec: Exec, signer: &SigningKey) -> DeliveredBlock {
        let block_cid = delivered.ingest.as_ref().unwrap().block_cid.clone();
        with_receipt_for(delivered, exec, signer, &block_cid)
    }

    /// Attach `exec` as the server's signed receipt for `block_cid`.
    fn with_receipt_for(
        mut delivered: DeliveredBlock,
        exec: Exec,
        signer: &SigningKey,
        block_cid: &str,
    ) -> DeliveredBlock {
        let receipt = Receipt {
            block_cid: jig_pipeline::receipts::block_cid(block_cid).unwrap(),
            executor: jig_pipeline::receipts::executor(signer),
            role: Role::Server,
            produced_at: 1,
            body: Body::Exec(Box::new(exec)),
        };
        delivered.receipts = vec![ReceiptRef {
            server_did: server_did(),
            render_hash: None,
            receipt_bytes_b64: STANDARD
                .encode(jig_pipeline::receipts::sign(receipt, signer).unwrap()),
        }];
        delivered
    }

    #[test]
    fn a_client_agrees_with_an_honest_server() {
        let (d, opened, exec) = delivered("hello");
        let d = with_receipt(d, exec, &server_key());
        assert_eq!(verify(&d, &opened), Verification::Agree);
    }

    #[test]
    fn a_forged_server_hash_is_a_divergence() {
        let (d, opened, mut exec) = delivered("hello");
        exec.outcome = Outcome::Ok { hash: [0xee; 32] };
        let d = with_receipt(d, exec, &server_key());
        assert!(matches!(
            verify(&d, &opened),
            Verification::Diverge(Divergence::Outcome { .. })
        ));
    }

    #[test]
    fn a_receipt_for_another_invocation_is_a_divergence() {
        let (mut d, opened, exec) = delivered("hello");
        // The server's own record says seq 4; its receipt was for seq 3.
        d.ingest = Some(signed_record(4, &opened.cid));
        let d = with_receipt(d, exec, &server_key());
        assert_eq!(
            verify(&d, &opened),
            Verification::Diverge(Divergence::Invocation)
        );
    }

    /// A server's receipt for another block, delivered with this one, is not evidence about it:
    /// without the check it would read as the server's render differing (a different invocation).
    #[test]
    fn a_receipt_for_another_block_is_unverified() {
        let (d, opened, exec) = delivered("hello");
        let other = jig_core::canonical_cid::of(b"another block").to_string();
        let d = with_receipt_for(d, exec, &server_key(), &other);
        assert!(matches!(verify(&d, &opened), Verification::Unverified(_)));
    }

    /// A record the server did not sign could carry any sequence or clock, so it is not used:
    /// otherwise a forged record would read as the server's render differing.
    #[test]
    fn a_record_not_signed_by_the_server_is_unverified() {
        let (mut d, opened, exec) = delivered("hello");
        d.ingest.as_mut().unwrap().seq = 4; // altered after signing
        let d = with_receipt(d, exec, &server_key());
        assert!(matches!(verify(&d, &opened), Verification::Unverified(_)));
    }

    #[test]
    fn a_local_incomplete_run_is_not_compared() {
        let (d, opened, exec) = delivered("hello");
        let d = with_receipt(d, exec, &server_key());
        let starved = ClientLimits {
            fuel: 100,
            timeout: Duration::from_secs(1),
        };
        assert!(matches!(
            verify_with(&d, &opened, starved),
            Verification::NotComparable(_)
        ));
    }

    #[test]
    fn a_server_incomplete_receipt_is_not_run_or_compared() {
        let (d, opened, mut exec) = delivered("hello");
        exec.outcome = Outcome::Incomplete {
            reason: "deadline-exceeded".into(),
        };
        let d = with_receipt(d, exec, &server_key());
        assert!(matches!(
            verify(&d, &opened),
            Verification::NotComparable(_)
        ));
    }

    #[test]
    fn a_receipt_signed_by_another_server_is_not_used() {
        let (d, opened, exec) = delivered("hello");
        let d = with_receipt(d, exec, &SigningKey::from_bytes(&[0x43; 32]));
        assert!(matches!(verify(&d, &opened), Verification::Unverified(_)));
    }

    #[test]
    fn a_block_with_no_exec_receipt_is_unverified() {
        let (d, opened, _) = delivered("hello");
        assert!(matches!(verify(&d, &opened), Verification::Unverified(_)));
    }
}
