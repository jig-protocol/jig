//! Proof of work at admission, done once per server and identity.
//!
//! A server under `[auth.admission] unknown_dids = "proof-of-work"` refuses a
//! DID it has never seen until that DID posts some work to
//! `/api/v1/admission`, and advertises how much at `/.well-known/jig`. Before
//! a command talks to the server, [`ensure`] asks (signed) whether this
//! identity is already known there and, if not, does the work and posts it.
//! Against a server that asks for none it costs one unauthenticated GET.

use anyhow::{Context, Result};
use jig_client::Identity;
use jig_client::admission::{AdmissionProof, PowAdmissionProof};
use jig_client::read_auth::{ReadProof, signable_path};
use jig_client::tls::TlsError;
use serde::Deserialize;

use crate::cmd::channel::base_http_url;
use crate::cmd::common::CliContext;
use crate::cmd::server::well_known_url;

#[derive(Deserialize)]
struct Advertised {
    #[serde(default)]
    server_did: Option<String>,
    #[serde(default)]
    admission_pow_bits: Option<u8>,
    /// JEP-0008's form of the same ask. Preferred when present.
    #[serde(default)]
    admission_pow: Option<AdvertisedPow>,
}

#[derive(Deserialize)]
struct AdvertisedPow {
    alg: jig_core::pow::Alg,
    effort: u64,
}

/// What the server asks a new identity for.
enum Work {
    Effort(std::num::NonZeroU64),
    LegacyBits(u8),
}

#[derive(Deserialize)]
struct Status {
    proven: bool,
}

/// [`ensure_for`] the configured server and identity. Without either there is
/// nothing to prove; the command reports what is missing itself.
pub async fn ensure(ctx: &CliContext) -> Result<()> {
    let (Ok(server), Ok(identity)) = (ctx.server_url(), ctx.identity()) else {
        return Ok(());
    };
    ensure_for(&server, &identity).await
}

/// Make sure `identity` has done `server`'s admission work.
///
/// An unreachable server, or one that predates admission, is not an error
/// here: the command that follows reports it in its own terms. A server that
/// refuses the proof is, since nothing after it would work, and so is one
/// this device does not trust ([`crate::cmd::trust`]).
pub async fn ensure_for(server: &str, identity: &Identity) -> Result<()> {
    let http = match crate::cmd::trust::http(server, std::time::Duration::from_secs(15)).await {
        Ok(http) => http,
        Err(e) if matches!(e.downcast_ref(), Some(TlsError::Fetch { .. })) => return Ok(()),
        Err(e) => return Err(e),
    };
    let advertised: Option<Advertised> = match http.get(well_known_url(server)).send().await {
        Ok(resp) if resp.status().is_success() => {
            jig_client::limits::json_capped(resp, jig_client::limits::MAX_DOCUMENT_BYTES)
                .await
                .ok()
        }
        _ => None,
    };
    let Some(Advertised {
        server_did: Some(server_did),
        admission_pow_bits,
        admission_pow,
    }) = advertised
    else {
        return Ok(());
    };
    let work = match (admission_pow, admission_pow_bits) {
        (Some(AdvertisedPow { alg, effort }), _) => {
            if alg != jig_core::pow::Alg::Blake3 {
                anyhow::bail!(
                    "{server} asks for proof of work under an algorithm this client lacks"
                );
            }
            // Zero means no work is asked (JEP-0008 rule 17).
            match std::num::NonZeroU64::new(effort) {
                Some(effort) => Work::Effort(effort),
                None => return Ok(()),
            }
        }
        (None, Some(bits)) => Work::LegacyBits(bits),
        (None, None) => return Ok(()),
    };

    let url = format!("{}/api/v1/admission", base_http_url(server));
    let proof = ReadProof::sign(identity, "GET", signable_path(&url));
    let mut req = http.get(&url);
    for (name, value) in proof.headers() {
        req = req.header(name, value);
    }
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            if jig_client::limits::json_capped::<Status>(
                resp,
                jig_client::limits::MAX_DOCUMENT_BYTES,
            )
            .await
            .is_ok_and(|s| s.proven)
            {
                return Ok(());
            }
        }
        _ => return Ok(()),
    }

    let (server_did2, did) = (server_did.clone(), identity.did_string());
    let resp = match work {
        Work::Effort(effort) => {
            if effort.get() > jig_core::pow::MAX_EFFORT {
                anyhow::bail!(
                    "{server} asks a new identity for proof of work of effort {effort}, more \
                     than the {} any server may ask; not doing it",
                    jig_core::pow::MAX_EFFORT
                );
            }
            eprintln!(
                "{server} asks a new identity for proof of work (effort {effort}); working (once)…"
            );
            let pow = tokio::task::spawn_blocking(move || {
                jig_core::admission_pow::puzzle(&server_did2, &did).solve(effort)
            })
            .await
            .context("proof of work thread")?;
            http.post(&url)
                .json(&PowAdmissionProof::sign(identity, &server_did, pow))
                .send()
                .await
        }
        Work::LegacyBits(bits) => {
            if bits > jig_core::admission_pow::MAX_BITS {
                anyhow::bail!(
                    "{server} asks a new identity for {bits} bits of proof of work, more than \
                     the {} any server may ask; not doing it",
                    jig_core::admission_pow::MAX_BITS
                );
            }
            eprintln!(
                "{server} asks a new identity for {bits} bits of proof of work; working (once)…"
            );
            let nonce = tokio::task::spawn_blocking(move || {
                jig_core::admission_pow::solve(&server_did2, &did, bits)
            })
            .await
            .context("proof of work thread")?;
            http.post(&url)
                .json(&AdmissionProof::sign(identity, &server_did, nonce))
                .send()
                .await
        }
    }
    .with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body: serde_json::Value =
            serde_json::from_str(&jig_client::limits::error_text(resp).await).unwrap_or_default();
        anyhow::bail!(
            "{server} refused the admission proof ({status} {}): {}",
            body["code"].as_str().unwrap_or("HTTP_ERROR"),
            body["message"].as_str().unwrap_or("")
        );
    }
    eprintln!("admitted to {server}");
    Ok(())
}
