//! `jig keys renew` and `jig keys rotate` — Phase F2 of v0.0.2 hello-world.
//!
//! Both subcommands hit the v0.0.2 nameserver at `/v1/challenge` for a
//! fresh nonce, sign it with the appropriate ed25519 key(s), and POST
//! to `/v1/renew` or `/v1/rotate` respectively.
//!
//! The wire-shapes (`RenewReq` / `RotateReq`) are defined in
//! `jig_nameserver::v0_0_2_rotate_renew`. Keep field names in lockstep.
//!
//! Rotate semantics:
//!   1. Load the current identity from `~/.jig/keys/<old_did>.key`.
//!   2. Mint a fresh identity (writes the new keyfile via
//!      `Identity::generate_and_save`).
//!   3. Sign the same challenge with BOTH keys.
//!   4. POST /v1/rotate. If the request fails, the new keyfile is
//!      removed before bailing so we never end up with two valid keys
//!      and a stale config.
//!   5. On success: rename the OLD keyfile to `<old_did>.key.rotated`
//!      (kept for offline recovery) and rewrite `~/.jig/cli.toml` so
//!      `[user] did` points at the new DID.
//!
//! The `.key.rotated` rename is a design call — `v0_0_2_rotate_renew.rs`
//! handles the server-side expiry but is silent on client-side cleanup;
//! keeping the file (under a non-loadable name) preserves the operator's
//! ability to verify or recover offline.

use anyhow::{Context, Result};
use base64::Engine as _;
use jig_client::Identity;
use serde::{Deserialize, Serialize};

use crate::cmd::init::{AttestationResponse, ChallengeResponse};
use crate::config;

/// Parsed flags for `jig keys renew`.
#[derive(Debug, Clone)]
pub struct KeysRenewArgs {
    /// Fully-qualified alias being renewed (e.g. `dj@dj.jig`).
    pub alias: String,
    /// Nameserver base URL.
    pub nameserver: String,
}

/// Parsed flags for `jig keys rotate`.
#[derive(Debug, Clone)]
pub struct KeysRotateArgs {
    /// Fully-qualified alias whose binding is being rotated.
    pub alias: String,
    /// Nameserver base URL.
    pub nameserver: String,
}

/// Body of POST `/v1/renew`. Mirrors
/// `jig_nameserver::v0_0_2_rotate_renew::RenewReq`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RenewRequestBody {
    pub alias: String,
    pub did: String,
    pub challenge: String,
    pub proof_of_control: String,
}

/// Body of POST `/v1/rotate`. Mirrors
/// `jig_nameserver::v0_0_2_rotate_renew::RotateReq`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RotateRequestBody {
    pub alias: String,
    pub old_did: String,
    pub new_did: String,
    pub challenge: String,
    pub sig_by_old: String,
    pub sig_by_new: String,
}

// ============================================================================
// renew
// ============================================================================

pub async fn renew(args: KeysRenewArgs) -> Result<()> {
    // 1. Load current identity from cli.toml's DID.
    let cfg = config::load_config(None)?;
    let did_str = cfg.user.did.clone();
    if !did_str.starts_with("did:jig:") {
        anyhow::bail!(
            "cli.toml `[user] did = \"{did_str}\"` does not look like a Jig DID. \
             Run `jig init` first or fix the config."
        );
    }
    let keys_dir = jig_client::identity::default_keys_dir();
    let id = Identity::load_from_dir(&keys_dir, &did_str)
        .with_context(|| format!("loading identity {did_str} from {}", keys_dir.display()))?;

    // 2. Run the renew handshake.
    let attestation = renew_with_nameserver(&id, &args.alias, &args.nameserver).await?;

    let ttl_days = (attestation.valid_until - attestation.valid_from) / 86_400;
    println!(
        "alias attestation renewed: {} (valid {ttl_days}d, ns={})",
        attestation.alias, attestation.ns_did
    );
    Ok(())
}

/// Drive the challenge → sign → renew handshake.
pub async fn renew_with_nameserver(
    id: &Identity,
    alias: &str,
    ns_url: &str,
) -> Result<AttestationResponse> {
    let base = ns_url.trim_end_matches('/');
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("building HTTP client for nameserver")?;

    let challenge = fetch_challenge(&http, base).await?;
    let body = build_renew_request(id, alias, &challenge);

    let url = format!("{base}/v1/renew");
    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "POST {url} returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let attestation: AttestationResponse = resp
        .json()
        .await
        .context("decoding /v1/renew response")?;
    Ok(attestation)
}

/// Build the POST /v1/renew body. Factored out for unit testing.
pub(crate) fn build_renew_request(
    id: &Identity,
    alias: &str,
    challenge: &str,
) -> RenewRequestBody {
    let sig = id.sign(challenge.as_bytes());
    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    RenewRequestBody {
        alias: alias.to_string(),
        did: id.did_string(),
        challenge: challenge.to_string(),
        proof_of_control: proof_b64,
    }
}

// ============================================================================
// rotate
// ============================================================================

pub async fn rotate(args: KeysRotateArgs) -> Result<()> {
    // 1. Load current identity from cli.toml's DID.
    let cfg = config::load_config(None)?;
    let old_did_str = cfg.user.did.clone();
    if !old_did_str.starts_with("did:jig:") {
        anyhow::bail!(
            "cli.toml `[user] did = \"{old_did_str}\"` does not look like a Jig DID. \
             Run `jig init` first or fix the config."
        );
    }
    let keys_dir = jig_client::identity::default_keys_dir();
    let old_id = Identity::load_from_dir(&keys_dir, &old_did_str).with_context(|| {
        format!("loading old identity {old_did_str} from {}", keys_dir.display())
    })?;

    // 2. Mint a fresh keypair. This writes the new keyfile to disk.
    let new_id = Identity::generate_and_save(&keys_dir)
        .with_context(|| format!("generating new identity under {}", keys_dir.display()))?;
    let new_did_str = new_id.did_string();
    let new_keyfile = keys_dir.join(format!("{new_did_str}.key"));

    // 3. Drive the rotate handshake. On any failure, undo the new keyfile
    //    so we don't leak an orphaned key.
    let attestation =
        match rotate_with_nameserver(&old_id, &new_id, &args.alias, &args.nameserver).await {
            Ok(a) => a,
            Err(e) => {
                // Best-effort cleanup; ignore secondary errors.
                let _ = std::fs::remove_file(&new_keyfile);
                return Err(e);
            }
        };

    // 4. Rename the OLD keyfile to <old_did>.key.rotated. Operator may
    //    want it for offline recovery. The rename keeps it on disk but
    //    out of the DID-load lookup path.
    let old_keyfile = keys_dir.join(format!("{old_did_str}.key"));
    let rotated_keyfile = keys_dir.join(format!("{old_did_str}.key.rotated"));
    std::fs::rename(&old_keyfile, &rotated_keyfile).with_context(|| {
        format!(
            "renaming {} -> {} after successful rotation",
            old_keyfile.display(),
            rotated_keyfile.display()
        )
    })?;

    // 5. Update cli.toml to point at the new DID.
    let mut updated_cfg = cfg.clone();
    updated_cfg.user.did = new_did_str.clone();
    config::save_config(&updated_cfg, None)?;

    let ttl_days = (attestation.valid_until - attestation.valid_from) / 86_400;
    println!("rotated alias: {}", attestation.alias);
    println!("  old DID: {old_did_str} (keyfile -> {})", rotated_keyfile.display());
    println!("  new DID: {new_did_str} (keyfile -> {})", new_keyfile.display());
    println!("  ns={} valid {ttl_days}d", attestation.ns_did);
    Ok(())
}

/// Drive the challenge → dual-sign → rotate handshake.
pub async fn rotate_with_nameserver(
    old_id: &Identity,
    new_id: &Identity,
    alias: &str,
    ns_url: &str,
) -> Result<AttestationResponse> {
    let base = ns_url.trim_end_matches('/');
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("building HTTP client for nameserver")?;

    let challenge = fetch_challenge(&http, base).await?;
    let body = build_rotate_request(old_id, new_id, alias, &challenge);

    let url = format!("{base}/v1/rotate");
    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "POST {url} returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let attestation: AttestationResponse = resp
        .json()
        .await
        .context("decoding /v1/rotate response")?;
    Ok(attestation)
}

/// Build the POST /v1/rotate body. Factored out for unit testing.
pub(crate) fn build_rotate_request(
    old_id: &Identity,
    new_id: &Identity,
    alias: &str,
    challenge: &str,
) -> RotateRequestBody {
    let sig_old = old_id.sign(challenge.as_bytes());
    let sig_new = new_id.sign(challenge.as_bytes());
    let encode = |b: [u8; 64]| base64::engine::general_purpose::STANDARD.encode(b);
    RotateRequestBody {
        alias: alias.to_string(),
        old_did: old_id.did_string(),
        new_did: new_id.did_string(),
        challenge: challenge.to_string(),
        sig_by_old: encode(sig_old.to_bytes()),
        sig_by_new: encode(sig_new.to_bytes()),
    }
}

// ============================================================================
// shared helpers
// ============================================================================

async fn fetch_challenge(http: &reqwest::Client, base: &str) -> Result<String> {
    let url = format!("{base}/v1/challenge");
    let resp = http
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "GET {url} returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let body: ChallengeResponse = resp
        .json()
        .await
        .context("decoding /v1/challenge response")?;
    Ok(body.challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use tempfile::tempdir;

    #[test]
    fn build_renew_request_signs_challenge_and_uses_canonical_did() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        let challenge = "deadbeef".to_string();

        let req = build_renew_request(&id, "dj@dj.jig", &challenge);

        assert_eq!(req.did, id.did_string());
        assert!(req.did.starts_with("did:jig:z"), "DID must be canonical: {}", req.did);
        assert_eq!(req.alias, "dj@dj.jig");
        assert_eq!(req.challenge, challenge);

        // Signature must verify against the identity's pubkey over the
        // raw challenge bytes — the nameserver's verify_proof_of_control
        // signs the challenge string directly.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&req.proof_of_control)
            .unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        id.public_key()
            .verify(challenge.as_bytes(), &sig)
            .expect("proof_of_control must verify under the identity's pubkey");
    }

    #[test]
    fn build_renew_request_passes_full_alias_through_unchanged() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        // Renew takes a fully-qualified alias (`local@ns_suffix`), unlike
        // register which takes only the local part. Make sure we don't
        // strip or rewrite it.
        let req = build_renew_request(&id, "Alice_42@dj.jig", "abc");
        assert_eq!(req.alias, "Alice_42@dj.jig");
    }

    #[test]
    fn build_rotate_request_signs_with_both_keys_and_pins_both_dids() {
        let dir = tempdir().unwrap();
        let old = Identity::generate_and_save(dir.path()).unwrap();
        // Sleep is unnecessary — two separate generate calls produce
        // distinct keys with overwhelming probability.
        let new = Identity::generate_and_save(dir.path()).unwrap();
        assert_ne!(old.did_string(), new.did_string(), "DIDs must differ");

        let challenge = "c0ffee".to_string();
        let req = build_rotate_request(&old, &new, "dj@dj.jig", &challenge);

        assert_eq!(req.alias, "dj@dj.jig");
        assert_eq!(req.old_did, old.did_string());
        assert_eq!(req.new_did, new.did_string());
        assert_eq!(req.challenge, challenge);

        // sig_by_old must verify under old's pubkey over the challenge.
        let old_sig = ed25519_dalek::Signature::from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(&req.sig_by_old)
                .unwrap(),
        )
        .unwrap();
        old.public_key()
            .verify(challenge.as_bytes(), &old_sig)
            .expect("sig_by_old must verify under old pubkey");

        // sig_by_new must verify under new's pubkey over the challenge.
        let new_sig = ed25519_dalek::Signature::from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(&req.sig_by_new)
                .unwrap(),
        )
        .unwrap();
        new.public_key()
            .verify(challenge.as_bytes(), &new_sig)
            .expect("sig_by_new must verify under new pubkey");
    }

    #[test]
    fn build_rotate_request_cross_signature_does_not_verify() {
        // Defence-in-depth: confirm that swapping sigs across pubkeys
        // doesn't accidentally pass (would indicate identical signing input).
        let dir = tempdir().unwrap();
        let old = Identity::generate_and_save(dir.path()).unwrap();
        let new = Identity::generate_and_save(dir.path()).unwrap();
        let req = build_rotate_request(&old, &new, "dj@dj.jig", "zz");

        let old_sig = ed25519_dalek::Signature::from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(&req.sig_by_old)
                .unwrap(),
        )
        .unwrap();
        assert!(
            new.public_key().verify(b"zz", &old_sig).is_err(),
            "sig_by_old must NOT verify under the new pubkey"
        );
    }
}
