//! `jig init` — Phase F1 of v0.0.2 hello-world.
//!
//! One-step onboarding:
//!   1. Generate a fresh ed25519 identity under `~/.jig/keys/<did>.key`.
//!   2. Write `~/.jig/cli.toml` binding the new DID to a nickname.
//!   3. Optionally `--request-alias <local> --nameserver <url>`:
//!      GET `/v1/challenge` → sign → POST `/v1/register` → print attestation.
//!
//! The nameserver wire-shape (`requested_alias` + `proof_of_control` +
//! `challenge`) is defined by `jig-nameserver::v0_0_2_register`. Keep
//! the field names in sync with that module.

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use jig_client::Identity;
use serde::{Deserialize, Serialize};

use crate::config::{self, Config};

/// Parsed flags for `jig init`. Construct directly from `clap`-parsed args
/// in `main.rs`; this struct keeps the CLI surface and the implementation
/// decoupled for testability.
#[derive(Debug, Clone, Default)]
pub struct InitArgs {
    /// Optional nickname; defaults to `whoami::username()`.
    pub nickname: Option<String>,
    /// Overwrite `~/.jig/cli.toml` if it already exists.
    pub force: bool,
    /// Local part of an alias to request from a nameserver (e.g. `dj`).
    pub request_alias: Option<String>,
    /// Nameserver base URL (required when `request_alias` is set).
    pub nameserver: Option<String>,
}

/// Body of GET `/v1/challenge` (we only consume the `challenge` field).
#[derive(Debug, Deserialize)]
pub(crate) struct ChallengeResponse {
    pub challenge: String,
}

/// Body of POST `/v1/register`. Must mirror
/// `jig_nameserver::v0_0_2_register::RegisterReq` exactly.
#[derive(Debug, Serialize)]
pub(crate) struct RegisterRequest {
    pub did: String,
    pub requested_alias: String,
    pub proof_of_control: String,
    pub challenge: String,
}

/// Response from POST `/v1/register`. Mirrors
/// `jig_nameserver::v0_0_2_register::Attestation` (subset we display).
#[derive(Debug, Deserialize, Serialize)]
pub struct AttestationResponse {
    pub did: String,
    pub alias: String,
    pub ns_did: String,
    pub valid_from: i64,
    pub valid_until: i64,
    pub profile_ttl_seconds: u64,
    pub sig: String,
}

pub async fn run(args: InitArgs) -> Result<()> {
    // 1. Refuse to clobber existing cli.toml unless --force was passed.
    let cfg_path = config::default_config_path();
    if cfg_path.exists() && !args.force {
        anyhow::bail!(
            "cli config already exists at {}. Pass --force to overwrite.",
            cfg_path.display()
        );
    }

    // 2. Generate fresh ed25519 keypair under ~/.jig/keys/.
    let keys_dir = jig_client::identity::default_keys_dir();
    let id = Identity::generate_and_save(&keys_dir)
        .with_context(|| format!("generating identity under {}", keys_dir.display()))?;
    let did_string = id.did_string();
    println!("generated DID: {did_string}");
    println!("keyfile: {}", keys_dir.join(format!("{did_string}.key")).display());

    // 3. Persist nickname + DID binding to ~/.jig/cli.toml.
    let nickname = args
        .nickname
        .clone()
        .unwrap_or_else(whoami::username);
    write_cli_config(&id, &nickname)?;
    println!("wrote {} (nickname: {nickname})", cfg_path.display());

    // 4. Optional alias registration.
    if let Some(alias_local) = args.request_alias {
        let ns_url = args
            .nameserver
            .ok_or_else(|| anyhow!("--nameserver <url> is required with --request-alias"))?;
        let attestation = register_with_nameserver(&id, &alias_local, &ns_url).await?;
        let ttl_days = (attestation.valid_until - attestation.valid_from) / 86_400;
        println!(
            "alias attestation received: {} (valid {ttl_days}d, ns={})",
            attestation.alias, attestation.ns_did
        );
    }

    Ok(())
}

/// Write `~/.jig/cli.toml` with the freshly generated DID and the
/// caller-supplied nickname. Server URL + default channel are pulled
/// from `Config::default()` so v0.0.2 stays one-line-installable.
fn write_cli_config(id: &Identity, nickname: &str) -> Result<()> {
    let mut cfg = Config::default();
    cfg.user.did = id.did_string();
    cfg.user.display_name = nickname.to_string();
    config::save_config(&cfg, None)?;
    Ok(())
}

/// Run the challenge → sign → register handshake against a nameserver.
///
/// Returns the parsed attestation on success. Errors propagate as
/// `anyhow::Error` with context describing the failed step.
pub async fn register_with_nameserver(
    id: &Identity,
    alias_local: &str,
    ns_url: &str,
) -> Result<AttestationResponse> {
    let base = ns_url.trim_end_matches('/');
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("building HTTP client for nameserver")?;

    // 1. Fetch a challenge nonce.
    let ch_url = format!("{base}/v1/challenge");
    let ch_resp = http
        .get(&ch_url)
        .send()
        .await
        .with_context(|| format!("GET {ch_url}"))?;
    if !ch_resp.status().is_success() {
        anyhow::bail!(
            "GET {ch_url} returned {}: {}",
            ch_resp.status(),
            ch_resp.text().await.unwrap_or_default()
        );
    }
    let challenge: ChallengeResponse = ch_resp
        .json()
        .await
        .context("decoding /v1/challenge response")?;

    // 2. Sign the challenge bytes (UTF-8) and base64-encode the signature.
    let body = build_register_request(id, alias_local, &challenge.challenge);

    // 3. POST /v1/register.
    let reg_url = format!("{base}/v1/register");
    let reg_resp = http
        .post(&reg_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {reg_url}"))?;
    if !reg_resp.status().is_success() {
        anyhow::bail!(
            "POST {reg_url} returned {}: {}",
            reg_resp.status(),
            reg_resp.text().await.unwrap_or_default()
        );
    }
    let attestation: AttestationResponse = reg_resp
        .json()
        .await
        .context("decoding /v1/register response")?;
    Ok(attestation)
}

/// Build the POST /v1/register body for a given identity, requested
/// alias local-part, and server-issued challenge string. Factored out
/// so unit tests can exercise the signing-and-encoding step without an
/// HTTP transport.
pub(crate) fn build_register_request(
    id: &Identity,
    alias_local: &str,
    challenge: &str,
) -> RegisterRequest {
    let sig = id.sign(challenge.as_bytes());
    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    RegisterRequest {
        did: id.did_string(),
        requested_alias: alias_local.to_string(),
        proof_of_control: proof_b64,
        challenge: challenge.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use tempfile::tempdir;

    #[test]
    fn build_register_request_signs_challenge_and_uses_canonical_did() {
        // Generate a fresh identity in a tempdir (separate from ~/.jig/keys/).
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        let challenge = "deadbeef".to_string();

        let req = build_register_request(&id, "dj", &challenge);

        assert_eq!(req.did, id.did_string(), "DID must match identity");
        assert!(
            req.did.starts_with("did:jig:z"),
            "DID must be canonical: {}",
            req.did
        );
        assert_eq!(req.requested_alias, "dj");
        assert_eq!(req.challenge, challenge);

        // Signature must verify against the identity's public key over the
        // raw challenge bytes (matching what jig-nameserver does).
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&req.proof_of_control)
            .unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        id.public_key()
            .verify(challenge.as_bytes(), &sig)
            .expect("proof_of_control must verify under the identity's pubkey");
    }

    #[test]
    fn build_register_request_passes_local_part_through_unchanged() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        // Local part should not be uppercased, suffixed, or rewritten —
        // the nameserver owns suffix composition (`<local>@<ns_suffix>`).
        let req = build_register_request(&id, "Alice_42", "abc");
        assert_eq!(req.requested_alias, "Alice_42");
    }

    // TODO(F1): integration test against a real jig-nameserver instance
    // — the H-phase end-to-end tests in `integration-tests/` cover the
    // challenge → sign → register round-trip against an in-process
    // nameserver, so this module only unit-tests the request-builder.
}
