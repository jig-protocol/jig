//! `jig keys renew` and `jig keys rotate` — Phase F2 of v0.0.2 hello-world.
//!
//! Both subcommands read the nameserver's delegation, fetch a fresh nonce
//! from `/v1/challenge`, sign it, POST to `/v1/renew` or `/v1/rotate`, and
//! verify the attestation that comes back. Renew signs an action-bound proof
//! of control (JEP-0004 rule 10); rotate still signs the bare challenge with
//! both keys, until lane I's I3 moves rotation onto links.
//!
//! The wire-shapes (`RenewReq` / `RotateReq`) are defined in
//! `jig_nameserver::v0_0_2_rotate_renew`. Keep field names in lockstep.
//!
//! Rotate semantics:
//!   1. Load the current identity from `~/.jig/keys/<old_did>.jigkey`.
//!   2. Mint a fresh identity (seals the new keyfile via
//!      `Identity::create`).
//!   3. Sign the same challenge with BOTH keys.
//!   4. POST /v1/rotate. If the request fails, the new keyfile is
//!      removed before bailing so we never end up with two valid keys
//!      and a stale config. If the nameserver accepts the rotation but its
//!      reply does not verify, both keyfiles and the config stay as they
//!      are: the alias may already point at the new DID, so its key must
//!      not be thrown away.
//!   5. On a verified reply: rename the OLD keyfile to `<old_did>.jigkey.rotated`
//!      (kept for offline recovery) and rewrite the active config file
//!      (`--config <path>`, else `~/.jig/cli.toml`) so `[user] did`
//!      points at the new DID.
//!
//! The `.jigkey.rotated` rename is a design call — `v0_0_2_rotate_renew.rs`
//! handles the server-side expiry but is silent on client-side cleanup;
//! keeping the file (under a non-loadable name) preserves the operator's
//! ability to verify or recover offline.

use anyhow::{Context, Result};
use base64::Engine as _;
use jig_client::Identity;
use jig_core::naming::{Action, Attestation, Name};
use serde::{Deserialize, Serialize};

use crate::cmd::common::CliContext;
use crate::cmd::ns::{Nameserver, Purpose, b64u};

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

pub async fn renew(ctx: &CliContext, args: KeysRenewArgs) -> Result<()> {
    // 1. Load the active identity (`--did` override or `[user] did`).
    let id = ctx.identity()?;

    // 2. Run the renew handshake.
    let delegations = crate::config::delegations(ctx.effective());
    let attestation =
        renew_with_nameserver(&id, &args.alias, &args.nameserver, &delegations).await?;

    let ttl_days = (attestation.valid_until - attestation.valid_from) / 86_400;
    println!(
        "alias attestation renewed: {} (valid {ttl_days}d, ns={})",
        attestation.alias, attestation.ns_did
    );
    Ok(())
}

/// Renew `alias` (the full `alias@suffix`) for `id` and return the
/// verified attestation.
pub async fn renew_with_nameserver(
    id: &Identity,
    alias: &str,
    ns_url: &str,
    delegations: &jig_client::naming::Delegations,
) -> Result<Attestation> {
    parse_full_name(alias)?;
    let ns = Nameserver::connect(ns_url, alias, delegations, Purpose::Keep).await?;
    let challenge = ns.challenge().await?;
    let body = build_renew_request(id, ns.name(), ns.ns_did(), &challenge);
    ns.post_binding("/v1/renew", &body, &id.did_string())
        .await?
}

/// Build the POST /v1/renew body: the proof of control is bound to the renew
/// action, this nameserver, the full lowercased name and the challenge.
/// Factored out for unit testing.
pub(crate) fn build_renew_request(
    id: &Identity,
    name: &Name,
    ns_did: &str,
    challenge: &str,
) -> RenewRequestBody {
    let alias = name.as_alias();
    let proof = id.sign_name_proof(Action::Renew, ns_did, &alias, challenge);
    RenewRequestBody {
        alias,
        did: id.did_string(),
        challenge: challenge.to_string(),
        proof_of_control: b64u(&proof),
    }
}

// ============================================================================
// rotate
// ============================================================================

pub async fn rotate(ctx: &CliContext, args: KeysRotateArgs) -> Result<()> {
    // 1. Load the active identity (`--did` override or `[user] did`).
    let old_id = ctx.identity()?;
    let old_did_str = old_id.did_string();
    let keys_dir = jig_client::identity::default_keys_dir();
    // Checked before anything changes: once the nameserver has moved the
    // alias, failing to move the old key aside would leave cli.toml on it.
    let rotated = keys_dir.join(format!("{old_did_str}.jigkey.rotated"));
    if rotated.exists() {
        anyhow::bail!(
            "{} exists already; move it somewhere safe before rotating again",
            rotated.display()
        );
    }

    // 2. Mint a fresh keypair. This writes the new keyfile to disk.
    let new_id = Identity::create(&keys_dir, super::passphrase::key_access()?)
        .with_context(|| format!("generating new identity under {}", keys_dir.display()))?;
    let new_did_str = new_id.did_string();
    let new_keyfile = jig_client::identity::key_path(&keys_dir, &new_did_str);

    // 3. Drive the rotate handshake. If the nameserver never accepted it,
    //    undo the new keyfile so we don't leak an orphaned key. If it
    //    accepted but the reply doesn't verify, keep everything: the alias
    //    may already be bound to the new key.
    let delegations = crate::config::delegations(ctx.effective());
    let reply = match rotate_with_nameserver(
        &old_id,
        &new_id,
        &args.alias,
        &args.nameserver,
        &delegations,
    )
    .await
    {
        Ok(reply) => reply,
        Err(e) => {
            // Best-effort cleanup; ignore secondary errors.
            let _ = std::fs::remove_file(&new_keyfile);
            return Err(e);
        }
    };
    let attestation = reply.with_context(|| {
        format!(
            "the nameserver accepted the rotation, so {} may now point at {new_did_str}. \
             Both keyfiles are kept and [user] did still names {old_did_str}; check with \
             `jig ns resolve {}` before switching keys by hand (new keyfile: {})",
            args.alias,
            args.alias,
            new_keyfile.display()
        )
    })?;

    // 4. Rename the OLD keyfile to <old_did>.jigkey.rotated. Operator may
    //    want it for offline recovery. The rename keeps it on disk, still
    //    sealed, but out of the DID-load lookup path.
    let old_keyfile = jig_client::identity::key_path(&keys_dir, &old_did_str);
    let rotated_keyfile =
        jig_client::identity::retire_key(&keys_dir, &old_did_str).with_context(|| {
            format!(
                "moving {} aside after successful rotation",
                old_keyfile.display()
            )
        })?;

    // 5. Point the config file at the new DID. Start from the on-disk
    //    config so a one-shot `--server`/`--display-name` override isn't
    //    persisted as a side effect of rotating.
    let mut updated_cfg = ctx.file_config().clone();
    updated_cfg.user.did = new_did_str.clone();
    ctx.save_file_config(&updated_cfg)?;

    let ttl_days = (attestation.valid_until - attestation.valid_from) / 86_400;
    println!("rotated alias: {}", attestation.alias);
    println!(
        "  old DID: {old_did_str} (keyfile -> {})",
        rotated_keyfile.display()
    );
    println!(
        "  new DID: {new_did_str} (keyfile -> {})",
        new_keyfile.display()
    );
    println!("  ns={} valid {ttl_days}d", attestation.ns_did);
    Ok(())
}

/// Drive the challenge → dual-sign → rotate handshake. `Err` means the
/// nameserver did not accept the rotation; `Ok(Err(_))` means it accepted it
/// but its reply does not verify as an attestation for `new_id`.
pub async fn rotate_with_nameserver(
    old_id: &Identity,
    new_id: &Identity,
    alias: &str,
    ns_url: &str,
    delegations: &jig_client::naming::Delegations,
) -> Result<Result<Attestation>> {
    parse_full_name(alias)?;
    let ns = Nameserver::connect(ns_url, alias, delegations, Purpose::Keep).await?;
    let challenge = ns.challenge().await?;
    let body = build_rotate_request(old_id, new_id, &ns.name().as_alias(), &challenge);
    ns.post_binding("/v1/rotate", &body, &new_id.did_string())
        .await
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

/// Parse the full `alias@suffix` renew and rotate take.
fn parse_full_name(alias: &str) -> Result<Name> {
    Name::parse(alias).with_context(|| format!("`{alias}` is not a full alias@suffix"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use jig_core::naming;
    use tempfile::tempdir;

    #[test]
    fn build_renew_request_signs_an_action_bound_proof() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_for_tests(dir.path());
        let name = Name::parse("Alice_42@Dj.Jig").unwrap();
        let ns_did = "did:jig:zNameserver";

        let req = build_renew_request(&id, &name, ns_did, "deadbeef");

        assert_eq!(req.did, id.did_string());
        assert!(req.did.starts_with("did:jig:z"), "{}", req.did);
        assert_eq!(req.alias, "alice_42@dj.jig", "the full name, lowercased");
        assert_eq!(req.challenge, "deadbeef");

        let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&req.proof_of_control)
            .expect("proof_of_control is unpadded base64url");
        let check = |action, ns: &str, alias: &str| {
            naming::verify_proof(&req.did, &proof, action, ns, alias, "deadbeef")
        };
        check(Action::Renew, ns_did, "alice_42@dj.jig").expect("the proof verifies");
        assert!(
            check(Action::Register, ns_did, "alice_42@dj.jig").is_err(),
            "a renew proof is not a register proof"
        );
        assert!(check(Action::Renew, "did:jig:zOther", "alice_42@dj.jig").is_err());
        assert!(check(Action::Renew, ns_did, "Alice_42@Dj.Jig").is_err());
    }

    #[test]
    fn renew_and_rotate_refuse_a_name_without_a_suffix() {
        let err = parse_full_name("dj").unwrap_err();
        assert!(format!("{err:#}").contains("full alias@suffix"), "{err:#}");
    }

    #[test]
    fn build_rotate_request_signs_with_both_keys_and_pins_both_dids() {
        let dir = tempdir().unwrap();
        let old = Identity::generate_for_tests(dir.path());
        // Sleep is unnecessary — two separate generate calls produce
        // distinct keys with overwhelming probability.
        let new = Identity::generate_for_tests(dir.path());
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
        let old = Identity::generate_for_tests(dir.path());
        let new = Identity::generate_for_tests(dir.path());
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
