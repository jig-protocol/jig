//! `jig init` — Phase F1 of v0.0.2 hello-world.
//!
//! One-step onboarding:
//!   1. Generate a fresh ed25519 identity under `~/.jig/keys/<did>.key`.
//!   2. Write `~/.jig/cli.toml` (or the global `--config <path>`) binding
//!      the new DID to a nickname.
//!   3. Optionally `--request-alias <local> --nameserver <url>`: read the
//!      nameserver's delegation → GET `/v1/challenge` → sign an action-bound
//!      proof of control → POST `/v1/register` → verify the attestation.
//!
//! The nameserver wire-shape (`requested_alias` + `proof_of_control` +
//! `challenge`) is defined by `jig-nameserver::v0_0_2_register`. Keep
//! the field names in sync with that module.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use jig_client::Identity;
use jig_core::naming::{Action, Attestation, Name};
use serde::Serialize;

use crate::cmd::ns::{Nameserver, b64u};
use crate::config::{self, Config};

/// Parsed flags for `jig init`. Construct directly from `clap`-parsed args
/// in `main.rs`; this struct keeps the CLI surface and the implementation
/// decoupled for testability.
///
/// `init` is the one command that does NOT take a resolved
/// [`crate::cmd::common::CliContext`]: it *creates* the config file, so
/// requiring an existing one would be circular. It takes the two global
/// overrides that still apply — where to write, and what to write.
#[derive(Debug, Clone, Default)]
pub struct InitArgs {
    /// Optional nickname; defaults to `whoami::username()`.
    pub nickname: Option<String>,
    /// Overwrite the config file if it already exists.
    pub force: bool,
    /// Local part of an alias to request from a nameserver (e.g. `dj`).
    pub request_alias: Option<String>,
    /// Nameserver base URL (required when `request_alias` is set).
    pub nameserver: Option<String>,
    /// Config file to write. `None` means `~/.jig/cli.toml`; a `Some`
    /// value comes from the global `--config <path>` flag.
    pub config_path: Option<PathBuf>,
    /// `[server] base_url` to record. `None` keeps `Config::default()`'s
    /// `https://127.0.0.1:7117`; a `Some` value comes from `--server`.
    pub server_url: Option<String>,
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

pub async fn run(args: InitArgs) -> Result<()> {
    // 1. Refuse to clobber an existing config unless --force was passed.
    let cfg_path = args
        .config_path
        .clone()
        .unwrap_or_else(config::default_config_path);
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
    println!(
        "keyfile: {}",
        keys_dir.join(format!("{did_string}.key")).display()
    );

    // 3. Persist nickname + DID binding to ~/.jig/cli.toml.
    let nickname = args
        .nickname
        .clone()
        .unwrap_or_else(crate::config::os_username);
    write_cli_config(&id, &nickname, &cfg_path, args.server_url.as_deref())?;
    println!("wrote {} (nickname: {nickname})", cfg_path.display());

    // 3b. With no server of their own, offer the hub (dormant until its URL
    //     and DID are real; never without a terminal). Its DID is pinned
    //     before anything connects to it.
    if let Some(hub) = crate::cmd::hub::offer(args.server_url.is_some())? {
        let mut cfg = config::load_config(Some(&cfg_path))?;
        cfg.server.base_url = hub.url.clone();
        config::save_config(&cfg, Some(&cfg_path))
            .with_context(|| format!("writing {}", cfg_path.display()))?;
        crate::cmd::hub::pin(&hub, &jig_client::pins::Pins::default_path())?;
        println!("server: {} (pinned to {})", hub.url, hub.did);
    }

    // 4. Optional alias registration.
    if let Some(alias_local) = args.request_alias {
        let ns_url = args
            .nameserver
            .ok_or_else(|| anyhow!("--nameserver <url> is required with --request-alias"))?;
        let attestation = register_with_nameserver(&id, &alias_local, &ns_url).await?;
        let ttl_days = (attestation.valid_until - attestation.valid_from) / 86_400;
        println!(
            "alias attestation verified: {} (valid {ttl_days}d, ns={})",
            attestation.alias, attestation.ns_did
        );
    }

    Ok(())
}

/// Write the config file with the freshly generated DID and the
/// caller-supplied nickname. Default channel (and the server URL, unless
/// `--server` supplied one) comes from `Config::default()` so v0.0.2 stays
/// one-line-installable.
fn write_cli_config(
    id: &Identity,
    nickname: &str,
    cfg_path: &std::path::Path,
    server_url: Option<&str>,
) -> Result<()> {
    let cfg = build_initial_config(id, nickname, server_url);
    config::save_config(&cfg, Some(cfg_path))
        .with_context(|| format!("writing {}", cfg_path.display()))?;
    Ok(())
}

/// Build the first-run config for a freshly generated identity.
///
/// Split out from the file write so it can be unit-tested without touching
/// `~/.jig`. Seeds `[contacts]` with the operator's own DID so their own
/// messages render as their nickname from the very first `jig chat`, and
/// pins the `@jig` delegation this build ships (JEP-0004 `config` root) when
/// it has one, so a later binary with another default does not change whose
/// answers count. Nothing depends on that entry: without it the built-in
/// delegation applies. A build whose authority is still the placeholder
/// writes none.
fn build_initial_config(id: &Identity, nickname: &str, server_url: Option<&str>) -> Config {
    let mut cfg = Config::default();
    cfg.user.did = id.did_string();
    cfg.user.display_name = nickname.to_string();
    if let Some(url) = server_url {
        cfg.server.base_url = url.to_string();
    }
    config::remember_contact(&mut cfg, &id.did_string(), nickname);
    if let Ok(jig) = config::default_jig_delegation(&cfg) {
        cfg.naming
            .delegations
            .insert(config::DEFAULT_SUFFIX.to_string(), jig);
    }
    cfg
}

/// Register `alias_local` under the nameserver's suffix for `id`.
///
/// Returns the attestation once it verifies: signed by the nameserver's
/// delegated authority, for the lowercased `alias_local@suffix`, valid now,
/// and naming `id`'s DID.
pub async fn register_with_nameserver(
    id: &Identity,
    alias_local: &str,
    ns_url: &str,
) -> Result<Attestation> {
    let ns = Nameserver::connect(ns_url).await?;
    let name = Name::parse(&format!("{alias_local}@{}", ns.suffix()))
        .with_context(|| format!("`{alias_local}` is not a valid alias"))?;
    let challenge = ns.challenge().await?;
    let body = build_register_request(id, &name, ns.ns_did(), &challenge);
    ns.post_binding("/v1/register", &body, &name, &id.did_string())
        .await?
}

/// Build the POST /v1/register body: the proof of control is bound to the
/// register action, this nameserver, the full lowercased name and the
/// challenge (JEP-0004 rule 10). Factored out so unit tests can exercise the
/// signing step without an HTTP transport.
pub(crate) fn build_register_request(
    id: &Identity,
    name: &Name,
    ns_did: &str,
    challenge: &str,
) -> RegisterRequest {
    let proof = id.sign_name_proof(Action::Register, ns_did, &name.as_alias(), challenge);
    RegisterRequest {
        did: id.did_string(),
        requested_alias: name.alias.clone(),
        proof_of_control: b64u(&proof),
        challenge: challenge.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use jig_core::naming;
    use tempfile::tempdir;

    #[test]
    fn build_register_request_signs_an_action_bound_proof() {
        // Generate a fresh identity in a tempdir (separate from ~/.jig/keys/).
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        let name = Name::parse("DJ@Dj.Jig").unwrap();
        let ns_did = "did:jig:zNameserver";

        let req = build_register_request(&id, &name, ns_did, "deadbeef");

        assert_eq!(req.did, id.did_string(), "DID must match identity");
        assert!(req.did.starts_with("did:jig:z"), "{}", req.did);
        assert_eq!(req.requested_alias, "dj", "the local part, lowercased");
        assert_eq!(req.challenge, "deadbeef");

        // The proof verifies for exactly this action, nameserver, full name
        // and challenge, which is what jig-nameserver checks.
        let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&req.proof_of_control)
            .expect("proof_of_control is unpadded base64url");
        let check = |action, ns: &str, alias: &str, ch: &str| {
            naming::verify_proof(&req.did, &proof, action, ns, alias, ch)
        };
        check(Action::Register, ns_did, "dj@dj.jig", "deadbeef").expect("the proof verifies");
        assert!(check(Action::Renew, ns_did, "dj@dj.jig", "deadbeef").is_err());
        assert!(check(Action::Register, "did:jig:zOther", "dj@dj.jig", "deadbeef").is_err());
        assert!(check(Action::Register, ns_did, "dj", "deadbeef").is_err());
        assert!(check(Action::Register, ns_did, "dj@dj.jig", "other").is_err());
    }

    #[test]
    fn initial_config_records_the_local_user_as_a_contact() {
        // Seeding the address book with your own DID is what stops `jig chat`
        // rendering a 61-char DID for every line you write yourself.
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();

        let cfg = build_initial_config(&id, "dj", None);

        assert_eq!(cfg.user.did, id.did_string());
        assert_eq!(
            cfg.contacts.get(&id.did_string()).map(String::as_str),
            Some("dj"),
            "own DID must map to the chosen nickname: {:?}",
            cfg.contacts
        );
    }

    #[test]
    fn initial_config_pins_the_jig_delegation_this_build_ships() {
        // Tests build jig-core with `test-default-authority`; a real build
        // writes no entry while the authority is the placeholder.
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        let cfg = build_initial_config(&id, "dj", None);
        assert_eq!(
            cfg.naming.delegations.get(config::DEFAULT_SUFFIX),
            Some(&config::default_jig_delegation(&Config::default()).unwrap())
        );
    }

    #[test]
    fn initial_config_keeps_the_default_server_unless_overridden() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        assert_eq!(
            build_initial_config(&id, "dj", None).server.base_url,
            Config::default().server.base_url
        );
        assert_eq!(
            build_initial_config(&id, "dj", Some("wss://deji.jig.onl"))
                .server
                .base_url,
            "wss://deji.jig.onl"
        );
    }

    #[test]
    fn build_register_request_sends_the_local_part_without_the_suffix() {
        // The nameserver composes `<local>@<its suffix>`; the request names
        // only the local part, but the proof is over the full name.
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        let name = Name::parse("Alice_42@dj.jig").unwrap();
        let req = build_register_request(&id, &name, "did:jig:zNs", "abc");
        assert_eq!(req.requested_alias, "alice_42");
    }
}
