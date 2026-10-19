//! What this process trusts for a server: the DID this device pinned for it,
//! and the TLS certificate that DID vouches for ([`jig_client::tls`]).
//!
//! The first connection to an `https://` server in a process probes it once:
//! the DID it names must be the pinned one (or is pinned, on first contact),
//! and its certificate must be one that DID vouches for, or one a CA issued.
//! Every later REST and WSS connection in the process gets a config that
//! accepts that certificate and nothing else. A certificate the server rotated
//! is picked up by the next process, as long as the same DID vouches for it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use jig_client::pins::Pins;
use jig_client::secure::server_key;
use jig_client::tls::{TlsError, probe};

type Config = Option<Arc<jig_client::tls::TlsConfig>>;

static PROBED: Mutex<Option<HashMap<String, Config>>> = Mutex::new(None);

/// The TLS config for connections to `server`: `None` over plaintext, which
/// has nothing to bind.
pub async fn server_tls(server: &str) -> Result<Config> {
    let key = server_key(server);
    if let Some(config) = PROBED
        .lock()
        .expect("probe cache lock")
        .get_or_insert_with(HashMap::new)
        .get(&key)
    {
        return Ok(config.clone());
    }
    let plaintext = !jig_client::tls::http_base(server)?.starts_with("https://");
    let config = if plaintext {
        hint_if_tls(server).await?;
        None
    } else {
        let mut pins = Pins::load(&Pins::default_path())?;
        let expected = pins.offer(server).pinned_server_did;
        let probed = probe(server, expected.as_deref())
            .await
            .map_err(|e| refusal(server, e))?;
        if let Some(did) = &probed.server_did {
            pins.check_server_did(server, did)?;
        }
        probed.config
    };
    PROBED
        .lock()
        .expect("probe cache lock")
        .get_or_insert_with(HashMap::new)
        .insert(key, config.clone());
    Ok(config)
}

/// A REST client for `server` that trusts what [`server_tls`] decided.
pub async fn http(server: &str, timeout: std::time::Duration) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(config) = server_tls(server).await? {
        builder = builder.use_preconfigured_tls(config.as_ref().clone());
    }
    builder.build().context("building HTTP client")
}

fn refusal(server: &str, e: TlsError) -> anyhow::Error {
    match e {
        TlsError::OtherServer { .. } => anyhow::anyhow!(
            "{e}. If its key really changed, `jig server forget {server}` drops the pin."
        ),
        e => e.into(),
    }
}

/// A configured `http://` URL for a server that has since turned TLS on
/// (the default) fails with a bare "connection closed". Say what to do.
async fn hint_if_tls(server: &str) -> Result<()> {
    let base = jig_client::tls::http_base(server)?;
    let plain = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .context("building HTTP client")?
        .get(format!("{base}/.well-known/jig"))
        .send()
        .await;
    let Err(e) = plain else {
        return Ok(());
    };
    if e.is_connect() || e.is_timeout() {
        // Down or unreachable: the command reports that in its own terms.
        return Ok(());
    }
    let tls_url = base.replacen("http://", "https://", 1);
    if probe(&tls_url, None).await.is_ok() {
        anyhow::bail!(
            "{server} serves TLS now; run `jig server set {tls_url}` to talk to it over TLS"
        );
    }
    Ok(())
}

/// A name's delegation as given on the command line: the nameservers to ask
/// and the authorities whose attestations count. Without any, the suffix's
/// delegation is discovered over `dns`.
pub fn delegations_for(
    name: &str,
    nameservers: Vec<String>,
    authorities: Vec<String>,
) -> Result<jig_client::naming::Delegations> {
    let mut delegations = jig_client::naming::Delegations::default();
    if nameservers.is_empty() && authorities.is_empty() {
        return Ok(delegations);
    }
    anyhow::ensure!(
        !nameservers.is_empty() && !authorities.is_empty(),
        "a delegation needs both --nameserver and --authority"
    );
    let suffix = jig_core::naming::Name::parse(name)?.suffix;
    delegations.config.insert(
        suffix,
        jig_client::naming::ConfigDelegation {
            authorities,
            nameservers,
        },
    );
    Ok(delegations)
}

/// Resolve `name` and hold it to this device's pin (JEP-0004 rule 17): a new
/// name is pinned, a pinned one must still match, and a change is refused
/// with the reason and both DIDs. Everything the resolution acted on is kept
/// as evidence. Warns when the pinned attestation is close to expiring.
pub async fn verify_name(
    name: &str,
    delegations: &jig_client::naming::Delegations,
) -> Result<jig_client::naming::Binding> {
    use jig_client::naming::{NameResolver, Verified};
    let mut pins = Pins::load(&Pins::default_path())?;
    let evidence = jig_client::evidence::NameEvidenceDir::new(
        &jig_client::evidence::NameEvidenceDir::default_path(),
    );
    let binding = match NameResolver::new()
        .resolve(name, delegations, &pins, &evidence)
        .await?
    {
        Verified::New(binding) | Verified::Pinned(binding) => {
            pins.pin_name(&binding)?;
            binding
        }
        Verified::Rotated { binding, from } => {
            pins.accept_name(&binding, binding.did())?;
            eprintln!(
                "note: {name} moved from {from} to {} along rotation links its old key signed.",
                binding.did()
            );
            binding
        }
    };
    warn_if_expiring(name, &binding, chrono::Utc::now().timestamp());
    Ok(binding)
}

/// Move `name`'s pin to `confirmed`, the DID its holder confirmed out of
/// band (rule 9). The name is resolved afresh and must attest exactly that
/// DID. Returns the DID it was pinned to before.
pub async fn accept_name(
    name: &str,
    confirmed: &str,
    delegations: &jig_client::naming::Delegations,
) -> Result<Option<String>> {
    use jig_client::naming::{NameResolver, Verified};
    // Resolve as if nothing were pinned: the point is to replace the pin.
    struct Unpinned;
    impl jig_client::naming::NamePins for Unpinned {
        fn name_pin(&self, _: &jig_client::naming::NameKey) -> Option<jig_client::naming::NamePin> {
            None
        }
    }
    let evidence = jig_client::evidence::NameEvidenceDir::new(
        &jig_client::evidence::NameEvidenceDir::default_path(),
    );
    let binding = match NameResolver::new()
        .resolve(name, delegations, &Unpinned, &evidence)
        .await?
    {
        Verified::New(b) | Verified::Pinned(b) | Verified::Rotated { binding: b, .. } => b,
    };
    let mut pins = Pins::load(&Pins::default_path())?;
    Ok(pins.accept_name(&binding, confirmed)?)
}

/// How long before an attestation expires the CLI starts saying so.
const EXPIRY_WARNING_SECS: i64 = 7 * 24 * 3600;

fn warn_if_expiring(name: &str, binding: &jig_client::naming::Binding, now: i64) {
    if let Some(message) = expiry_warning(name, binding.attestation.valid_until, now) {
        eprintln!("warning: {message}");
    }
}

fn expiry_warning(name: &str, valid_until: i64, now: i64) -> Option<String> {
    let left = valid_until - now;
    (left < EXPIRY_WARNING_SECS).then(|| {
        format!(
            "{name}'s attestation expires in {} day(s); its holder should renew it, or it stops \
             resolving",
            left.max(0) / (24 * 3600)
        )
    })
}

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn an_attestation_near_expiry_is_warned_about() {
        let day = 24 * 3600;
        assert!(expiry_warning("alice@example.org", 30 * day, 0).is_none());
        let soon = expiry_warning("alice@example.org", 3 * day, 0).unwrap();
        assert!(soon.contains("3 day"), "{soon}");
    }

    #[test]
    fn a_delegation_needs_both_halves() {
        assert!(
            delegations_for("alice@example.org", vec![], vec![])
                .unwrap()
                .config
                .is_empty()
        );
        assert!(delegations_for("alice@example.org", vec!["https://ns".into()], vec![]).is_err());
        let d = delegations_for(
            "alice@example.org",
            vec!["https://ns".into()],
            vec!["did:jig:zNs".into()],
        )
        .unwrap();
        assert_eq!(d.config["example.org"].authorities, ["did:jig:zNs"]);
    }
}
