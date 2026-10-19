//! What this process trusts for a server: the DID this device pinned for it,
//! and the TLS certificate that DID vouches for ([`jig_client::tls`]).
//!
//! The first connection to an `https://` server in a process probes it once:
//! the DID it names must be the pinned one (or is pinned, on first contact),
//! and its certificate must be one that DID vouches for, or one a CA issued.
//! Every later REST and WSS connection in the process gets a config that
//! accepts that certificate and nothing else. A certificate the server rotated
//! is picked up by the next process, as long as the same DID vouches for it.
//!
//! Plaintext REST is refused, except to this machine (D11 item 10): nothing
//! ties a plaintext response to the pinned server, and any response may say
//! what a channel's suite is.

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
        refuse_remote_plaintext(server)?;
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

/// Refuse a plaintext server that is not on this machine. Loopback stays
/// allowed for local development; nothing on the wire leaves the host.
fn refuse_remote_plaintext(server: &str) -> Result<()> {
    let base = jig_client::tls::http_base(server)?;
    let host = url::Url::parse(&base)
        .ok()
        .and_then(|url| url.host().map(|host| host.to_owned()));
    let loopback = match host {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if loopback {
        return Ok(());
    }
    let tls_url = base.replacen("http://", "https://", 1);
    anyhow::bail!(
        "refusing plaintext {server}: over plaintext nothing ties an answer to the server this \
         device pinned. Use TLS: `jig server set {tls_url}`"
    )
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

#[cfg(test)]
mod tests {
    use super::refuse_remote_plaintext;

    #[test]
    fn plaintext_is_refused_except_on_this_machine() {
        for local in [
            "http://127.0.0.1:7117",
            "http://127.0.0.2:1",
            "http://localhost:7117",
            "http://[::1]:7117",
            "ws://127.0.0.1:7117",
        ] {
            assert!(refuse_remote_plaintext(local).is_ok(), "{local}");
        }
        for remote in [
            "http://example.com:7117",
            "http://10.0.0.5:7117",
            "ws://example.com",
        ] {
            let err = refuse_remote_plaintext(remote).unwrap_err().to_string();
            assert!(err.contains("jig server set https://"), "{remote}: {err}");
        }
    }
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
/// with the reason, both DIDs and the `jig trust accept-name` command that
/// moves the pin. Everything the resolution acted on is kept as evidence; a
/// failure to keep it fails the resolution. Warns when the pinned
/// attestation is close to expiring. Returns the resolver's verdict, after
/// pinning, so a caller can say "first contact" only on [`Verified::New`].
///
/// [`Verified::New`]: jig_client::naming::Verified::New
pub async fn verify_name(
    name: &str,
    delegations: &jig_client::naming::Delegations,
) -> Result<jig_client::naming::Verified> {
    use jig_client::naming::{NameResolver, ResolveError, Verified};
    let mut pins = Pins::load(&Pins::default_path())?;
    let evidence = jig_client::evidence::NameEvidenceDir::new(
        &jig_client::evidence::NameEvidenceDir::default_path(),
    );
    let verified = match NameResolver::new()
        .resolve(name, delegations, &pins, &evidence)
        .await
    {
        Ok(verified) => verified,
        Err(e) => {
            let hint = match &e {
                ResolveError::PinMismatch { new, .. } => Some(format!(
                    "if its holder confirms the change, `jig trust accept-name {name} --did {new}` \
                     moves the pin"
                )),
                _ => None,
            };
            let e = anyhow::Error::new(e);
            return Err(match hint {
                Some(hint) => e.context(hint),
                None => e,
            });
        }
    };
    let binding = match &verified {
        Verified::New(binding) | Verified::Pinned(binding) => {
            pins.pin_name(binding)?;
            binding
        }
        Verified::Rotated { binding, from } => {
            pins.accept_name(binding, binding.did())?;
            eprintln!(
                "note: {name} moved from {from} to {} along rotation links its old key signed.",
                binding.did()
            );
            binding
        }
    };
    warn_if_expiring(name, binding, chrono::Utc::now().timestamp());
    Ok(verified)
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
    let old = pins.accept_name(&binding, confirmed)?;
    warn_if_expiring(name, &binding, chrono::Utc::now().timestamp());
    Ok(old)
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
