//! How the server reaches the nameservers `[identity.delegations]` lists.
//!
//! A nameserver serves TLS with a certificate its DID vouches for in
//! `/.well-known/jig-ns` (JEP-0004 rule 12). The server accepts a nameserver
//! only over TLS bound to one of its suffix's authorities
//! ([`jig_client::tls::probe_bound`]): a CA's word for the host counts for
//! nothing, since getting a CA certificate for a host does not make anyone an
//! authority for a suffix. `http://` nameservers are refused unless
//! `[identity] dangerously_allow_plaintext_nameservers` is set, for loopback
//! or local testing.

use async_trait::async_trait;
use jig_pipeline::identity::{NameserverTransport, nameserver_client_builder, plaintext_client};

/// Where a nameserver publishes its DID and the binding for its certificate.
const NS_WELL_KNOWN: &str = "/.well-known/jig-ns";

/// The server's [`NameserverTransport`].
pub struct BoundNameservers {
    /// `[identity] dangerously_allow_plaintext_nameservers`.
    pub allow_plaintext: bool,
}

#[async_trait]
impl NameserverTransport for BoundNameservers {
    async fn client(
        &self,
        ns_url: &str,
        authorities: &[String],
    ) -> Result<reqwest::Client, String> {
        let base = jig_client::tls::http_base(ns_url).map_err(|e| e.to_string())?;
        if base.starts_with("http://") {
            return if self.allow_plaintext {
                Ok(plaintext_client())
            } else {
                Err(format!(
                    "{ns_url} is plaintext; set [identity] \
                     dangerously_allow_plaintext_nameservers only for loopback or local testing"
                ))
            };
        }
        let probed = jig_client::tls::probe_bound(&base, NS_WELL_KNOWN, authorities)
            .await
            .map_err(|e| e.to_string())?;
        let config = probed.config.expect("a bound probe over TLS has a config");
        nameserver_client_builder()
            .use_preconfigured_tls(config.as_ref().clone())
            .build()
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plaintext_is_refused_unless_allowed() {
        let refused = BoundNameservers {
            allow_plaintext: false,
        }
        .client("http://127.0.0.1:1", &["did:jig:zA".into()])
        .await
        .unwrap_err();
        assert!(refused.contains("plaintext"), "{refused}");

        BoundNameservers {
            allow_plaintext: true,
        }
        .client("http://127.0.0.1:1", &["did:jig:zA".into()])
        .await
        .expect("allowed: a client, nothing sent yet");
    }
}
