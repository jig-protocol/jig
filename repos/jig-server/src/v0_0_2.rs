//! v0.0.2 hello-world milestone — additive layer wiring jig-pipeline + jig-client
//! into jig-server without touching the existing handler tree.
//!
//! `AppState` is the boot context Phase D2-D6 will hand to NEW axum routes
//! (under `/api/v1/*`). Existing v0.0.1 routes
//! (defined in `handler.rs`, `server.rs`, `websocket/`, `federation/`,
//! etc.) keep their own state and are unaffected by this module.
//!
//! When Phase F's new `jig-cli` commands hit the new routes via WSS,
//! they reach jig-pipeline's `ingest()` pipeline (Task B6). The existing
//! /blocks HTTP routes stay alive for backward compat until Phase F+
//! retires them.

use crate::runtime::ExecutionConfig;
use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use jig_client::server_key::ServerKeyOptions;
use jig_config::v0_0_2_server::{IdentityMode, IdentitySection, JigServerConfig, NameDelegation};
use jig_core::Did;
use jig_pipeline::{
    executor::{BlockExecutor, text_block_program},
    fanout::Fanout,
    hlc::HlcClock,
    identity::{IdentityResolver, NameserverResolver, TofuResolver},
    ingest::IngestContext,
    persist::SqliteStore,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Boot state for the v0.0.2 pipeline-driven request handlers. Constructed
/// once at server start; cloned cheaply (everything is `Arc` inside).
#[derive(Clone)]
pub struct AppState {
    pub config: JigServerConfig,
    pub ingest_ctx: Arc<IngestContext>,
    pub server_did: Did,
    pub server_url: String,
    /// v0.0.3: bridge load-time policy gate + lifecycle owner. Populated
    /// from `config.bridges`; no bridges actually registered in alpha.1a
    /// (alpha.email is the first real registrant).
    pub bridges: Arc<crate::v0_0_2_bridges::BridgeRegistry>,
    /// v0.0.3 (alpha.email): shared collector for bridge-contributed HTTP
    /// routes. `build_v0_0_2_router` drains it and nests each under
    /// `/_bridge/<name>/`. A bridge mounts into it during `start()` via its
    /// `BridgeContext::mount_router`. Empty until PR2 registers a real bridge
    /// in the boot path.
    pub bridge_router_mount: jig_bridge_core::RouterMount,
    /// Authentication state, shared by every clone of this struct.
    ///
    /// `Arc` is load-bearing: the replay guard defends by remembering nonces,
    /// so all clones must share ONE guard. If each clone owned its own, a
    /// replayed request landing on a different clone would find an empty set
    /// and be accepted. See `crate::auth::state`.
    pub auth: Arc<crate::auth::AuthState>,
    /// The server DID's word for the TLS certificate this server serves, set
    /// once the listener has its certificate ([`Self::bind_tls_certificate`])
    /// and published at `/.well-known/jig`. Shared by every clone.
    pub tls_binding: Arc<std::sync::OnceLock<jig_core::tls_binding::TlsBinding>>,
    /// The `server-manifest` every welcome cites, once
    /// [`crate::v0_0_2_manifest_log::publish`] has run. Shared by every clone.
    pub manifest: Arc<std::sync::RwLock<Option<jig_pipeline::handshake::ManifestRef>>>,
    /// During a key change: the public link from this server's old DID to
    /// its current one (JEP-0012), served in every welcome and at
    /// `/.well-known/jig`, so clients and peers that pinned the old DID
    /// follow it. Read from [`key_link_path`] at boot.
    pub key_link: Option<Vec<u8>>,
    /// What handles frames between proven peers
    /// ([`crate::v0_0_2_peer::PeerFrames`]), set once at boot by
    /// [`Self::set_peer_frames`]. Shared by every clone.
    pub peer_frames: Arc<std::sync::OnceLock<Arc<dyn crate::v0_0_2_peer::PeerFrames>>>,
    /// The live connections to proven peers, whichever side dialed.
    pub peers: Arc<crate::v0_0_2_peer::PeerRegistry>,
}

/// Where the server's key link is read from: beside its key file, with
/// `.link` appended, where `jig-server keys rotate` and `keys link` write it
/// ([`jig_client::server_key::key_link_path`]).
pub fn key_link_path(keyfile: &std::path::Path) -> PathBuf {
    jig_client::server_key::key_link_path(keyfile)
}

/// The key link at `path`, if there is one. A link that does not verify, is
/// not public, or does not move to `server_did` is a boot error: serving it
/// would make every client that pinned the old DID refuse this server.
fn load_key_link(path: &std::path::Path, server_did: &Did) -> Result<Option<Vec<u8>>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", path.display())),
    };
    let signed = jig_core::key_link::SignedKeyLink::from_envelope(&bytes)
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    let link = signed.link();
    anyhow::ensure!(
        link.audience == jig_core::key_link::Audience::Public,
        "{}: the key link is not a public one",
        path.display()
    );
    anyhow::ensure!(
        // Exactly, as clients compare it (`handshake::link_moves`).
        link.new == server_did.to_did_jig_string(),
        "{}: the key link moves to {}, not to this server's DID",
        path.display(),
        link.new
    );
    tracing::info!(from = %link.old, "serving the key link from this server's old DID");
    Ok(Some(bytes))
}

/// Gates 1 and 2 from `[auth]`, plus the federation peers from `[federation]`:
/// listing a peer is what lets its DID subscribe to this server's stream.
///
/// Every `AppState` constructor goes through here, so this is also where a
/// peer that must not be dialed — a `ws://` URL without
/// `dangerously_allow_plaintext_federation` — becomes a boot error, as does a
/// peer policy the server manifest must not publish.
fn build_auth(
    config: &JigServerConfig,
    store: Arc<SqliteStore>,
) -> anyhow::Result<Arc<crate::auth::AuthState>> {
    crate::v0_0_2_federation::check_federation_transport(&config.federation)?;
    config.federation.validate().map_err(anyhow::Error::msg)?;
    check_published_peer_dids(&config.federation)?;
    let auth = crate::auth::AuthState::from_config(&config.auth)?.with_proofs(store);
    for (i, peer) in config.federation.peers.iter().enumerate() {
        auth.trust_federation_peer(&peer.expected_did)
            .with_context(|| format!("[federation] peers[{i}].expected_did"))?;
    }
    Ok(Arc::new(auth))
}

/// A published peer's DID goes into the signed manifest as written, so it
/// must be the canonical spelling: two spellings of one key would list the
/// peer twice and match neither consistently.
fn check_published_peer_dids(
    federation: &jig_config::v0_0_2_server::FederationSection,
) -> anyhow::Result<()> {
    for (i, peer) in federation
        .peers
        .iter()
        .enumerate()
        .filter(|(_, p)| p.publish)
    {
        // A re-cased spelling no longer parses strictly, so name the key's
        // canonical DID from the lenient reading of what the operator wrote.
        let Ok(canonical) = Did::canonicalize(&peer.expected_did).map(|d| d.to_did_jig_string())
        else {
            continue;
        };
        if canonical != peer.expected_did {
            anyhow::bail!(
                "[federation] peers[{i}].expected_did: a published peer's DID must be canonical: `{canonical}`"
            );
        }
    }
    Ok(())
}

/// Translate the operator's server-level execution settings into the runtime's
/// own config type.
///
/// Kept as a named function rather than inlined so the mapping is one visible
/// place: a limit added on either side that is not wired here is the same class
/// of silent divergence this exists to remove.
pub(crate) fn runtime_config_from(execution: &ExecutionConfig) -> jig_runtime::RuntimeConfig {
    jig_runtime::RuntimeConfig {
        // Enumerated rather than assigned onto a default, and deliberately: a
        // limit added to `ResourceLimits` should break this build so somebody
        // decides whether operators can set it, instead of it silently taking a
        // default here.
        limits: jig_runtime::config::ResourceLimits {
            fuel_max: execution.fuel_max,
            memory_max_mb: execution.memory_max_mb,
            execution_timeout_ms: execution.timeout_ms,
            // Per-execution instance cap, not a concurrency knob — no operator
            // setting maps to it, and conflating the two is what once capped the
            // engine at a single simultaneous execution.
            max_instances: 1,
            max_concurrent_instances: execution.max_concurrent_executions,
        },
        ..Default::default()
    }
}

/// `[server] max_future_skew_ms`, refused outside the protocol's range
/// (JEP-0002 rule 13) so a server cannot boot advertising an unbounded clock.
fn checked_skew_bound(config: &JigServerConfig) -> Result<u64> {
    let skew = config.server.max_future_skew_ms;
    let range =
        jig_pipeline::handshake::MIN_FUTURE_SKEW_MS..=jig_pipeline::handshake::MAX_FUTURE_SKEW_MS;
    if !range.contains(&skew) {
        anyhow::bail!(
            "[server] max_future_skew_ms = {skew} is outside the protocol's {}..={} ms",
            range.start(),
            range.end()
        );
    }
    Ok(skew)
}

/// `[identity]`, refused when a suffix is both delegated and refused.
/// `ServerConfig::load` already checked a loaded config; one built in code
/// has not been.
fn checked_identity(config: &JigServerConfig) -> Result<()> {
    config.identity.validate().map_err(anyhow::Error::msg)
}

impl AppState {
    /// Register the handler for peer frames. Only the first call counts;
    /// returns whether this one did.
    pub fn set_peer_frames(&self, handler: Arc<dyn crate::v0_0_2_peer::PeerFrames>) -> bool {
        self.peer_frames.set(handler).is_ok()
    }

    /// The registered peer-frame handler, if any.
    pub fn peer_frame_handler(&self) -> Option<&dyn crate::v0_0_2_peer::PeerFrames> {
        self.peer_frames.get().map(|h| h.as_ref())
    }

    /// Vouch, with the server DID's key, for the certificate the listener
    /// serves (DER), so clients can trust it without a CA. The first call
    /// wins; the certificate does not change while the server runs.
    pub fn bind_tls_certificate(&self, cert_der: &[u8]) {
        let _ = self.tls_binding.get_or_init(|| {
            jig_core::tls_binding::TlsBinding::sign(&self.ingest_ctx.server_key, cert_der)
        });
    }

    /// Build the AppState from a parsed JigServerConfig and a SQLite path.
    /// Generates the server signing key if the configured keyfile is absent;
    /// loads it otherwise. On Unix the keyfile is set to mode 0600 on
    /// generation.
    ///
    /// `execution` carries the operator's `[execution]` limits, which live on
    /// `ServerConfig` rather than in the `JigServerConfig` sections. Passing
    /// them explicitly is what makes the ingest render path honour
    /// configured fuel, memory, timeout and concurrency instead of running on
    /// library defaults.
    pub fn new(
        config: JigServerConfig,
        db_path: PathBuf,
        execution: ExecutionConfig,
    ) -> Result<Self> {
        let store = Arc::new(SqliteStore::open(&db_path).context("opening SqliteStore")?);
        let signing_key =
            load_or_generate_server_key(&config).context("loading server signing key")?;
        // Before anything logs a DID: tags are keyed by this server's seed.
        if !jig_core::did::set_log_tag_key(&signing_key.to_bytes()) {
            tracing::warn!(
                "a different log tag key is already in effect in this process; DID tags keep using it"
            );
        }
        let server_did = Did::from_ed25519_pubkey(signing_key.verifying_key().as_bytes());
        let key_link = load_key_link(
            &key_link_path(Path::new(
                shellexpand::tilde(&config.server.server_did_keyfile).as_ref(),
            )),
            &server_did,
        )?;
        // A store written before `ingest` records existed is sequenced once,
        // here: each local channel's chain starts at its channel-create and
        // follows the old history order (JEP-0002 rule 9).
        let backfilled = store
            .backfill_ingest_records(&signing_key)
            .context("sequencing stored blocks")?;
        if backfilled > 0 {
            tracing::info!(backfilled, "gave stored blocks their ingest records");
        }
        // Channels from before channel terms (JEP-0005 rules 5-6) were all
        // this server's: they take its DID as their sequencer, here, where
        // the key is known. The migration could only mark them "this server".
        let adopted = store
            .adopt_local_sequencer(&server_did.to_did_jig_string())
            .context("recording this server as its channels' sequencer")?;
        if adopted > 0 {
            tracing::info!(
                adopted,
                "recorded this server as the sequencer of stored channels"
            );
        }

        checked_identity(&config)?;
        let identity: Arc<dyn IdentityResolver> = match config.identity.mode {
            IdentityMode::Tofu => Arc::new(TofuResolver::new(store.clone())),
            IdentityMode::Nameserver => {
                if !config.identity.trusted_nameservers.is_empty() {
                    tracing::warn!(
                        "identity.trusted_nameservers is not used to resolve aliases; \
                         list each suffix's authorities and nameservers under \
                         [identity.delegations]"
                    );
                }
                Arc::new(nameserver_resolver(
                    &config.identity,
                    jig_core::naming::default_jig_authority(),
                    store.clone(),
                    Arc::new(crate::v0_0_2_nameserver_tls::BoundNameservers {
                        allow_plaintext: config.identity.dangerously_allow_plaintext_nameservers,
                    }),
                ))
            }
        };

        let hlc_clock = Arc::new(
            HlcClock::new(server_did.clone()).with_max_future_skew_ms(checked_skew_bound(&config)?),
        );
        let fanout = Arc::new(Fanout::new());
        let server_url = format!("ws://{}", config.server.listen);

        let naively_allow_unknown_handles_fallback =
            config.identity.naively_allow_unknown_handles_fallback;

        // The server owns its executor rather than taking the process-wide test
        // one, so a module compile failure is reported through this function's
        // `Result` instead of aborting the process.
        //
        // Limits come from the operator's `[execution]` settings, which live on
        // `ServerConfig`, outside the `JigServerConfig` sections, so they are
        // passed in rather than read from `config`. Without this the
        // ingest render path ran on library defaults and silently ignored every
        // configured limit.
        //
        // Deliberately NOT solved by adding an `[execution]` section to
        // `JigServerConfig`: both types would then parse the same TOML table under
        // different key names (`timeout_ms` here, `execution_timeout_ms` in
        // jig-config's own type), so one would silently fall back to its default.
        //
        // The server signs text-block's program manifest and its default operator
        // policy here (JEP-0011 §5.1). Who should author built-in manifests (each
        // server, or one project key) is still open, so the author key is a parameter
        // of `text_block_program`.
        let runtime_config = runtime_config_from(&execution);
        let program = text_block_program(&signing_key, &runtime_config)
            .context("signing text-block's program manifest")?;
        let executor = Arc::new(
            BlockExecutor::with_config(runtime_config, &signing_key, program)
                .context("compiling the canonical text-render component")?,
        );

        // Built before the ingest context so gate 2 can be installed on it;
        // `config` is moved into the struct literal below.
        let auth = build_auth(&config, store.clone())?;

        let ingest_ctx = Arc::new(IngestContext {
            store,
            identity,
            admission: auth.clone(),
            hlc_clock,
            allowed_block_kinds: config.server.allowed_block_kinds.clone(),
            server_did: server_did.clone(),
            server_key: signing_key,
            fanout,
            server_url: server_url.clone(),
            naively_allow_unknown_handles_fallback,
            executor: Some(executor),
        });

        let bridges = Arc::new(crate::v0_0_2_bridges::BridgeRegistry::new(&config));

        Ok(Self {
            config,
            ingest_ctx,
            server_did,
            server_url,
            bridges,
            bridge_router_mount: jig_bridge_core::RouterMount::new(),
            auth,
            tls_binding: Default::default(),
            manifest: Default::default(),
            key_link,
            peer_frames: Default::default(),
            peers: Default::default(),
        })
    }

    /// Convenience constructor for tests: in-memory SQLite, supplied config,
    /// freshly generated keypair (never written to disk). Mirrors `for_test`
    /// but uses the provided config so callers can test non-default settings
    /// (e.g. bridge policy, feature flags).
    #[cfg(test)]
    pub fn for_test_with_config(config: JigServerConfig) -> Result<Self> {
        let store = Arc::new(SqliteStore::open_in_memory()?);
        let secret: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&secret);
        let server_did = Did::from_ed25519_pubkey(signing_key.verifying_key().as_bytes());

        checked_identity(&config)?;
        let identity: Arc<dyn IdentityResolver> = Arc::new(TofuResolver::new(store.clone()));
        let hlc_clock = Arc::new(
            HlcClock::new(server_did.clone()).with_max_future_skew_ms(checked_skew_bound(&config)?),
        );
        let fanout = Arc::new(Fanout::new());
        let server_url = format!("ws://{}", config.server.listen);

        let naively_allow_unknown_handles_fallback =
            config.identity.naively_allow_unknown_handles_fallback;

        // Built before the ingest context so gate 2 can be installed on it;
        // `config` is moved into the struct literal below.
        let auth = build_auth(&config, store.clone())?;

        let ingest_ctx = Arc::new(IngestContext {
            store,
            identity,
            admission: auth.clone(),
            hlc_clock,
            allowed_block_kinds: config.server.allowed_block_kinds.clone(),
            server_did: server_did.clone(),
            server_key: signing_key,
            fanout,
            server_url: server_url.clone(),
            naively_allow_unknown_handles_fallback,
            executor: Some(BlockExecutor::shared()),
        });

        let bridges = Arc::new(crate::v0_0_2_bridges::BridgeRegistry::new(&config));

        Ok(Self {
            config,
            ingest_ctx,
            server_did,
            server_url,
            bridges,
            bridge_router_mount: jig_bridge_core::RouterMount::new(),
            auth,
            tls_binding: Default::default(),
            manifest: Default::default(),
            key_link: None,
            peer_frames: Default::default(),
            peers: Default::default(),
        })
    }

    /// Convenience constructor for tests: in-memory SQLite, defaults config,
    /// freshly generated keypair (never written to disk).
    #[cfg(test)]
    pub fn for_test() -> Result<Self> {
        let store = Arc::new(SqliteStore::open_in_memory()?);
        let secret: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&secret);
        let server_did = Did::from_ed25519_pubkey(signing_key.verifying_key().as_bytes());

        let identity: Arc<dyn IdentityResolver> = Arc::new(TofuResolver::new(store.clone()));
        let hlc_clock = Arc::new(HlcClock::new(server_did.clone()));
        let fanout = Arc::new(Fanout::new());
        let config = JigServerConfig::default();
        let server_url = format!("ws://{}", config.server.listen);

        let naively_allow_unknown_handles_fallback =
            config.identity.naively_allow_unknown_handles_fallback;

        // Built before the ingest context so gate 2 can be installed on it;
        // `config` is moved into the struct literal below.
        let auth = build_auth(&config, store.clone())?;

        let ingest_ctx = Arc::new(IngestContext {
            store,
            identity,
            admission: auth.clone(),
            hlc_clock,
            allowed_block_kinds: config.server.allowed_block_kinds.clone(),
            server_did: server_did.clone(),
            server_key: signing_key,
            fanout,
            server_url: server_url.clone(),
            naively_allow_unknown_handles_fallback,
            executor: Some(BlockExecutor::shared()),
        });

        let bridges = Arc::new(crate::v0_0_2_bridges::BridgeRegistry::new(&config));

        Ok(Self {
            config,
            ingest_ctx,
            server_did,
            server_url,
            bridges,
            bridge_router_mount: jig_bridge_core::RouterMount::new(),
            auth,
            tls_binding: Default::default(),
            manifest: Default::default(),
            key_link: None,
            peer_frames: Default::default(),
            peers: Default::default(),
        })
    }
}

/// Load the server's signing key from `[server] server_did_keyfile`, or make
/// and seal one if there is none, opening it as `[keys]` says
/// ([`jig_client::server_key`]). The path supports `~` expansion.
fn load_or_generate_server_key(config: &JigServerConfig) -> Result<SigningKey> {
    let path = shellexpand::tilde(&config.server.server_did_keyfile).into_owned();
    Ok(jig_client::server_key::load_or_create(
        Path::new(&path),
        &key_options(&config.keys),
    )?)
}

/// How `jig-server` opens its key, from `[keys]`.
pub fn key_options(keys: &jig_config::v0_0_2_server::KeysSection) -> ServerKeyOptions {
    let mut opts = ServerKeyOptions::new("server", "jig-server");
    opts.unlock = keys.unlock.clone();
    opts.plaintext = keys.storage == jig_config::v0_0_2_server::KeyStorage::Plaintext;
    opts
}

/// `[identity.delegations]` as the pipeline's resolver takes it.
pub fn suffix_authorities(
    delegations: &std::collections::BTreeMap<String, jig_config::v0_0_2_server::NameDelegation>,
) -> std::collections::BTreeMap<String, jig_pipeline::identity::SuffixAuthority> {
    delegations
        .iter()
        .map(|(suffix, d)| {
            (
                suffix.clone(),
                jig_pipeline::identity::SuffixAuthority {
                    authorities: d.authorities.clone(),
                    nameservers: d.nameservers.clone(),
                },
            )
        })
        .collect()
}

/// The resolver `[identity] mode = "nameserver"` boots with: the configured
/// delegations plus the built-in `@jig` one, and the refused suffixes, which
/// it logs. They are listed only here, in the operator's log: what a server
/// refuses is its own policy, not something `/.well-known/jig` advertises.
fn nameserver_resolver(
    identity: &IdentitySection,
    authority: Result<&str, jig_core::naming::NamingError>,
    store: Arc<SqliteStore>,
    transport: Arc<dyn jig_pipeline::identity::NameserverTransport>,
) -> NameserverResolver {
    let refused = identity.refused();
    if !refused.is_empty() {
        tracing::info!(
            "identity.refused_suffixes: aliases under {} are refused",
            refused.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    let (delegations, warning) =
        with_default_delegation(identity.delegations.clone(), &refused, authority);
    if let Some(warning) = warning {
        tracing::warn!("{warning}");
    }
    NameserverResolver::new(
        suffix_authorities(&delegations),
        refused,
        identity.cache_ttl_seconds,
        store,
        transport,
    )
}

/// `[identity.delegations]` plus the built-in delegation for
/// `jig_core::naming::DEFAULT_SUFFIX`, when the config neither has nor
/// refuses one for it and this build has a real authority:
/// `jig → {authorities: [DEFAULT_JIG_AUTHORITY],
/// nameservers: [DEFAULT_JIG_NAMESERVER]}`. An operator overrides it with their
/// own `[identity.delegations.jig]`. While the authority is the placeholder
/// nothing is added and boot carries on; `@jig` names then fail closed at
/// lookup, like any suffix without a delegation.
///
/// Also returns the one boot warning the result calls for, judged on the
/// delegations that will actually be used: none at all, or none for `@jig`.
fn with_default_delegation(
    mut delegations: BTreeMap<String, NameDelegation>,
    refused: &BTreeSet<String>,
    authority: Result<&str, jig_core::naming::NamingError>,
) -> (BTreeMap<String, NameDelegation>, Option<String>) {
    use jig_core::naming::{DEFAULT_JIG_NAMESERVER, DEFAULT_SUFFIX};
    if delegations.contains_key(DEFAULT_SUFFIX) {
        return (delegations, None);
    }
    if refused.contains(DEFAULT_SUFFIX) {
        // The operator asked for this; say only what it adds up to.
        let warning = delegations.is_empty().then(|| {
            "identity.mode = \"nameserver\" with no [identity.delegations], and \
             `jig` refused: every alias will be refused"
                .to_string()
        });
        return (delegations, warning);
    }
    match authority {
        Ok(authority) => {
            delegations.insert(
                DEFAULT_SUFFIX.to_string(),
                NameDelegation {
                    authorities: vec![authority.to_string()],
                    nameservers: vec![DEFAULT_JIG_NAMESERVER.to_string()],
                },
            );
            (delegations, None)
        }
        Err(e) if delegations.is_empty() => (
            delegations,
            Some(format!(
                "identity.mode = \"nameserver\" with no [identity.delegations], and no \
                 built-in `@{DEFAULT_SUFFIX}` delegation ({e}): every alias will be refused"
            )),
        ),
        Err(e) => (
            delegations,
            Some(format!(
                "no built-in [identity.delegations.{DEFAULT_SUFFIX}]: {e}; `@{DEFAULT_SUFFIX}` \
                 aliases are refused unless the config delegates the suffix"
            )),
        ),
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_published_peer_needs_a_canonical_did() {
        let mut config = crate::v0_0_2_manifest_log::tests::policy_config();
        assert!(super::check_published_peer_dids(&config.federation).is_ok());
        let canonical = config.federation.peers[0].expected_did.clone();
        let body = canonical.strip_prefix("did:jig:z").unwrap();
        // Still parses (the body decodes case-insensitively), but isn't canonical.
        config.federation.peers[0].expected_did = format!("did:jig:z{}", body.to_uppercase());
        let err = super::check_published_peer_dids(&config.federation).unwrap_err();
        assert!(err.to_string().contains(&canonical), "{err}");
        // An unpublished peer's spelling isn't published, so it's left alone.
        config.federation.peers[0].publish = false;
        assert!(super::check_published_peer_dids(&config.federation).is_ok());
    }

    #[test]
    fn a_key_link_beside_the_key_is_served_only_if_it_moves_to_this_server() {
        use jig_core::key_link::{Audience, SignedKeyLink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key.link");
        let (old, new) = (
            jig_core::crypto::ed25519::generate_signing_key(),
            jig_core::crypto::ed25519::generate_signing_key(),
        );
        let server_did = Did::from_ed25519_pubkey(new.verifying_key().as_bytes());
        assert_eq!(
            load_key_link(&path, &server_did).unwrap(),
            None,
            "no file, no link"
        );
        assert_eq!(
            key_link_path(Path::new("/k/server.key")),
            Path::new("/k/server.key.link")
        );

        let good = SignedKeyLink::sign(&old, &new, Audience::Public, 1).unwrap();
        std::fs::write(&path, good.envelope()).unwrap();
        assert_eq!(
            load_key_link(&path, &server_did).unwrap().as_deref(),
            Some(good.envelope())
        );
        let elsewhere = SignedKeyLink::sign(&new, &old, Audience::Public, 1).unwrap();
        std::fs::write(&path, elsewhere.envelope()).unwrap();
        assert!(
            load_key_link(&path, &server_did).is_err(),
            "moves to another DID"
        );
        std::fs::write(&path, b"not a link").unwrap();
        assert!(load_key_link(&path, &server_did).is_err());
    }

    #[test]
    fn the_built_in_jig_delegation_is_added_only_with_a_real_authority() {
        use super::*;
        use jig_core::naming::{DEFAULT_JIG_NAMESERVER, DEFAULT_SUFFIX, NamingError};
        let none = BTreeSet::new();
        // With no config of its own, a real authority leaves nothing to warn
        // about: `@jig` names resolve.
        let (added, warning) = with_default_delegation(BTreeMap::new(), &none, Ok("did:jig:zReal"));
        assert_eq!(added[DEFAULT_SUFFIX].authorities, ["did:jig:zReal"]);
        assert_eq!(added[DEFAULT_SUFFIX].nameservers, [DEFAULT_JIG_NAMESERVER]);
        assert_eq!(warning, None);

        // What every build without `test-default-authority` gets today:
        // nothing added, boot carries on, and one warning says every alias
        // is refused.
        let (refused, warning) =
            with_default_delegation(BTreeMap::new(), &none, Err(NamingError::NoDefaultAuthority));
        assert!(refused.is_empty());
        let warning = warning.expect("one warning");
        assert!(warning.contains("every alias will be refused"), "{warning}");

        // Placeholder, but the config delegates another suffix: only `@jig`
        // names are refused, and the warning says so.
        let other = NameDelegation {
            authorities: vec!["did:jig:zOther".into()],
            nameservers: vec!["https://ns.other".into()],
        };
        let (some, warning) = with_default_delegation(
            BTreeMap::from([("names.example.org".to_string(), other)]),
            &none,
            Err(NamingError::NoDefaultAuthority),
        );
        assert!(!some.contains_key(DEFAULT_SUFFIX));
        let warning = warning.expect("one warning");
        assert!(warning.contains("`@jig` aliases are refused"), "{warning}");
        assert!(!warning.contains("every alias"), "{warning}");

        // The operator's own entry wins.
        let mine = NameDelegation {
            authorities: vec!["did:jig:zMine".into()],
            nameservers: vec!["https://ns.mine".into()],
        };
        for authority in [Ok("did:jig:zReal"), Err(NamingError::NoDefaultAuthority)] {
            let (kept, warning) = with_default_delegation(
                BTreeMap::from([(DEFAULT_SUFFIX.to_string(), mine.clone())]),
                &none,
                authority,
            );
            assert_eq!(kept[DEFAULT_SUFFIX], mine);
            assert_eq!(warning, None, "the operator delegates `@jig` themselves");
        }
    }

    /// A refused `jig` gets no built-in delegation, and its aliases are
    /// refused before any nameserver is reached.
    #[tokio::test]
    async fn a_refused_jig_is_refused_despite_the_built_in_delegation() {
        use super::*;
        use jig_core::naming::DEFAULT_SUFFIX;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let refused = BTreeSet::from([DEFAULT_SUFFIX.to_string()]);
        let (none, warning) =
            with_default_delegation(BTreeMap::new(), &refused, Ok("did:jig:zReal"));
        assert!(!none.contains_key(DEFAULT_SUFFIX), "{none:?}");
        assert!(warning.expect("one warning").contains("every alias"));

        /// Counts every nameserver the resolver tries to reach.
        struct Counting(AtomicUsize);
        #[async_trait::async_trait]
        impl jig_pipeline::identity::NameserverTransport for Counting {
            async fn client(&self, _: &str, _: &[String]) -> Result<reqwest::Client, String> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err("not reached in this test".into())
            }
        }
        let counting = Arc::new(Counting(AtomicUsize::new(0)));
        let identity = IdentitySection {
            mode: IdentityMode::Nameserver,
            refused_suffixes: vec!["JIG".into()],
            ..IdentitySection::default()
        };
        let r = nameserver_resolver(
            &identity,
            Ok("did:jig:zReal"),
            Arc::new(SqliteStore::open_in_memory().unwrap()),
            counting.clone(),
        );
        let err = r.resolve("dj@jig").await.unwrap_err();
        assert!(
            matches!(err, jig_pipeline::identity::IdentityError::SuffixRefused(ref s) if s == "jig"),
            "{err:?}"
        );
        assert_eq!(counting.0.load(Ordering::SeqCst), 0);

        // Not refused, the same boot asks the built-in delegation's nameserver.
        let r = nameserver_resolver(
            &IdentitySection::default(),
            Ok("did:jig:zReal"),
            Arc::new(SqliteStore::open_in_memory().unwrap()),
            counting.clone(),
        );
        r.resolve("dj@jig").await.unwrap_err();
        assert_eq!(counting.0.load(Ordering::SeqCst), 1);
    }

    /// A config built in code is checked at boot as a loaded one is.
    #[test]
    fn a_suffix_both_delegated_and_refused_does_not_boot() {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.identity.refused_suffixes = vec!["Example.ORG".into()];
        config.identity.delegations.insert(
            "example.org".into(),
            jig_config::v0_0_2_server::NameDelegation {
                authorities: vec!["did:jig:zA".into()],
                nameservers: vec!["https://ns.example".into()],
            },
        );
        let err = super::AppState::for_test_with_config(config)
            .err()
            .expect("an overlap must not boot");
        assert!(format!("{err:#}").contains("`example.org`"), "{err:#}");
    }

    /// The configured bound is what ingest enforces and the welcome signs; one
    /// outside the protocol's range stops the boot.
    #[test]
    fn the_skew_bound_is_configured_and_checked() {
        assert_eq!(
            jig_config::v0_0_2_server::DEFAULT_MAX_FUTURE_SKEW_MS,
            jig_pipeline::handshake::DEFAULT_FUTURE_SKEW_MS,
            "the config default is the protocol default"
        );
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.server.max_future_skew_ms = 60_000;
        let state = super::AppState::for_test_with_config(config.clone()).unwrap();
        assert_eq!(state.ingest_ctx.hlc_clock.max_future_skew_ms(), 60_000);

        for outside in [0, 29_999, 900_001] {
            config.server.max_future_skew_ms = outside;
            let err = super::AppState::for_test_with_config(config.clone())
                .err()
                .expect("a bound outside the range must not boot");
            assert!(err.to_string().contains("max_future_skew_ms"), "{err}");
        }
    }

    /// Every operator-facing execution limit must reach the runtime config.
    ///
    /// Written with values that are all distinct from the defaults, so a field
    /// that silently keeps its default fails here. That is the exact failure this
    /// mapping exists to prevent: before it, the ingest render path ran on library
    /// defaults and ignored `[execution]` entirely.
    #[test]
    fn operator_execution_limits_reach_the_runtime_config() {
        let execution = crate::runtime::ExecutionConfig {
            fuel_max: 1_234_567,
            memory_max_mb: 111,
            timeout_ms: 999,
            host_id: "test-host".into(),
            pricing_enabled: false,
            cost_per_fuel: None,
            max_concurrent_executions: 7,
        };

        let rc = super::runtime_config_from(&execution);

        assert_eq!(rc.limits.fuel_max, 1_234_567);
        assert_eq!(rc.limits.memory_max_mb, 111);
        assert_eq!(rc.limits.execution_timeout_ms, 999);
        assert_eq!(rc.limits.max_concurrent_instances, 7);

        // Not an operator knob: this is the per-execution instance cap, and
        // conflating it with concurrency is what capped the engine at one
        // simultaneous execution.
        assert_eq!(rc.limits.max_instances, 1);

        // Each asserted value must differ from the default, or the assertion
        // above would pass on an unwired field.
        let default = jig_runtime::RuntimeConfig::default();
        assert_ne!(rc.limits.fuel_max, default.limits.fuel_max);
        assert_ne!(rc.limits.memory_max_mb, default.limits.memory_max_mb);
        assert_ne!(
            rc.limits.execution_timeout_ms,
            default.limits.execution_timeout_ms
        );
        assert_ne!(
            rc.limits.max_concurrent_instances,
            default.limits.max_concurrent_instances
        );
    }

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn for_test_constructs_appstate_with_defaults() {
        let state = AppState::for_test().unwrap();
        assert_eq!(state.config.identity.mode, IdentityMode::Tofu);
        assert!(
            state
                .server_did
                .to_did_jig_string()
                .starts_with("did:jig:z")
        );
    }

    #[test]
    fn for_test_appstate_clones_cheaply() {
        // Should be Arc-internal — cloning is cheap and doesn't duplicate the SQLite store.
        let state = AppState::for_test().unwrap();
        let cloned = state.clone();
        assert_eq!(state.server_did, cloned.server_did);
        // Internal Arc identity check: cloned shares the same IngestContext
        assert!(Arc::ptr_eq(&state.ingest_ctx, &cloned.ingest_ctx));
    }

    fn keyed_config(dir: &Path, keyfile: &str) -> JigServerConfig {
        let mut config = JigServerConfig::default();
        config.server.server_did_keyfile = dir.join(keyfile).to_string_lossy().into_owned();
        config.keys.unlock = Some(jig_client::server_key::credential_for_tests(dir));
        config
    }

    #[test]
    fn a_new_key_is_sealed_and_reloads_to_the_same_did() {
        let dir = tempdir().unwrap();
        let config = keyed_config(dir.path(), "subdir/server.key");
        let key = load_or_generate_server_key(&config).unwrap();
        let sealed = dir.path().join("subdir/server.jigkey");
        assert!(
            sealed.exists(),
            "the configured server.key names server.jigkey"
        );
        assert!(
            !dir.path().join("subdir/server.key").exists(),
            "nothing in clear"
        );
        assert!(jig_core::keystore::JigKey::from_bytes(&std::fs::read(&sealed).unwrap()).is_ok());
        let reloaded = load_or_generate_server_key(&config).unwrap();
        assert_eq!(key.to_bytes(), reloaded.to_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&sealed).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "a sealed keyfile is 0600 too");
        }
    }

    #[test]
    fn after_keys_rotate_the_server_boots_with_the_new_did_and_serves_the_link() {
        let dir = tempdir().unwrap();
        let mut config = keyed_config(dir.path(), "server.key");
        let old = load_or_generate_server_key(&config).unwrap();
        let next_dir = dir.path().join("next");
        std::fs::create_dir_all(&next_dir).unwrap();
        let next = jig_client::server_key::credential_for_tests(&next_dir);
        let done = jig_client::server_key::rotate(
            &dir.path().join("server.key"),
            std::slice::from_ref(&next),
            false,
            &key_options(&config.keys),
            1,
        )
        .unwrap();
        assert_eq!(
            done.old_did,
            Did::from_ed25519_pubkey(old.verifying_key().as_bytes()).to_did_jig_string()
        );

        config.keys.unlock = Some(next);
        let state = AppState::new(
            config,
            dir.path().join("jig.db"),
            ExecutionConfig::default(),
        )
        .unwrap();
        assert_eq!(state.server_did.to_did_jig_string(), done.new_did);
        assert_eq!(
            state.key_link.as_deref(),
            Some(std::fs::read(&done.link).unwrap().as_slice())
        );
    }

    #[test]
    fn a_new_key_file_never_replaces_an_existing_one() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("server.key");
        std::fs::write(&path, b"keep me").unwrap();
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let err = jig_core::crypto::ed25519::write_new_key_file(&path, &key).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
    }

    #[cfg(unix)]
    fn write_raw(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, [7u8; 32]).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_raw_keyfile_is_refused_and_the_error_names_the_seal_command() {
        let dir = tempdir().unwrap();
        let config = keyed_config(dir.path(), "server.key");
        write_raw(&dir.path().join("server.key"), 0o600);
        let msg = load_or_generate_server_key(&config)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("jig-server keys seal"), "{msg}");
        assert!(msg.contains("storage = \"plaintext\""), "{msg}");
    }

    #[cfg(unix)]
    #[test]
    fn plaintext_storage_still_loads_a_raw_key_but_checks_it() {
        let dir = tempdir().unwrap();
        let mut config = keyed_config(dir.path(), "server.key");
        config.keys.storage = jig_config::v0_0_2_server::KeyStorage::Plaintext;
        let path = dir.path().join("server.key");
        write_raw(&path, 0o600);
        let key = load_or_generate_server_key(&config).unwrap();
        assert_eq!(key.to_bytes(), [7u8; 32]);

        write_raw(&path, 0o644);
        let msg = load_or_generate_server_key(&config)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("permissions"), "{msg}");

        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&path, b"too short").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let msg = load_or_generate_server_key(&config)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("malformed"), "{msg}");
    }

    #[test]
    fn with_nothing_to_seal_with_a_new_key_is_refused() {
        let dir = tempdir().unwrap();
        let mut config = keyed_config(dir.path(), "server.key");
        config.keys.unlock = None;
        // The process may carry these; this test is about the config alone.
        if std::env::var_os("JIG_KEY_UNLOCK").is_some()
            || std::env::var_os("JIG_KEY_PASSPHRASE").is_some()
        {
            return;
        }
        let msg = load_or_generate_server_key(&config)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("[keys] unlock"), "{msg}");
        assert!(!dir.path().join("server.jigkey").exists());
    }
}
