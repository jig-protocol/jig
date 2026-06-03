//! v0.0.2 hello-world milestone — additive layer wiring jig-pipeline + jig-client
//! into jig-server without touching the existing handler tree.
//!
//! `AppState` is the boot context Phase D2-D6 will hand to NEW axum routes
//! (under `/api/v1/*` and `/_admin_v0_0_2/*`). Existing v0.0.1 routes
//! (defined in `handler.rs`, `server.rs`, `websocket/`, `federation/`,
//! etc.) keep their own state and are unaffected by this module.
//!
//! When Phase F's new `jig-cli` commands hit the new routes via WSS,
//! they reach jig-pipeline's `ingest()` pipeline (Task B6). The existing
//! /blocks HTTP routes stay alive for backward compat until Phase F+
//! retires them.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use jig_config::v0_0_2_server::{IdentityMode, JigServerConfig};
use jig_core::Did;
use jig_pipeline::{
    fanout::Fanout,
    hlc::HlcClock,
    identity::{IdentityResolver, NameserverResolver, TofuResolver},
    ingest::IngestContext,
    persist::SqliteStore,
};
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
}

impl AppState {
    /// Build the AppState from a parsed JigServerConfig and a SQLite path.
    /// Generates the server signing key if the configured keyfile is absent;
    /// loads it otherwise. On Unix the keyfile is set to mode 0600 on
    /// generation.
    pub fn new(config: JigServerConfig, db_path: PathBuf) -> Result<Self> {
        let store = Arc::new(SqliteStore::open(&db_path).context("opening SqliteStore")?);
        let signing_key = load_or_generate_server_key(&config.server.server_did_keyfile)
            .context("loading server signing key")?;
        let server_did = Did::from_ed25519_pubkey(signing_key.verifying_key().as_bytes());

        let identity: Arc<dyn IdentityResolver> = match config.identity.mode {
            IdentityMode::Tofu => Arc::new(TofuResolver::new(store.clone())),
            IdentityMode::Nameserver => Arc::new(NameserverResolver::new(
                config.identity.trusted_nameservers.clone(),
                config.identity.cache_ttl_seconds,
            )),
        };

        let hlc_clock = Arc::new(HlcClock::new(server_did.clone()));
        let fanout = Arc::new(Fanout::new());
        let server_url = format!("ws://{}", config.server.listen);

        let naively_allow_unknown_handles_fallback =
            config.identity.naively_allow_unknown_handles_fallback;

        let ingest_ctx = Arc::new(IngestContext {
            store,
            identity,
            hlc_clock,
            allowed_block_kinds: config.server.allowed_block_kinds.clone(),
            server_did: server_did.clone(),
            server_key: signing_key,
            fanout,
            server_url: server_url.clone(),
            naively_allow_unknown_handles_fallback,
        });

        let bridges = Arc::new(crate::v0_0_2_bridges::BridgeRegistry::new(&config));

        Ok(Self {
            config,
            ingest_ctx,
            server_did,
            server_url,
            bridges,
            bridge_router_mount: jig_bridge_core::RouterMount::new(),
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

        let ingest_ctx = Arc::new(IngestContext {
            store,
            identity,
            hlc_clock,
            allowed_block_kinds: config.server.allowed_block_kinds.clone(),
            server_did: server_did.clone(),
            server_key: signing_key,
            fanout,
            server_url: server_url.clone(),
            naively_allow_unknown_handles_fallback,
        });

        let bridges = Arc::new(crate::v0_0_2_bridges::BridgeRegistry::new(&config));

        Ok(Self {
            config,
            ingest_ctx,
            server_did,
            server_url,
            bridges,
            bridge_router_mount: jig_bridge_core::RouterMount::new(),
        })
    }
}

/// Load the server's ed25519 signing key from `path`, or generate + write
/// it if the file doesn't exist. On Unix, generated files are set to mode
/// 0600. The path supports `~` expansion (e.g. `~/.jig/server/server.key`).
fn load_or_generate_server_key(path: &str) -> Result<SigningKey> {
    let expanded = shellexpand::tilde(path).into_owned();
    let path = Path::new(&expanded);
    if path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .with_context(|| format!("stating keyfile at {}", path.display()))?
                .permissions()
                .mode()
                & 0o777;
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "server keyfile at {} has insecure permissions {:#o} (must be 0o600 — group/other access is forbidden)",
                    path.display(),
                    mode,
                );
            }
        }
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading server keyfile at {}", path.display()))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "server keyfile at {} is malformed: expected 32 bytes, got {}",
                path.display(),
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(SigningKey::from_bytes(&arr))
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("creating server keyfile parent dir {}", parent.display())
            })?;
        }
        let secret: [u8; 32] = rand::random();
        let signing = SigningKey::from_bytes(&secret);
        std::fs::write(path, signing.to_bytes())
            .with_context(|| format!("writing server keyfile to {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(signing)
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn load_or_generate_creates_keyfile_and_returns_signing_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("subdir/server.key");
        assert!(!path.exists());
        let key = load_or_generate_server_key(path.to_str().unwrap()).unwrap();
        assert!(path.exists());
        // Reloading returns the same signing key
        let reloaded = load_or_generate_server_key(path.to_str().unwrap()).unwrap();
        assert_eq!(key.to_bytes(), reloaded.to_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "generated keyfile must be 0600 on Unix");
        }
    }

    #[test]
    fn load_or_generate_errors_on_malformed_keyfile() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.key");
        std::fs::write(&path, b"too short").unwrap();
        // Set 0600 so the permission check passes and we hit the length check.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let err = load_or_generate_server_key(path.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("malformed"));
    }

    #[cfg(unix)]
    #[test]
    fn load_or_generate_rejects_world_readable_keyfile() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("server.key");
        // Write a valid 32-byte keyfile but with permissive (0644) mode.
        std::fs::write(&path, [0u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = load_or_generate_server_key(path.to_str().unwrap()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("permissions") || msg.contains("0644") || msg.contains("0o644"),
            "expected permission error, got: {msg}"
        );
    }
}
