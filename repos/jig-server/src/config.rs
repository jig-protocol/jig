//! Configuration handling for the Jig server.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::runtime::ExecutionConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub database_path: PathBuf,
    pub bind_address: String,
    pub port: u16,
    #[serde(default = "default_host_id")]
    pub host_id: String,
    /// The origin to advertise at `/.well-known/jig`, e.g.
    /// `https://jig-vps.example.ts.net:7117`.
    ///
    /// When unset, the origin is derived as `{scheme}://{bind_address}:{port}`
    /// with the scheme following `[tls] enabled`. That derivation is right for a
    /// plaintext deployment and WRONG for most TLS ones: `bind_address` is
    /// usually an IP, while a certificate is issued for a hostname, so a peer
    /// that follows the advertisement gets a certificate-name mismatch rather
    /// than a useful error. Set this to whatever name the cert actually covers.
    ///
    /// Must stay ahead of the `[execution]` / `[tls]` tables: `write_template`
    /// serializes this struct in declaration order, and TOML forbids a bare
    /// value after a table.
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub execution: ExecutionSection,
    #[serde(default)]
    pub tls: TlsConfig,
}

/// TLS for the listener. On by default.
///
/// With neither `cert_path` nor `key_path`, the server makes a self-signed
/// certificate on first start, keeps it in `tls/` next to the database, and
/// its DID vouches for it at `/.well-known/jig`: jig clients trust it through
/// the DID they pinned, not through a CA. Give both paths to serve a
/// certificate a CA issued (`tailscale cert`, certbot); jig clients accept
/// either. `enabled = false` serves plaintext HTTP, for loopback development
/// or behind a proxy that terminates TLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_tls_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

fn default_tls_enabled() -> bool {
    true
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cert_path: None,
            key_path: None,
        }
    }
}

impl TlsConfig {
    /// The certificate and key to serve: the configured pair, or the
    /// self-signed pair under `dir/tls/`, made on first use for `names`. One
    /// path without the other is a misconfiguration and fails loudly.
    pub fn material(&self, dir: &Path, names: &[String]) -> Result<(PathBuf, PathBuf), String> {
        match (&self.cert_path, &self.key_path) {
            (Some(cert), Some(key)) => Ok((cert.clone(), key.clone())),
            (None, None) => self_signed(&dir.join("tls"), names),
            _ => Err(
                "[tls] needs both cert_path and key_path, or neither for a self-signed \
                 certificate"
                    .to_string(),
            ),
        }
    }
}

/// The self-signed certificate in `dir`, made now if it is not there yet.
/// The key is written 0600.
fn self_signed(dir: &Path, names: &[String]) -> Result<(PathBuf, PathBuf), String> {
    let (cert, key) = (dir.join("self-signed.crt"), dir.join("self-signed.key"));
    if cert.exists() && key.exists() {
        return Ok((cert, key));
    }
    let made = rcgen::generate_simple_self_signed(names.to_vec())
        .map_err(|e| format!("making a self-signed TLS certificate: {e}"))?;
    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(
        &mut options
            .open(&key)
            .map_err(|e| format!("writing {}: {e}", key.display()))?,
        made.signing_key.serialize_pem().as_bytes(),
    )
    .map_err(|e| format!("writing {}: {e}", key.display()))?;
    fs::write(&cert, made.cert.pem()).map_err(|e| format!("writing {}: {e}", cert.display()))?;
    Ok((cert, key))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSection {
    #[serde(default = "default_fuel_max")]
    pub fuel_max: u64,
    #[serde(default = "default_memory_max_mb")]
    pub memory_max_mb: u32,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub pricing_enabled: bool,
    #[serde(default)]
    pub cost_per_fuel: Option<f64>,
    /// How many block executions may run at once.
    ///
    /// Sizes wasmtime's instance pool. Past it, execution does not queue inside
    /// the engine — it fails — so the ingest executor gates itself to this number
    /// and callers wait for a slot instead. Costs address space rather than
    /// resident memory: roughly `max_concurrent_executions * memory_max_mb`
    /// reserved, paged in only as guests touch it.
    #[serde(default = "default_max_concurrent_executions")]
    pub max_concurrent_executions: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let jig_dir = PathBuf::from(home).join(".jig");
        Self {
            database_path: jig_dir.join("jig.db"),
            bind_address: "127.0.0.1".into(),
            port: 7117,
            host_id: default_host_id(),
            public_url: None,
            execution: ExecutionSection::default(),
            tls: TlsConfig::default(),
        }
    }
}

impl ServerConfig {
    /// Attempt to construct a ServerConfig from a `jig-config` TOML file.
    /// Maps a minimal subset needed by jig-server:
    /// - storage.truth.connection_string -> database_path (when backend = sqlite)
    pub fn load_from_jig_config_path(path: &Path) -> std::io::Result<Self> {
        #[derive(serde::Deserialize, Default)]
        struct JigConfigDoc {
            #[serde(default)]
            storage: Option<jig_config::storage::MultiTierStorageConfig>,
        }

        let s = fs::read_to_string(path)?;
        let doc: JigConfigDoc = toml::from_str(&s)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut cfg = ServerConfig::default();

        // Map storage.truth -> database_path (sqlite path)
        if let Some(storage) = &doc.storage
            && let Some(truth) = &storage.truth
        {
            use jig_config::storage::Backend;
            if matches!(truth.backend, Backend::Sqlite)
                && let Some(path) = &truth.connection_string
            {
                cfg.database_path = PathBuf::from(path);
            }
        }

        Ok(cfg)
    }

    /// Try to load jig-config from common locations (cwd ./jig-config.toml or ~/.jig/config.toml).
    pub fn try_load_jig_config_from_well_known() -> Option<Self> {
        let cwd = std::env::current_dir().ok();
        if let Some(mut p) = cwd.clone() {
            p.push("jig-config.toml");
            if p.exists()
                && let Ok(cfg) = Self::load_from_jig_config_path(&p)
            {
                return Some(cfg);
            }
        }
        let home_default = jig_config::default_config_path();
        if home_default.exists()
            && let Ok(cfg) = Self::load_from_jig_config_path(&home_default)
        {
            return Some(cfg);
        }
        None
    }

    /// Pure helper for tests: try to load from exactly these two potential files in order.
    pub fn try_load_jig_config_from_paths(cwd_config: &Path, home_config: &Path) -> Option<Self> {
        if cwd_config.exists()
            && let Ok(cfg) = Self::load_from_jig_config_path(cwd_config)
        {
            return Some(cfg);
        }
        if home_config.exists()
            && let Ok(cfg) = Self::load_from_jig_config_path(home_config)
        {
            return Some(cfg);
        }
        None
    }
}

impl Default for ExecutionSection {
    fn default() -> Self {
        Self {
            fuel_max: default_fuel_max(),
            memory_max_mb: default_memory_max_mb(),
            timeout_ms: default_timeout_ms(),
            max_concurrent_executions: default_max_concurrent_executions(),
            pricing_enabled: false,
            cost_per_fuel: None,
        }
    }
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config = toml::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }

    /// Write a config template covering BOTH halves of the hybrid file.
    ///
    /// `jig-server --config <file>` loads the same file into two unrelated
    /// types, so a template with only `ServerConfig` keys leaves
    /// `JigServerConfig` on `::default()` and gives the operator nothing to
    /// edit for identity, auth or admission.
    pub fn write_template(path: impl AsRef<Path>) -> std::io::Result<()> {
        let defaults = Self::default();
        let mut template = toml::to_string_pretty(&defaults).map_err(std::io::Error::other)?;
        // Appended after the serialized struct because TOML forbids a bare
        // key/value pair once a table header has been emitted.
        template.push_str(&v0_0_2_template_sections(&defaults));
        fs::write(path, template)
    }

    /// Names a self-signed certificate is made for: `localhost`, the bind
    /// address unless it is a wildcard, and `public_url`'s host. jig clients
    /// trust the certificate through the server's DID, not these names; they
    /// are there for other tools.
    pub fn tls_names(&self) -> Vec<String> {
        let mut names = vec!["localhost".to_string()];
        if !matches!(self.bind_address.as_str(), "0.0.0.0" | "::" | "[::]") {
            names.push(self.bind_address.clone());
        }
        if let Some(host) = self
            .public_url
            .as_deref()
            .and_then(|u| url::Url::parse(u).ok())
            .and_then(|u| u.host_str().map(str::to_string))
        {
            names.push(host.trim_matches(['[', ']']).to_string());
        }
        names.dedup();
        names
    }

    pub fn execution_config(&self) -> ExecutionConfig {
        ExecutionConfig {
            fuel_max: self.execution.fuel_max,
            memory_max_mb: self.execution.memory_max_mb,
            timeout_ms: self.execution.timeout_ms,
            max_concurrent_executions: self.execution.max_concurrent_executions,
            host_id: self.host_id.clone(),
            pricing_enabled: self.execution.pricing_enabled,
            cost_per_fuel: self.execution.cost_per_fuel,
        }
    }

    /// Apply explicit overrides with precedence: CLI > ENV > existing (jig-config/defaults)
    pub fn apply_overrides_explicit(
        &mut self,
        cli_db: Option<PathBuf>,
        env_db: Option<PathBuf>,
        cli_bind: Option<String>,
        cli_port: Option<u16>,
    ) {
        if let Some(db) = cli_db.or(env_db) {
            self.database_path = db;
        }
        if let Some(bind) = cli_bind {
            self.bind_address = bind;
        }
        if let Some(port) = cli_port {
            self.port = port;
        }
    }
}

/// The `[server]`/`[identity]`/`[debug]` half of the hybrid config file, as
/// commented TOML. Values track `JigServerConfig`'s own defaults so the
/// template can't drift from them.
fn v0_0_2_template_sections(server: &ServerConfig) -> String {
    let defaults = jig_config::v0_0_2_server::JigServerConfig::default();
    let kinds = defaults
        .server
        .allowed_block_kinds
        .iter()
        .map(|k| format!("\"{k}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let listen = format!("{}:{}", server.bind_address, server.port);

    format!(
        r#"
# ============================================================================
# JigServerConfig — the v0.0.2 half of this file.
#
# jig-server loads THIS SAME PATH into a second type. The keys above open the
# socket; the sections below configure identity, federation, bridges and the
# admin surface. Neither type rejects the other's keys, which is what makes
# one file legal for both.
# ============================================================================

[server]
# DECORATIVE. Only builds the ws:// origin-tag string stamped onto blocks —
# the socket binds bind_address/port above. jig-server logs a WARN at startup
# when the two disagree.
listen = "{listen}"

# The ed25519 seed the server DID is derived from. BACK IT UP: losing it
# changes the server DID and breaks TOFU pinning for every client.
server_did_keyfile = "{keyfile}"

# channel-create and member-add are not optional extras — `jig channel create`
# and `jig channel join` submit exactly these kinds. member-remove and
# channel-promote back `jig channel kick/leave/promote`.
allowed_block_kinds = [{kinds}]

[identity]
# tofu = trust the first key seen for a DID and pin it. No nameserver needed.
mode = "tofu"
trusted_nameservers = []
cache_ttl_seconds = {cache_ttl}
naively_allow_unknown_handles_fallback = {unknown_handles}

[auth]
# Every read (REST and WSS) must carry a proof of possession of the caller's
# key; restricted channels are then enforced against membership. Setting this
# to false disables BOTH — there is nobody to authorize — and exists only to
# migrate a deployment whose clients cannot sign yet. It is advertised in
# unsafe_options_active while set.
require_authenticated_reads = {require_auth}
# Half-width of the request acceptance window, and the cap on remembered
# nonces. A full guard refuses new requests rather than forget a live nonce.
replay_window_ms = {replay_window_ms}
replay_capacity = {replay_capacity}

# Gate 2: whom this server deals with at all, decided after a caller proves
# their key and before anything is authorized. The default admits everyone.
# Reputation is ruleset-scoped: a floor names its ruleset, and a DID with no
# score under it is UNKNOWN for it — decided by `unknown_dids`, never by the
# number. `unknown_dids = "refuse"` plus `records` is a members-only server.
# `unknown_dids = "proof-of-work"` admits a new DID once it has done `pow_bits`
# of work for this server (`POST /api/v1/admission`; the CLI does it on first
# contact). Each bit doubles the cost; 20 is under a second on a laptop and
# much less on a GPU, so it is a speed bump for identity floods, not a wall.
[auth.admission]
unknown_dids = "admit"
# pow_bits = 20
banned_dids = []
# [[auth.admission.floors]]
# ruleset_key = "gigue.highsec.v1"
# minimum = 0
# [[auth.admission.records]]
# did = "did:jig:z..."
# ruleset_key = "gigue.highsec.v1"
# score = 5

# Token buckets in front of the gates: per verified DID (reads, subscriptions,
# and every write it authors) and per remote address (every request and every
# WebSocket frame). A bucket holds `*_burst` and refills at `*_per_second`;
# a rate of 0 turns that limit off. Behind a reverse proxy every request has
# the proxy's address: raise the per-IP limit or turn it off there.
[auth.rate_limit]
per_did_burst = {per_did_burst}
per_did_per_second = {per_did_per_second}
per_ip_burst = {per_ip_burst}
per_ip_per_second = {per_ip_per_second}
replay_per_did = {replay_per_did}
max_tracked = {max_tracked}

[debug]
# Channel ops live on /api/v1/channels and are always mounted. This flag only
# adds the legacy /_admin_v0_0_2/* aliases that pre-v0.1 `jig` CLIs POST to.
admin_endpoints = {admin_endpoints}
# Handle enumeration stays off — it dumps the registry to any caller.
list_handles = {list_handles}
"#,
        listen = listen,
        keyfile = defaults.server.server_did_keyfile,
        require_auth = defaults.auth.require_authenticated_reads,
        replay_window_ms = defaults.auth.replay_window_ms,
        replay_capacity = defaults.auth.replay_capacity,
        per_did_burst = defaults.auth.rate_limit.per_did_burst,
        per_did_per_second = defaults.auth.rate_limit.per_did_per_second,
        per_ip_burst = defaults.auth.rate_limit.per_ip_burst,
        per_ip_per_second = defaults.auth.rate_limit.per_ip_per_second,
        replay_per_did = defaults.auth.rate_limit.replay_per_did,
        max_tracked = defaults.auth.rate_limit.max_tracked,
        kinds = kinds,
        cache_ttl = defaults.identity.cache_ttl_seconds,
        unknown_handles = defaults.identity.naively_allow_unknown_handles_fallback,
        admin_endpoints = defaults.debug.admin_endpoints,
        list_handles = defaults.debug.list_handles,
    )
}

fn default_host_id() -> String {
    "did:jig:server:local".into()
}

fn default_fuel_max() -> u64 {
    5_000_000
}

fn default_memory_max_mb() -> u32 {
    64
}

fn default_timeout_ms() -> u64 {
    250
}

/// Matches jig-runtime's own default, so the two agree unless an operator says
/// otherwise.
fn default_max_concurrent_executions() -> u32 {
    16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_is_on_by_default_with_a_self_signed_certificate() {
        let cfg = ServerConfig::default();
        assert!(cfg.tls.enabled);
        // An operator config that predates `[tls]` gets it too.
        let cfg: ServerConfig = toml::from_str(
            r#"
            database_path = "/tmp/x.db"
            bind_address = "127.0.0.1"
            port = 7117
        "#,
        )
        .unwrap();
        assert!(cfg.tls.enabled);

        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = cfg.tls.material(dir.path(), &cfg.tls_names()).unwrap();
        assert!(cert.starts_with(dir.path().join("tls")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&key).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "the key must not be group/other readable");
        }
        // Made once: a restart serves the same certificate.
        let pem = fs::read(&cert).unwrap();
        cfg.tls.material(dir.path(), &cfg.tls_names()).unwrap();
        assert_eq!(fs::read(&cert).unwrap(), pem);
    }

    #[test]
    fn tls_can_be_turned_off() {
        let cfg: ServerConfig = toml::from_str(
            r#"
            database_path = "/tmp/x.db"
            bind_address = "127.0.0.1"
            port = 7117
            [tls]
            enabled = false
        "#,
        )
        .unwrap();
        assert!(!cfg.tls.enabled);
    }

    #[test]
    fn tls_section_parses() {
        let toml_str = r#"
            database_path = "/tmp/x.db"
            bind_address = "0.0.0.0"
            port = 443
            [tls]
            enabled = true
            cert_path = "/etc/jig/tls/fullchain.pem"
            key_path = "/etc/jig/tls/privkey.pem"
        "#;
        let cfg: ServerConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.tls.enabled);
        let (cert, key) = cfg.tls.material(Path::new("/unused"), &[]).unwrap();
        assert_eq!(cert.to_str().unwrap(), "/etc/jig/tls/fullchain.pem");
        assert_eq!(key.to_str().unwrap(), "/etc/jig/tls/privkey.pem");
    }

    #[test]
    fn a_cert_without_its_key_is_an_error() {
        let toml_str = r#"
            database_path = "/tmp/x.db"
            bind_address = "0.0.0.0"
            port = 443
            [tls]
            cert_path = "/etc/jig/tls/fullchain.pem"
        "#;
        let cfg: ServerConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.tls.material(Path::new("/unused"), &[]).is_err());
    }
}

#[cfg(test)]
mod jig_config_bridge_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn maps_sqlite_path_from_jig_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jig-config.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"[storage.truth]
backend = "sqlite"
connection_string = "{db}"
"#,
            db = dir.path().join("test.db").display()
        )
        .unwrap();

        let cfg = ServerConfig::load_from_jig_config_path(&path).unwrap();
        assert_eq!(cfg.database_path, dir.path().join("test.db"));
    }

    #[test]
    fn apply_overrides_explicit_precedence() {
        let mut cfg = ServerConfig::default();
        let env_db = Some(PathBuf::from("/tmp/env.db"));
        cfg.apply_overrides_explicit(None, env_db.clone(), None, None);
        assert_eq!(cfg.database_path, PathBuf::from("/tmp/env.db"));
        let cli_db = Some(PathBuf::from("/tmp/cli.db"));
        cfg.apply_overrides_explicit(cli_db.clone(), None, Some("0.0.0.0".into()), Some(8123));
        assert_eq!(cfg.database_path, PathBuf::from("/tmp/cli.db"));
        assert_eq!(cfg.bind_address, "0.0.0.0");
        assert_eq!(cfg.port, 8123);
    }

    #[test]
    fn write_template_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server-config.toml");
        ServerConfig::write_template(&path).unwrap();
        let loaded = ServerConfig::load(&path).unwrap();
        assert!(!loaded.bind_address.is_empty());
        let exec = loaded.execution_config();
        assert_eq!(exec.fuel_max, loaded.execution.fuel_max);
        assert_eq!(exec.timeout_ms, loaded.execution.timeout_ms);
    }

    #[test]
    fn write_template_emits_a_bootable_v0_0_2_half() {
        use jig_config::v0_0_2_server::JigServerConfig;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server-config.toml");
        ServerConfig::write_template(&path).unwrap();

        // Half 1: the socket-opening half.
        let server = ServerConfig::load(&path).unwrap();

        // Half 2: the v0.0.2 half. Channel ops are not debug-gated, so the
        // template must not need (or switch on) the debug flag.
        let v002 = JigServerConfig::load(&path).unwrap();
        assert!(
            !v002.debug.admin_endpoints,
            "template must not enable the legacy admin aliases"
        );
        assert_eq!(
            v002.server.listen,
            format!("{}:{}", server.bind_address, server.port),
            "template's decorative `listen` must agree with the real bind address"
        );
        for kind in ["text-render", "channel-create", "member-add"] {
            assert!(
                v002.server.allowed_block_kinds.contains(&kind.to_string()),
                "template must allow {kind}"
            );
        }
    }

    /// Extract the literal heredoc `install.sh` writes to `~/.jig/config.toml`
    /// and expand the shell variables it interpolates. Any variable the
    /// installer adds later that isn't in this map trips the `$`-residue
    /// assertion below, which is exactly the rot we want to catch.
    fn install_sh_config(jig_home: &str, listen: &str) -> String {
        let install_sh = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../install.sh")
            .canonicalize()
            .expect("install.sh must sit at the repo root");
        let script = fs::read_to_string(&install_sh).unwrap();

        let start = script
            .find("cat > \"$cfg\" <<EOF\n")
            .expect("install.sh must still write the config via a `cat > \"$cfg\" <<EOF` heredoc");
        let body_start = start + script[start..].find('\n').unwrap() + 1;
        let body_end = body_start
            + script[body_start..]
                .find("\nEOF\n")
                .expect("unterminated heredoc in install.sh")
            + 1;

        let (host, port) = listen.rsplit_once(':').unwrap();
        script[body_start..body_end]
            .replace("${JIG_SERVER_LISTEN%%:*}", host)
            .replace("${JIG_SERVER_LISTEN##*:}", port)
            .replace("$JIG_SERVER_LISTEN", listen)
            .replace("$JIG_HOME", jig_home)
    }

    /// The installer's own output must boot the server it just installed.
    /// This is the test that stops `install.sh` from silently rotting: the
    /// config it writes feeds BOTH config structs, and omitting either half
    /// ships a first-run flow that dies on `jig-server --config`.
    #[test]
    fn install_sh_writes_a_config_that_boots_both_halves() {
        use jig_config::v0_0_2_server::JigServerConfig;

        let rendered = install_sh_config("/opt/jig-home", "127.0.0.1:7117");
        assert!(
            !rendered.contains('$'),
            "unexpanded shell variable in install.sh's config heredoc:\n{rendered}"
        );

        let server: ServerConfig = toml::from_str(&rendered)
            .expect("install.sh's config must parse as ServerConfig — this is what binds");
        assert_eq!(server.bind_address, "127.0.0.1");
        assert_eq!(server.port, 7117);
        assert!(
            server.tls.enabled,
            "the installer's server serves TLS, and install.sh points the client at https"
        );
        assert!(
            server.database_path.starts_with("/opt/jig-home"),
            "database_path must live under JIG_HOME, got {}",
            server.database_path.display()
        );

        let v002: JigServerConfig = toml::from_str(&rendered).unwrap();
        assert!(
            !v002.debug.admin_endpoints,
            "install.sh's default path must not depend on a [debug] flag"
        );
        assert!(
            v002.unsafe_options_active()
                .iter()
                .all(|o| o != "debug.admin_endpoints"),
            "install.sh must not advertise debug options"
        );
        assert_eq!(v002.server.listen, "127.0.0.1:7117");
        assert_eq!(
            v002.server.listen,
            format!("{}:{}", server.bind_address, server.port),
            "install.sh must keep the decorative `listen` in sync with the real bind address"
        );
    }

    #[test]
    fn jig_config_paths_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let cwd_cfg = dir.path().join("cwd.toml");
        let home_cfg = dir.path().join("home.toml");

        {
            let mut f = std::fs::File::create(&cwd_cfg).unwrap();
            writeln!(
                f,
                r#"[storage.truth]
backend = "sqlite"
connection_string = "{db}"
"#,
                db = dir.path().join("cwd.db").display()
            )
            .unwrap();
        }

        {
            let mut f = std::fs::File::create(&home_cfg).unwrap();
            writeln!(
                f,
                r#"[storage.truth]
backend = "sqlite"
connection_string = "{db}"
"#,
                db = dir.path().join("home.db").display()
            )
            .unwrap();
        }

        let cfg1 = ServerConfig::try_load_jig_config_from_paths(&cwd_cfg, &home_cfg).unwrap();
        assert_eq!(cfg1.database_path, dir.path().join("cwd.db"));

        std::fs::remove_file(&cwd_cfg).unwrap();
        let cfg2 = ServerConfig::try_load_jig_config_from_paths(&cwd_cfg, &home_cfg).unwrap();
        assert_eq!(cfg2.database_path, dir.path().join("home.db"));
    }
}
