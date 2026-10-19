//! Configuration handling for the Jig server.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use jig_config::v0_0_2_server::{
    AuthSection, BridgesSection, DebugSection, FederationSection, IdentitySection, JigServerConfig,
    NameserverSection, ServerSection,
};

use crate::runtime::ExecutionConfig;

/// The whole `jig-server --config` file, in one type.
///
/// Root keys and `[execution]`/`[tls]` open the socket and size the runtime;
/// the other sections are the pipeline's, handed over as a
/// [`JigServerConfig`] by [`ServerConfig::v0_0_2`]. Every key is accounted
/// for: an unknown key at any level is a parse error, and a key that jig-server
/// used to accept fails with a message saying it was removed
/// ([`REMOVED_KEYS`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Must stay ahead of the `[execution]` / `[tls]` tables in `TemplateRoot`:
    /// `write_template` serializes in declaration order, and TOML forbids a
    /// bare value after a table.
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub execution: ExecutionSection,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub identity: IdentitySection,
    #[serde(default)]
    pub federation: FederationSection,
    #[serde(default)]
    pub debug: DebugSection,
    #[serde(default)]
    pub bridges: BridgesSection,
    #[serde(default)]
    pub nameserver: NameserverSection,
    #[serde(default)]
    pub auth: AuthSection,
}

/// Keys jig-server once accepted and no longer does, as a dotted path and the
/// reason. A config that still carries one fails to load with that reason
/// rather than serde's bare "unknown field".
pub const REMOVED_KEYS: &[(&str, &str)] = &[
    (
        "dangerously_enable_v0_0_1_rest",
        "the v0.0.1 REST API it enabled was removed",
    ),
    (
        "debug.admin_endpoints",
        "channel operations are always served at /api/v1/channels; the /_admin_v0_0_2 \
         aliases it enabled were removed. v0.1.0-alpha.1's install.sh and \
         deploy/config.example.toml wrote `admin_endpoints = false` under [debug]; deleting \
         that one line is all an upgrade needs",
    ),
    (
        "execution.pricing_enabled",
        "executions are never priced; the key had no effect",
    ),
    (
        "execution.cost_per_fuel",
        "executions are never priced; the key had no effect",
    ),
    (
        "storage",
        "jig-server never read it; the database lives at the root-level database_path",
    ),
];

/// TLS for the listener. On by default.
///
/// With neither `cert_path` nor `key_path`, the server makes a self-signed
/// certificate on first start, keeps it in `tls/` next to the database, and
/// its DID vouches for it at `/.well-known/jig`: jig clients trust it through
/// the DID they pinned, not through a CA. Give both paths to serve a
/// certificate a CA issued (`tailscale cert`, certbot); jig clients accept
/// either.
///
/// `enabled = false` serves plaintext HTTP. It is an unsafe option: use it only
/// on loopback or behind a proxy that terminates TLS, never on a listener peers
/// or clients reach directly. The server advertises it as `tls.enabled=false`
/// in `unsafe_options_active` and warns at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ExecutionSection {
    #[serde(default = "default_fuel_max")]
    pub fuel_max: u64,
    #[serde(default = "default_memory_max_mb")]
    pub memory_max_mb: u32,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
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
            server: ServerSection::default(),
            identity: IdentitySection::default(),
            federation: FederationSection::default(),
            debug: DebugSection::default(),
            bridges: BridgesSection::default(),
            nameserver: NameserverSection::default(),
            auth: AuthSection::default(),
        }
    }
}

impl Default for ExecutionSection {
    fn default() -> Self {
        Self {
            fuel_max: default_fuel_max(),
            memory_max_mb: default_memory_max_mb(),
            timeout_ms: default_timeout_ms(),
            max_concurrent_executions: default_max_concurrent_executions(),
        }
    }
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let contents = fs::read_to_string(path)?;
        Self::from_toml_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Parse a config file's contents. A key listed in [`REMOVED_KEYS`] is
    /// reported by name and reason; any other unknown key fails with serde's
    /// error, which names it.
    pub fn from_toml_str(contents: &str) -> Result<Self, String> {
        let table: toml::Table = toml::from_str(contents).map_err(|e| e.to_string())?;
        if let Some((key, why)) = REMOVED_KEYS
            .iter()
            .find(|(key, _)| has_dotted_key(&table, key))
        {
            return Err(format!(
                "`{key}` is no longer a jig-server config key: {why}. Delete it."
            ));
        }
        toml::from_str(contents).map_err(|e| e.to_string())
    }

    /// The pipeline's sections, as the [`JigServerConfig`] its `AppState`
    /// takes.
    pub fn v0_0_2(&self) -> JigServerConfig {
        JigServerConfig {
            server: self.server.clone(),
            identity: self.identity.clone(),
            federation: self.federation.clone(),
            debug: self.debug.clone(),
            bridges: self.bridges.clone(),
            nameserver: self.nameserver.clone(),
            auth: self.auth.clone(),
        }
    }

    /// Write a commented config template: the root keys, `[execution]` and
    /// `[tls]` as serialized defaults, then the pipeline's sections as
    /// hand-commented TOML with the same defaults.
    pub fn write_template(path: impl AsRef<Path>) -> std::io::Result<()> {
        let defaults = Self::default();
        let root = TemplateRoot {
            database_path: &defaults.database_path,
            bind_address: &defaults.bind_address,
            port: defaults.port,
            host_id: &defaults.host_id,
            public_url: &defaults.public_url,
            execution: &defaults.execution,
            tls: &defaults.tls,
        };
        let mut template = toml::to_string_pretty(&root).map_err(std::io::Error::other)?;
        // Appended after the serialized part because TOML forbids a bare
        // key/value pair once a table header has been emitted.
        template.push_str(&v0_0_2_template_sections(&defaults));
        fs::write(path, template)
    }

    /// Unsafe options set by the root keys and `[tls]`, named the way
    /// `JigServerConfig::unsafe_options_active` names its own, so
    /// `/.well-known/jig` and the startup log can list both together.
    pub fn unsafe_options_active(&self) -> Vec<String> {
        let mut active = Vec::new();
        if !self.tls.enabled {
            active.push("tls.enabled=false".to_string());
        }
        active
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
            // No operator setting: the v0.0.2 render path never prices
            // executions (`v0_0_2::runtime_config_from` maps no pricing).
            pricing_enabled: false,
            cost_per_fuel: None,
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

/// Whether `table` holds the dotted `key`, e.g. `debug.admin_endpoints`.
fn has_dotted_key(table: &toml::Table, key: &str) -> bool {
    let mut parts = key.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let mut value = match table.get(first) {
        Some(v) => v,
        None => return false,
    };
    for part in parts {
        match value.as_table().and_then(|t| t.get(part)) {
            Some(v) => value = v,
            None => return false,
        }
    }
    true
}

/// The part of [`ServerConfig`] `write_template` serializes; the pipeline's
/// sections are written by hand with comments instead.
#[derive(Serialize)]
struct TemplateRoot<'a> {
    database_path: &'a PathBuf,
    bind_address: &'a str,
    port: u16,
    host_id: &'a str,
    public_url: &'a Option<String>,
    execution: &'a ExecutionSection,
    tls: &'a TlsConfig,
}

/// The pipeline's sections (`[server]`, `[identity]`, `[auth]`, `[debug]`) as
/// commented TOML. Values track `JigServerConfig`'s own defaults so the
/// template can't drift from them.
fn v0_0_2_template_sections(server: &ServerConfig) -> String {
    let defaults = JigServerConfig::default();
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
# The keys above open the socket; the sections below configure identity, auth,
# federation and bridges. jig-server rejects any key it does not know, so a
# typo fails the boot instead of silently keeping a default.
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
    fn plaintext_listener_is_an_unsafe_option() {
        assert!(ServerConfig::default().unsafe_options_active().is_empty());
        let mut cfg = ServerConfig::default();
        cfg.tls.enabled = false;
        assert_eq!(cfg.unsafe_options_active(), vec!["tls.enabled=false"]);
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
mod config_file_tests {
    use super::*;

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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server-config.toml");
        ServerConfig::write_template(&path).unwrap();

        let server = ServerConfig::load(&path).unwrap();
        // The pipeline's sections must not switch on any debug option.
        let v002 = server.v0_0_2();
        assert!(
            !v002.debug.list_handles,
            "template must not enable handle enumeration"
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
    /// This is the test that stops `install.sh` from silently rotting: every
    /// key it writes must be one jig-server knows, and it must fill in both the
    /// socket keys and the pipeline's sections.
    #[test]
    fn install_sh_writes_a_config_that_boots_both_halves() {
        let rendered = install_sh_config("/opt/jig-home", "127.0.0.1:7117");
        assert!(
            !rendered.contains('$'),
            "unexpanded shell variable in install.sh's config heredoc:\n{rendered}"
        );

        let server = ServerConfig::from_toml_str(&rendered)
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

        let v002 = server.v0_0_2();
        assert!(
            v002.unsafe_options_active()
                .iter()
                .all(|o| !o.starts_with("debug.")),
            "install.sh must not advertise debug options"
        );
        assert_eq!(v002.server.listen, "127.0.0.1:7117");
        assert_eq!(
            v002.server.listen,
            format!("{}:{}", server.bind_address, server.port),
            "install.sh must keep the decorative `listen` in sync with the real bind address"
        );
    }

    /// The example operators copy must stay loadable as the config surface
    /// tightens.
    #[test]
    fn deploy_example_config_loads() {
        let example =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/config.example.toml");
        ServerConfig::load(&example).expect("deploy/config.example.toml must load");
    }

    #[test]
    fn one_file_carries_the_socket_keys_and_the_pipeline_sections() {
        let cfg = ServerConfig::from_toml_str(
            r#"
database_path = "/var/lib/jig/jig.db"
bind_address = "0.0.0.0"
port = 443

[tls]
enabled = true
cert_path = "/etc/jig/tls/fullchain.pem"
key_path = "/etc/jig/tls/privkey.pem"

[server]
server_did_keyfile = "/srv/keep-me.key"

[bridges.per_bridge.email]
enabled = true

[bridges.per_bridge.email.config]
bridge_domain = "mail.jig.onl"
provider = "resend"
bridge_secret = "literal-secret"
"#,
        )
        .unwrap();
        assert_eq!(cfg.port, 443);
        let v002 = cfg.v0_0_2();
        assert_eq!(v002.server.server_did_keyfile, "/srv/keep-me.key");
        assert!(v002.bridge_permitted("email"));
    }

    #[test]
    fn an_unknown_key_is_an_error_naming_it() {
        for (body, key) in [
            ("databse_path = \"/tmp/x.db\"\n", "databse_path"),
            ("[execution]\nfuel = 1\n", "fuel"),
            ("[tls]\nenable = false\n", "enable"),
            ("[identity]\nmod = \"tofu\"\n", "mod"),
            ("[sever]\nlisten = \"x\"\n", "sever"),
        ] {
            let err = ServerConfig::from_toml_str(&format!(
                "database_path = \"/tmp/x.db\"\nbind_address = \"127.0.0.1\"\nport = 7117\n{body}"
            ))
            .expect_err(&format!("`{key}` must be rejected"));
            assert!(err.contains(key), "the error must name `{key}`, got: {err}");
        }
    }

    #[test]
    fn a_removed_key_is_an_error_saying_so() {
        for (body, key) in [
            (
                "dangerously_enable_v0_0_1_rest = false\n",
                "dangerously_enable_v0_0_1_rest",
            ),
            (
                "[debug]\nadmin_endpoints = false\n",
                "debug.admin_endpoints",
            ),
            (
                "[execution]\npricing_enabled = false\n",
                "execution.pricing_enabled",
            ),
            (
                "[execution]\ncost_per_fuel = 0.1\n",
                "execution.cost_per_fuel",
            ),
            ("[storage.truth]\npath = \"/tmp/x.db\"\n", "storage"),
        ] {
            let err = ServerConfig::from_toml_str(&format!(
                "database_path = \"/tmp/x.db\"\nbind_address = \"127.0.0.1\"\nport = 7117\n{body}"
            ))
            .expect_err(&format!("`{key}` must be rejected"));
            assert!(
                err.contains(&format!("`{key}` is no longer a jig-server config key")),
                "got: {err}"
            );
        }
    }
}
