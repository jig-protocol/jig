//! Mandatory client–server handshake (JEP-0002), v0.1 subset.
//!
//! After the transport opens, the client sends [`Frame::Hello`] (versions,
//! suites, capabilities, a fresh nonce). The server answers with
//! [`Frame::Welcome`], signed by its DID key. The client does not send
//! anything else until that welcome verifies.
//!
//! v0.1 signs four facts that already exist, plus the JEP's reputation
//! placeholder:
//!
//! - the envelope version this implementation speaks (`1`)
//! - the encryption suites it implements (`none` only; MLS is registered and
//!   not advertised)
//! - capabilities taken from the running server: allowed block kinds, whether
//!   it executes Wasm, and whether it speaks federation
//! - `reputation`, which is JSON `null` until JEP-0003
//!
//! Every failure falls into one of JEP-0002 rule 7's classes, and the class
//! decides who closes and with which WebSocket code ([`close`]):
//!
//! - a missing, malformed, unsigned or mismatched welcome is a handshake
//!   failure: the client closes, sending nothing else;
//! - no version or suite in common is an incompatibility: the server sends a
//!   signed [`Frame::Refusal`] and closes;
//! - behaviour that contradicts the signed welcome is a contradiction: the
//!   client closes and keeps the evidence;
//! - a frame before `hello`, or a second `hello`, is a protocol violation:
//!   the server closes.
//!
//! Not in this subset: a non-null reputation, REST, or a second handshake in
//! the other direction on one socket.

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use jig_core::{Did, EncryptionSuite};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::envelope::{ENVELOPE_VERSION, Envelope, EnvelopeGateError, EnvelopeParseError, Frame};

/// How long a peer waits for the welcome before treating it as missing.
pub const WELCOME_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The label for the TLS exporter value the handshake signs (JEP-0002 rule 2,
/// RFC 9266 channel binding). Both ends export 32 bytes under it, with no
/// context, so a signed handshake cannot be relayed into another TLS session.
pub const TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-jig-handshake";

/// Length of the exported value.
pub const TLS_EXPORTER_LEN: usize = 32;

const DOMAIN: &[u8] = b"jig-handshake-welcome-v1";
/// The format a refusal is signed in, named on the frame and as the signed
/// payload's `domain`: a COSE_Sign1 over deterministic CBOR. A refusal in any
/// other format is refused by name.
pub const REFUSAL_FORMAT: &str = "jig-handshake-refusal-v2";

/// WebSocket close codes, one per failure class (JEP-0002 rule 7).
pub mod close {
    /// The welcome is missing, malformed, unsigned or mismatched. The client
    /// closes.
    pub const HANDSHAKE_FAILED: u16 = 4001;
    /// No version or suite in common. The server closes after its signed
    /// refusal.
    pub const INCOMPATIBLE: u16 = 4002;
    /// The server contradicted its signed welcome. The client closes.
    pub const CONTRADICTION: u16 = 4003;
    /// A frame before `hello`, a second `hello`, or a frame outside the
    /// client's own offer. The server closes.
    pub const PROTOCOL_VIOLATION: u16 = 4004;
}

/// The error code a server sends before closing with
/// [`close::PROTOCOL_VIOLATION`] for anything but a missing `hello`.
pub const PROTOCOL_VIOLATION_CODE: &str = "PROTOCOL_VIOLATION";

/// The protocol's bounds on how far ahead of the server's clock a block's
/// `hlc_ts` may run (JEP-0002 rule 13). A server picks a value in this range
/// and signs it in its welcome; a client refuses a welcome outside it.
pub const MIN_FUTURE_SKEW_MS: u64 = 30_000;
/// See [`MIN_FUTURE_SKEW_MS`]. A ceiling, so no server can advertise an
/// unbounded clock under another name.
pub const MAX_FUTURE_SKEW_MS: u64 = 900_000;
/// The bound a server uses unless configured otherwise: five minutes.
pub const DEFAULT_FUTURE_SKEW_MS: u64 = 300_000;

/// What a server is willing to do, taken from configuration it already has.
///
/// `block_kinds` is the server's allow-list. `execution` is whether a Wasm
/// executor is installed. `federation` is whether this process speaks the
/// federation relay. `max_future_skew_ms` is how far ahead of the server's
/// clock a block may claim to be; ingest refuses anything further.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub block_kinds: Vec<String>,
    pub execution: bool,
    pub federation: bool,
    #[serde(default = "default_future_skew_ms")]
    pub max_future_skew_ms: u64,
}

fn default_future_skew_ms() -> u64 {
    DEFAULT_FUTURE_SKEW_MS
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            block_kinds: Vec::new(),
            execution: false,
            federation: false,
            max_future_skew_ms: DEFAULT_FUTURE_SKEW_MS,
        }
    }
}

impl Capabilities {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push(&mut out, &canonical_list(&self.block_kinds));
        push(&mut out, &[u8::from(self.execution)]);
        push(&mut out, &[u8::from(self.federation)]);
        push(&mut out, &self.max_future_skew_ms.to_le_bytes());
        out
    }
}

/// The welcome's reputation field.
///
/// v0.1 servers send JSON `null`. The canonical JSON text is what the
/// signature covers, so a later non-null object is a signed claim rather than
/// a parse failure. It is not a security input (OP-10); JEP-0003 defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reputation {
    canonical: String,
}

impl Reputation {
    /// The v0.1 placeholder.
    pub fn none() -> Self {
        Self {
            canonical: "null".to_string(),
        }
    }

    /// Whether the signed claim is the v0.1 placeholder.
    pub fn is_null(&self) -> bool {
        self.canonical == "null"
    }

    /// Compact JSON, which is the byte string the signature covers.
    pub fn canonical_json(&self) -> &str {
        &self.canonical
    }
}

impl Serialize for Reputation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value: serde_json::Value =
            serde_json::from_str(&self.canonical).map_err(serde::ser::Error::custom)?;
        value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Reputation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        let canonical = serde_json::to_string(&value).map_err(D::Error::custom)?;
        Ok(Self { canonical })
    }
}

/// What the client offers. Defaults to the one version and the one suite v0.1
/// implements, and to no capability requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientOffer {
    pub versions: Vec<u64>,
    pub suites: Vec<String>,
    pub capabilities: Capabilities,
    /// When set, a welcome whose `server_did` is a different key fails closed.
    pub pinned_server_did: Option<String>,
    /// Suites this client pinned for the server. A signed refusal that no
    /// longer lists one is a downgrade, not an incompatibility.
    pub pinned_suites: Vec<String>,
}

impl Default for ClientOffer {
    fn default() -> Self {
        Self {
            versions: vec![u64::from(ENVELOPE_VERSION)],
            suites: implemented_suite_names(),
            capabilities: Capabilities::default(),
            pinned_server_did: None,
            pinned_suites: Vec::new(),
        }
    }
}

/// Facts the server puts in the welcome, aside from the key it signs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerOffer {
    pub capabilities: Capabilities,
}

/// The client's hello, after it has parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloView {
    pub versions: Vec<u64>,
    pub suites: Vec<String>,
    pub capabilities: Capabilities,
    pub nonce: String,
}

/// The bytes the server signs. `v` and `frame_suite` are the envelope fields
/// of the welcome, not a second copy on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WelcomeStatement {
    pub v: u8,
    pub frame_suite: String,
    pub server_did: String,
    pub suites: Vec<String>,
    pub capabilities: Capabilities,
    pub reputation: Reputation,
    pub nonce: String,
}

impl WelcomeStatement {
    /// Length-prefixed, domain-separated encoding. Field order is fixed so
    /// both sides sign the same bytes without depending on JSON key order.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push(&mut out, DOMAIN);
        push(&mut out, &[self.v]);
        push(&mut out, self.frame_suite.as_bytes());
        push(&mut out, self.server_did.as_bytes());
        push(&mut out, &canonical_list(&self.suites));
        push(&mut out, &self.capabilities.canonical_bytes());
        push(&mut out, self.reputation.canonical_json().as_bytes());
        push(&mut out, self.nonce.as_bytes());
        out
    }

    /// The welcome's own fields disagree. A hostile operator can sign that
    /// disagreement; the signature does not make it consistent.
    pub fn contradicts_itself(&self) -> Option<&'static str> {
        if self.suites.is_empty() {
            return Some("welcome advertises no encryption suites");
        }
        if !self.suites.iter().any(|suite| suite == &self.frame_suite) {
            return Some("welcome is carried under a suite it does not advertise");
        }
        None
    }
}

/// Why the server will not welcome this hello.
///
/// `UnsupportedVersion` and `UnsupportedSuite` are incompatibilities: the
/// server answers with [`seal_refusal`] and closes. `Malformed` is a protocol
/// violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloRefusal {
    UnsupportedVersion(String),
    UnsupportedSuite(String),
    Malformed(String),
}

impl HelloRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedVersion(_) => EnvelopeGateError::UNSUPPORTED_VERSION_CODE,
            Self::UnsupportedSuite(_) => EnvelopeGateError::UNSUPPORTED_SUITE_CODE,
            Self::Malformed(_) => "BAD_JSON",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::UnsupportedVersion(message)
            | Self::UnsupportedSuite(message)
            | Self::Malformed(message) => message,
        }
    }
}

/// What a server signs to refuse a hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalStatement {
    pub v: u8,
    pub frame_suite: String,
    pub server_did: String,
    pub code: String,
    pub message: String,
    pub versions: Vec<u64>,
    pub suites: Vec<String>,
    pub nonce: String,
}

impl RefusalStatement {
    /// The deterministic CBOR payload of the COSE_Sign1: a text-keyed map
    /// with `domain` = [`REFUSAL_FORMAT`], so no other signed object's payload
    /// can stand in for it.
    pub fn payload(&self) -> Vec<u8> {
        use jig_core::dcbor::{self, Value};
        dcbor::encode(&Value::text_map([
            ("domain", Value::text(REFUSAL_FORMAT)),
            ("v", Value::Unsigned(u64::from(self.v))),
            ("frame_suite", Value::text(&self.frame_suite)),
            ("server_did", Value::text(&self.server_did)),
            ("code", Value::text(&self.code)),
            ("message", Value::text(&self.message)),
            (
                "versions",
                Value::Array(self.versions.iter().copied().map(Value::Unsigned).collect()),
            ),
            (
                "suites",
                Value::Array(self.suites.iter().map(Value::text).collect()),
            ),
            ("nonce", Value::text(&self.nonce)),
        ]))
        .expect("a refusal of text and integers encodes")
    }
}

/// A refusal whose signature verified against `server_did`: the server
/// signed that it speaks none of what the client offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRefusal {
    pub server_did: String,
    pub code: String,
    pub message: String,
    pub versions: Vec<u64>,
    pub suites: Vec<String>,
    /// The frame text, kept as evidence.
    pub evidence: String,
}

/// A welcome whose signature verified against `server_did`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWelcome {
    pub server_did: String,
    pub version: u8,
    pub suites: Vec<String>,
    pub capabilities: Capabilities,
    pub reputation: Reputation,
    pub nonce: String,
    /// The frame text, kept so a later contradiction has something to show.
    pub evidence: String,
}

/// What the client does with the server's first frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeResult {
    Established(VerifiedWelcome),
    /// A signed refusal: nothing in common. The server closes
    /// ([`close::INCOMPATIBLE`]).
    Incompatible(VerifiedRefusal),
    /// Missing, malformed, unsigned or mismatched. The client closes
    /// ([`close::HANDSHAKE_FAILED`]).
    FailClosed {
        reason: String,
        evidence: Option<String>,
    },
    /// A signed answer that contradicts what this client pinned, such as a
    /// refusal that drops a pinned suite. The client closes
    /// ([`close::CONTRADICTION`]) and keeps the evidence.
    Contradiction {
        reason: String,
        evidence: String,
    },
}

/// The hello this client just sent. [`PendingHello::interpret`] checks the
/// server's first frame against it.
#[derive(Debug, Clone)]
pub struct PendingHello {
    nonce: String,
    offer: ClientOffer,
}

impl PendingHello {
    pub fn interpret(&self, text: &str) -> HandshakeResult {
        let env = match Envelope::parse(text) {
            Ok(env) => env,
            // A first frame at a version or suite this client does not speak
            // is outside its offer, whatever it says.
            Err(EnvelopeParseError::Gate(gate)) => {
                return HandshakeResult::FailClosed {
                    reason: format!("first frame is outside the offer: {gate}"),
                    evidence: Some(text.to_string()),
                };
            }
            Err(EnvelopeParseError::Malformed(_)) => {
                return HandshakeResult::FailClosed {
                    reason: "malformed handshake frame".to_string(),
                    evidence: Some(text.to_string()),
                };
            }
        };
        interpret_envelope(&env, text, &self.nonce, &self.offer)
    }
}

/// Content suites this implementation can carry: what a channel may be
/// created under. v0.2 advertises `none` and `mls`; a test suite compiled
/// into a test build is never advertised.
pub fn implemented_suite_names() -> Vec<String> {
    EncryptionSuite::REGISTERED
        .iter()
        .copied()
        .filter(|suite| suite.is_implemented() && suite.is_advertised())
        .map(|suite| suite.as_str().to_string())
        .collect()
}

/// 32 bytes from the OS CSPRNG, standard base64. A fresh value per hello.
pub fn fresh_nonce() -> String {
    let mut buf = [0u8; 32];
    jig_core::crypto::ed25519::fill_random(&mut buf);
    STANDARD.encode(buf)
}

/// Build the client's hello and the state needed to check the welcome.
pub fn begin(offer: &ClientOffer) -> (Envelope, PendingHello) {
    let nonce = fresh_nonce();
    let env = Envelope::new(Frame::Hello {
        versions: offer.versions.clone(),
        suites: offer.suites.clone(),
        capabilities: offer.capabilities.clone(),
        nonce: nonce.clone(),
    });
    (
        env,
        PendingHello {
            nonce,
            offer: offer.clone(),
        },
    )
}

/// Choose a welcome, or say why not.
///
/// An unknown or unimplemented suite in the offer is skipped. It is never
/// treated as `none`. If nothing implemented overlaps, the refusal is
/// `UNSUPPORTED_SUITE`.
pub fn negotiate(
    hello: &HelloView,
    server: &ServerOffer,
) -> Result<WelcomeStatement, HelloRefusal> {
    if hello.nonce.is_empty() {
        return Err(HelloRefusal::Malformed("hello nonce is empty".to_string()));
    }
    if !hello.versions.contains(&u64::from(ENVELOPE_VERSION)) {
        return Err(HelloRefusal::UnsupportedVersion(format!(
            "server speaks envelope v{ENVELOPE_VERSION}"
        )));
    }
    let suites = implemented_suite_names();
    // Frames themselves are always `none` (an encrypted block is encrypted
    // inside its manifest), so the offer must include it. A client offering
    // only `mls` is asking for frame-level encryption nobody implements, and
    // answering it under `none` would put the welcome outside its offer.
    let frame_suite = EncryptionSuite::Unencrypted.as_str();
    if !hello.suites.iter().any(|offered| offered == frame_suite) {
        return Err(HelloRefusal::UnsupportedSuite(format!(
            "frames are carried under `{frame_suite}`; server implements {}",
            suites.join(", ")
        )));
    }
    Ok(WelcomeStatement {
        v: ENVELOPE_VERSION,
        frame_suite: EncryptionSuite::Unencrypted.as_str().to_string(),
        server_did: String::new(),
        suites,
        capabilities: server.capabilities.clone(),
        reputation: Reputation::none(),
        nonce: hello.nonce.clone(),
    })
}

/// Set `server_did` from `key` and sign the statement. The envelope this
/// returns is what the client has to check.
pub fn seal(key: &SigningKey, mut statement: WelcomeStatement) -> Envelope {
    statement.server_did =
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string();
    statement.v = ENVELOPE_VERSION;
    statement.frame_suite = EncryptionSuite::Unencrypted.as_str().to_string();
    let sig = STANDARD.encode(key.sign(&statement.canonical_bytes()).to_bytes());
    Envelope::new(Frame::Welcome {
        server_did: statement.server_did,
        suites: statement.suites,
        capabilities: statement.capabilities,
        reputation: statement.reputation,
        nonce: statement.nonce,
        sig,
    })
}

/// Sign a refusal of `hello` for `refusal`, which must be a version or suite
/// incompatibility. The server sends it and closes with
/// [`close::INCOMPATIBLE`].
pub fn seal_refusal(key: &SigningKey, refusal: &HelloRefusal, nonce: &str) -> Envelope {
    let statement = RefusalStatement {
        v: ENVELOPE_VERSION,
        frame_suite: EncryptionSuite::Unencrypted.as_str().to_string(),
        server_did: Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string(),
        code: refusal.code().to_string(),
        message: refusal.message().to_string(),
        versions: vec![u64::from(ENVELOPE_VERSION)],
        suites: implemented_suite_names(),
        nonce: nonce.to_string(),
    };
    let sig = STANDARD.encode(jig_core::cose::sign1(key, &statement.payload()));
    Envelope::new(Frame::Refusal {
        format: REFUSAL_FORMAT.to_string(),
        server_did: statement.server_did,
        code: statement.code,
        message: statement.message,
        versions: statement.versions,
        suites: statement.suites,
        nonce: statement.nonce,
        sig,
    })
}

/// Whether two DID strings name the same key. Unparseable strings name
/// nothing, so they match nothing.
pub fn same_did(a: &str, b: &str) -> bool {
    let key = |s: &str| {
        Did::from_did_jig_string(s)
            .and_then(|did| did.as_bytes())
            .ok()
    };
    matches!((key(a), key(b)), (Some(a), Some(b)) if a == b)
}

fn interpret_refusal(
    env: &Envelope,
    text: &str,
    nonce: &str,
    offer: &ClientOffer,
) -> HandshakeResult {
    let Frame::Refusal {
        format,
        server_did,
        code,
        message,
        versions,
        suites,
        nonce: echoed,
        sig,
    } = &env.frame
    else {
        unreachable!("called for a refusal");
    };
    let fail = |reason: String| HandshakeResult::FailClosed {
        reason,
        evidence: Some(text.to_string()),
    };
    if format != REFUSAL_FORMAT {
        return fail(format!(
            "refusal is signed in format `{format}`, which this client does not verify"
        ));
    }
    if echoed != nonce {
        return fail("refusal nonce does not match".to_string());
    }
    if code != EnvelopeGateError::UNSUPPORTED_VERSION_CODE
        && code != EnvelopeGateError::UNSUPPORTED_SUITE_CODE
    {
        return fail(format!("refusal carries an unknown code {code}"));
    }
    let statement = RefusalStatement {
        v: env.v,
        frame_suite: env.suite.as_str().to_string(),
        server_did: server_did.clone(),
        code: code.clone(),
        message: message.clone(),
        versions: versions.clone(),
        suites: suites.clone(),
        nonce: echoed.clone(),
    };
    if let Err(reason) = verify_refusal_signature(&statement, sig) {
        return fail(reason);
    }
    if let Some(reason) = pin_mismatch(server_did, offer.pinned_server_did.as_deref()) {
        return fail(reason);
    }
    if let Some(dropped) = offer
        .pinned_suites
        .iter()
        .find(|pinned| !suites.contains(pinned))
    {
        return HandshakeResult::Contradiction {
            reason: format!(
                "the server signed a refusal that no longer lists the `{dropped}` suite it advertised before"
            ),
            evidence: text.to_string(),
        };
    }
    HandshakeResult::Incompatible(VerifiedRefusal {
        server_did: server_did.clone(),
        code: code.clone(),
        message: message.clone(),
        versions: versions.clone(),
        suites: suites.clone(),
        evidence: text.to_string(),
    })
}

fn interpret_envelope(
    env: &Envelope,
    text: &str,
    nonce: &str,
    offer: &ClientOffer,
) -> HandshakeResult {
    let Frame::Welcome {
        server_did,
        suites,
        capabilities,
        reputation,
        nonce: echoed,
        sig,
    } = &env.frame
    else {
        if matches!(env.frame, Frame::Refusal { .. }) {
            return interpret_refusal(env, text, nonce, offer);
        }
        // An unsigned refusal leaves nothing to show, so it is not one.
        return HandshakeResult::FailClosed {
            reason: format!("first frame is {} not a welcome", frame_name(&env.frame)),
            evidence: Some(text.to_string()),
        };
    };

    let statement = WelcomeStatement {
        v: env.v,
        frame_suite: env.suite.as_str().to_string(),
        server_did: server_did.clone(),
        suites: suites.clone(),
        capabilities: capabilities.clone(),
        reputation: reputation.clone(),
        nonce: echoed.clone(),
    };

    if echoed != nonce {
        return HandshakeResult::FailClosed {
            reason: "nonce does not match".to_string(),
            evidence: Some(text.to_string()),
        };
    }
    if let Err(reason) = verify_signature(&statement, sig) {
        return HandshakeResult::FailClosed {
            reason,
            evidence: Some(text.to_string()),
        };
    }
    if let Some(why) = statement.contradicts_itself() {
        return HandshakeResult::FailClosed {
            reason: format!("welcome contradicts itself: {why}"),
            evidence: Some(text.to_string()),
        };
    }
    if let Some(why) = outside_offer(&statement, offer) {
        return HandshakeResult::FailClosed {
            reason: why.to_string(),
            evidence: Some(text.to_string()),
        };
    }
    let skew = statement.capabilities.max_future_skew_ms;
    if !(MIN_FUTURE_SKEW_MS..=MAX_FUTURE_SKEW_MS).contains(&skew) {
        return HandshakeResult::FailClosed {
            reason: format!(
                "welcome advertises a clock-skew bound of {skew} ms, outside the protocol's \
                 {MIN_FUTURE_SKEW_MS}–{MAX_FUTURE_SKEW_MS} ms"
            ),
            evidence: Some(text.to_string()),
        };
    }
    if let Some(reason) = pin_mismatch(server_did, offer.pinned_server_did.as_deref()) {
        return HandshakeResult::FailClosed {
            reason,
            evidence: Some(text.to_string()),
        };
    }

    HandshakeResult::Established(VerifiedWelcome {
        server_did: server_did.clone(),
        version: env.v,
        suites: suites.clone(),
        capabilities: capabilities.clone(),
        reputation: reputation.clone(),
        nonce: echoed.clone(),
        evidence: text.to_string(),
    })
}

fn verify_signature(statement: &WelcomeStatement, sig_b64: &str) -> Result<(), String> {
    verify_key_signature(&statement.server_did, &statement.canonical_bytes(), sig_b64)
}

/// `sig` is a COSE_Sign1 by `statement.server_did` over exactly
/// `statement`'s payload.
fn verify_refusal_signature(statement: &RefusalStatement, sig_b64: &str) -> Result<(), String> {
    let envelope = STANDARD
        .decode(sig_b64)
        .map_err(|_| "sig is not base64".to_string())?;
    let signed = jig_core::cose::open_sign1(&envelope)
        .map_err(|err| format!("sig is not a COSE_Sign1: {err}"))?;
    if signed.payload != statement.payload() {
        return Err("signature does not verify: it covers other fields".to_string());
    }
    signed
        .verify(&statement.server_did)
        .map_err(|_| "signature does not verify".to_string())
}

fn verify_key_signature(server_did: &str, signed: &[u8], sig_b64: &str) -> Result<(), String> {
    let did = Did::from_did_jig_string(server_did)
        .map_err(|_| "server_did is not a canonical did:jig key".to_string())?;
    let public_key = did
        .as_bytes()
        .map_err(|err| format!("server_did does not decode to a key: {err}"))?;
    let verifying = VerifyingKey::from_bytes(&public_key)
        .map_err(|err| format!("server_did is not an ed25519 key: {err}"))?;
    let sig_bytes = STANDARD
        .decode(sig_b64)
        .map_err(|_| "sig is not base64".to_string())?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| "sig is not an ed25519 signature".to_string())?;
    verifying
        .verify(signed, &signature)
        .map_err(|_| "signature does not verify".to_string())
}

fn outside_offer(statement: &WelcomeStatement, offer: &ClientOffer) -> Option<&'static str> {
    if !offer.versions.contains(&u64::from(statement.v)) {
        return Some("welcome version is outside the versions the client offered");
    }
    if !offer
        .suites
        .iter()
        .any(|suite| suite == &statement.frame_suite)
    {
        return Some("welcome frame suite is outside the suites the client offered");
    }
    if !statement
        .suites
        .iter()
        .any(|advertised| offer.suites.iter().any(|offered| offered == advertised))
    {
        return Some("every advertised suite is outside what the client offered");
    }
    None
}

fn pin_mismatch(server_did: &str, pinned: Option<&str>) -> Option<String> {
    let pinned = pinned?;
    (!same_did(pinned, server_did))
        .then(|| format!("server_did {server_did} does not match the pinned DID"))
}

fn frame_name(frame: &Frame) -> &'static str {
    match frame {
        Frame::Hello { .. } => "hello",
        Frame::Welcome { .. } => "welcome",
        Frame::Refusal { .. } => "refusal",
        Frame::Subscribe { .. } => "subscribe",
        Frame::Submit { .. } => "submit",
        Frame::CatchUp { .. } => "catch_up",
        Frame::Ack { .. } => "ack",
        Frame::Block { .. } => "block",
        Frame::Error { .. } => "error",
    }
}

fn push(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).expect("handshake field fits in u64");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

fn canonical_list(items: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    let count = u64::try_from(items.len()).expect("suite list fits in u64");
    out.extend_from_slice(&count.to_le_bytes());
    for item in items {
        push(&mut out, item.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_core::crypto::ed25519::generate_signing_key;

    fn offer_server() -> ServerOffer {
        ServerOffer {
            capabilities: Capabilities {
                block_kinds: vec!["text-render".to_string()],
                execution: true,
                federation: false,
                ..Capabilities::default()
            },
        }
    }

    fn hello_view(nonce: &str) -> HelloView {
        HelloView {
            versions: vec![u64::from(ENVELOPE_VERSION)],
            suites: implemented_suite_names(),
            capabilities: Capabilities::default(),
            nonce: nonce.to_string(),
        }
    }

    #[test]
    fn sealed_welcome_verifies_and_is_null_reputation() {
        let key = generate_signing_key();
        let (hello, pending) = begin(&ClientOffer::default());
        let Frame::Hello { nonce, .. } = hello.frame else {
            panic!("hello");
        };
        let welcome = seal(
            &key,
            negotiate(&hello_view(&nonce), &offer_server()).unwrap(),
        );
        let text = serde_json::to_string(&welcome).unwrap();
        match pending.interpret(&text) {
            HandshakeResult::Established(verified) => {
                assert_eq!(verified.version, ENVELOPE_VERSION);
                // v0.2 hosts encrypted channels; frames stay `none`.
                assert_eq!(verified.suites, vec!["none".to_string(), "mls".to_string()]);
                assert!(verified.reputation.is_null());
                assert_eq!(
                    verified.capabilities.block_kinds,
                    vec!["text-render".to_string()]
                );
                assert!(verified.capabilities.execution);
                assert!(!verified.capabilities.federation);
                assert_eq!(
                    verified.server_did,
                    Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
                );
            }
            other => panic!("expected a welcome, got {other:?}"),
        }
    }

    #[test]
    fn every_signed_field_changes_the_canonical_bytes() {
        let mut base = negotiate(&hello_view("nonce-1"), &offer_server()).unwrap();
        base.server_did = "did:jig:zplaceholder".to_string();
        let base_bytes = base.canonical_bytes();

        let mut changed_did = base.clone();
        changed_did.server_did = "did:jig:zother".to_string();
        let mut changed_suite = base.clone();
        changed_suite.frame_suite = "mls".to_string();
        let mut changed_suites = base.clone();
        changed_suites.suites = vec!["mls".to_string()];
        let mut changed_caps = base.clone();
        changed_caps.capabilities.execution = false;
        let mut changed_skew = base.clone();
        changed_skew.capabilities.max_future_skew_ms += 1;
        let mut changed_rep = base.clone();
        changed_rep.reputation = Reputation {
            canonical: "{\"tier\":1}".to_string(),
        };
        let mut changed_nonce = base.clone();
        changed_nonce.nonce = "nonce-2".to_string();
        let mut changed_v = base.clone();
        changed_v.v = 9;

        for (label, bytes) in [
            ("did", changed_did.canonical_bytes()),
            ("frame_suite", changed_suite.canonical_bytes()),
            ("suites", changed_suites.canonical_bytes()),
            ("capabilities", changed_caps.canonical_bytes()),
            ("max_future_skew_ms", changed_skew.canonical_bytes()),
            ("reputation", changed_rep.canonical_bytes()),
            ("nonce", changed_nonce.canonical_bytes()),
            ("v", changed_v.canonical_bytes()),
        ] {
            assert_ne!(
                base_bytes, bytes,
                "{label} must be covered by the signature"
            );
        }
    }

    #[test]
    fn tampered_capabilities_fail_the_signature() {
        let key = generate_signing_key();
        let (hello, pending) = begin(&ClientOffer::default());
        let Frame::Hello { nonce, .. } = hello.frame else {
            panic!("hello");
        };
        let mut welcome = seal(
            &key,
            negotiate(&hello_view(&nonce), &offer_server()).unwrap(),
        );
        if let Frame::Welcome { capabilities, .. } = &mut welcome.frame {
            capabilities.execution = false;
        }
        let HandshakeResult::FailClosed { reason, evidence } =
            pending.interpret(&serde_json::to_string(&welcome).unwrap())
        else {
            panic!("tampered capabilities must fail closed");
        };
        assert!(reason.contains("signature does not verify"), "{reason}");
        assert!(evidence.is_some());
    }

    #[test]
    fn bad_signature_and_self_contradiction_fail_closed() {
        let key = generate_signing_key();
        let (hello, pending) = begin(&ClientOffer::default());
        let Frame::Hello { nonce, .. } = &hello.frame else {
            panic!("hello");
        };
        let mut statement = negotiate(&hello_view(nonce), &offer_server()).unwrap();
        statement.suites = vec!["mls".to_string()];
        let welcome = seal(&key, statement);
        let text = serde_json::to_string(&welcome).unwrap();
        match pending.interpret(&text) {
            HandshakeResult::FailClosed { reason, evidence } => {
                assert!(reason.contains("contradicts itself"), "reason was {reason}");
                assert!(evidence.is_some());
            }
            other => panic!("expected fail closed, got {other:?}"),
        }

        let statement = negotiate(&hello_view(nonce), &offer_server()).unwrap();
        let mut welcome = seal(&key, statement);
        if let Frame::Welcome { sig, .. } = &mut welcome.frame {
            sig.replace_range(0..4, "AAAA");
        }
        let text = serde_json::to_string(&welcome).unwrap();
        let HandshakeResult::FailClosed { reason, .. } = pending.interpret(&text) else {
            panic!("bad signature must fail closed");
        };
        assert!(
            reason.contains("signature") || reason.contains("sig"),
            "{reason}"
        );
    }

    #[test]
    fn missing_welcome_and_missing_reputation_fail_closed() {
        let (_hello, pending) = begin(&ClientOffer::default());
        let ack = serde_json::to_string(&Envelope::new(Frame::Ack {
            block_cid: "bafy".to_string(),
        }))
        .unwrap();
        match pending.interpret(&ack) {
            HandshakeResult::FailClosed { reason, .. } => {
                assert!(reason.contains("not a welcome"), "{reason}");
            }
            other => panic!("expected fail closed, got {other:?}"),
        }

        let key = generate_signing_key();
        let (hello, pending) = begin(&ClientOffer::default());
        let Frame::Hello { nonce, .. } = hello.frame else {
            panic!("hello");
        };
        let welcome = seal(
            &key,
            negotiate(&hello_view(&nonce), &offer_server()).unwrap(),
        );
        let mut value = serde_json::to_value(&welcome).unwrap();
        value.as_object_mut().unwrap().remove("reputation");
        let text = serde_json::to_string(&value).unwrap();
        match pending.interpret(&text) {
            HandshakeResult::FailClosed { reason, .. } => {
                assert!(reason.contains("malformed"), "{reason}");
            }
            other => panic!("missing reputation must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn an_unsigned_refusal_or_an_unspoken_version_fails_closed() {
        let (_hello, pending) = begin(&ClientOffer::default());
        let version = r##"{"v":2,"op":"subscribe","scope":{"kind":"channel","slug":"#hello"}}"##;
        assert!(matches!(
            pending.interpret(version),
            HandshakeResult::FailClosed { .. }
        ));

        let unsigned = Envelope::new(Frame::Error {
            status: Some(400),
            code: EnvelopeGateError::UNSUPPORTED_SUITE_CODE.to_string(),
            ref_cid: None,
            message: "server implements none".to_string(),
        });
        assert!(matches!(
            pending.interpret(&serde_json::to_string(&unsigned).unwrap()),
            HandshakeResult::FailClosed { .. }
        ));
    }

    fn refusal_for(pending: &PendingHello, key: &SigningKey) -> Envelope {
        seal_refusal(
            key,
            &HelloRefusal::UnsupportedVersion("server speaks envelope v1".to_string()),
            &pending.nonce,
        )
    }

    #[test]
    fn a_signed_refusal_is_an_incompatibility() {
        let key = generate_signing_key();
        let (_hello, pending) = begin(&ClientOffer::default());
        let text = serde_json::to_string(&refusal_for(&pending, &key)).unwrap();
        match pending.interpret(&text) {
            HandshakeResult::Incompatible(refusal) => {
                assert_eq!(refusal.code, EnvelopeGateError::UNSUPPORTED_VERSION_CODE);
                assert_eq!(refusal.versions, vec![u64::from(ENVELOPE_VERSION)]);
                assert_eq!(refusal.suites, implemented_suite_names());
                assert_eq!(refusal.evidence, text);
            }
            other => panic!("expected an incompatibility, got {other:?}"),
        }
    }

    #[test]
    fn a_refusal_that_does_not_verify_fails_closed() {
        let key = generate_signing_key();
        let (_hello, pending) = begin(&ClientOffer::default());

        let mut tampered = refusal_for(&pending, &key);
        if let Frame::Refusal { suites, .. } = &mut tampered.frame {
            suites.retain(|s| s == "none");
        }
        assert!(matches!(
            pending.interpret(&serde_json::to_string(&tampered).unwrap()),
            HandshakeResult::FailClosed { reason, .. } if reason.contains("signature")
        ));

        let mut renamed = refusal_for(&pending, &key);
        if let Frame::Refusal { format, .. } = &mut renamed.frame {
            *format = "jig-handshake-refusal-v1".to_string();
        }
        assert!(matches!(
            pending.interpret(&serde_json::to_string(&renamed).unwrap()),
            HandshakeResult::FailClosed { reason, .. } if reason.contains("format")
        ));

        let (_other, stale) = begin(&ClientOffer::default());
        let replayed = serde_json::to_string(&refusal_for(&stale, &key)).unwrap();
        assert!(matches!(
            pending.interpret(&replayed),
            HandshakeResult::FailClosed { reason, .. } if reason.contains("nonce")
        ));

        let pinned = PendingHello {
            offer: ClientOffer {
                pinned_server_did: Some(
                    Did::from_ed25519_pubkey(generate_signing_key().verifying_key().as_bytes())
                        .to_did_jig_string(),
                ),
                ..ClientOffer::default()
            },
            ..pending.clone()
        };
        let text = serde_json::to_string(&refusal_for(&pinned, &key)).unwrap();
        assert!(matches!(
            pinned.interpret(&text),
            HandshakeResult::FailClosed { reason, .. } if reason.contains("pinned")
        ));
    }

    #[test]
    fn a_refusal_that_drops_a_pinned_suite_is_a_contradiction() {
        let key = generate_signing_key();
        let (_hello, pending) = begin(&ClientOffer {
            pinned_suites: vec!["mls".to_string(), "rot13".to_string()],
            ..ClientOffer::default()
        });
        let text = serde_json::to_string(&refusal_for(&pending, &key)).unwrap();
        match pending.interpret(&text) {
            HandshakeResult::Contradiction { reason, evidence } => {
                assert!(reason.contains("rot13"), "{reason}");
                assert_eq!(evidence, text);
            }
            other => panic!("expected a contradiction, got {other:?}"),
        }
    }

    #[test]
    fn a_refusal_and_a_welcome_sign_different_bytes() {
        let refusal = RefusalStatement {
            v: 1,
            frame_suite: "none".to_string(),
            server_did: "did:jig:zA".to_string(),
            code: "UNSUPPORTED_VERSION".to_string(),
            message: String::new(),
            versions: vec![1],
            suites: vec!["none".to_string()],
            nonce: "n".to_string(),
        };
        let bytes = refusal.payload();
        let decoded = jig_core::dcbor::decode(&bytes).unwrap();
        assert_eq!(
            decoded.get("domain").and_then(|d| d.as_text()),
            Some(REFUSAL_FORMAT)
        );
        assert!(!bytes.windows(DOMAIN.len()).any(|w| w == DOMAIN));
        let mut other = refusal.clone();
        other.suites.push("mls".to_string());
        assert_ne!(bytes, other.payload());
    }

    #[test]
    fn negotiate_refuses_a_version_or_suite_it_does_not_speak() {
        let mut hello = hello_view("n");
        hello.versions = vec![2];
        let refusal = negotiate(&hello, &offer_server()).unwrap_err();
        assert_eq!(refusal.code(), EnvelopeGateError::UNSUPPORTED_VERSION_CODE);

        hello.versions = vec![1];
        hello.suites = vec!["mls".to_string()];
        let refusal = negotiate(&hello, &offer_server()).unwrap_err();
        assert_eq!(refusal.code(), EnvelopeGateError::UNSUPPORTED_SUITE_CODE);

        hello.suites = vec!["rot13".to_string()];
        let refusal = negotiate(&hello, &offer_server()).unwrap_err();
        assert_eq!(
            refusal.code(),
            EnvelopeGateError::UNSUPPORTED_SUITE_CODE,
            "an unknown suite is not treated as none"
        );

        hello.suites = vec!["rot13".to_string(), "none".to_string()];
        assert!(negotiate(&hello, &offer_server()).is_ok());
    }

    #[test]
    fn pinned_did_mismatch_fails_closed() {
        let key = generate_signing_key();
        let other = generate_signing_key();
        let (hello, _) = begin(&ClientOffer::default());
        let Frame::Hello { nonce, .. } = hello.frame else {
            panic!("hello");
        };
        let welcome = seal(
            &key,
            negotiate(&hello_view(&nonce), &offer_server()).unwrap(),
        );
        let pending = PendingHello {
            nonce,
            offer: ClientOffer {
                pinned_server_did: Some(
                    Did::from_ed25519_pubkey(other.verifying_key().as_bytes()).to_did_jig_string(),
                ),
                ..ClientOffer::default()
            },
        };
        let text = serde_json::to_string(&welcome).unwrap();
        match pending.interpret(&text) {
            HandshakeResult::FailClosed { reason, .. } => {
                assert!(reason.contains("pinned"), "{reason}");
            }
            other => panic!("expected pin mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_skew_bound_outside_the_protocol_range_fails_closed() {
        let key = generate_signing_key();
        for skew in [0, MIN_FUTURE_SKEW_MS - 1, MAX_FUTURE_SKEW_MS + 1, u64::MAX] {
            let (hello, pending) = begin(&ClientOffer::default());
            let Frame::Hello { nonce, .. } = hello.frame else {
                panic!("hello");
            };
            let mut statement = negotiate(&hello_view(&nonce), &offer_server()).unwrap();
            statement.capabilities.max_future_skew_ms = skew;
            let text = serde_json::to_string(&seal(&key, statement)).unwrap();
            assert!(
                matches!(
                    pending.interpret(&text),
                    HandshakeResult::FailClosed { reason, .. } if reason.contains("skew")
                ),
                "{skew}"
            );
        }
    }

    #[test]
    fn fresh_nonces_differ() {
        assert_ne!(fresh_nonce(), fresh_nonce());
    }
}
