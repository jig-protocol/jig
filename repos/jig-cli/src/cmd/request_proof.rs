//! Signed REST requests, addressed to the server they are sent to.
//!
//! A request proof names the server's DID (`jig-request-auth-v2`, JEP-0015),
//! so it does not verify anywhere else. The DID is taken from a signed
//! welcome on a handshake with the server at that URL ([`audience`]): one the
//! handshake held to this device's pin ([`Trust::Pinned`]), or, for a server
//! asked a question without being trusted with anything
//! ([`Trust::Unpinned`]), the one that server proved it holds. A server
//! whose welcome does not list v2 is refused before anything is signed, and
//! nothing falls back to the unbound v1.
//!
//! [`send`] signs, sends, and on `WRONG_AUDIENCE` — the pin is behind a key
//! change — handshakes again (which moves the pin along the server's key
//! links) and retries once with a freshly signed proof.

use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::{Context, Result};
use jig_client::Identity;
use jig_client::read_auth::{ReadProof, signable_path};
use jig_core::request_auth::refusal::WRONG_AUDIENCE;

/// How the audience for a server is proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trust {
    /// By a welcome held to this device's pin for the server, pinning it on
    /// first contact ([`crate::cmd::secure::connect_pinned`]).
    Pinned,
    /// By a welcome alone, pinning nothing: for a server asked a question and
    /// trusted with nothing but the answer.
    Unpinned,
}

/// Audiences this process has proven, by how and by
/// [`jig_client::secure::server_key`]: one handshake per server per process.
static AUDIENCES: Mutex<BTreeMap<(Trust, String), String>> = Mutex::new(BTreeMap::new());

/// How long proving a server's audience may take: the handshake, connection
/// and WebSocket upgrade included. A server that accepts the connection and
/// never answers must not hang a command that only meant to make a request.
const DISCOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The most of a 401's body read to tell a `WRONG_AUDIENCE` refusal apart:
/// the crate's bound for error bodies. A longer body is no refusal this
/// module acts on, and is reported as an error rather than read as one.
const REFUSAL_BYTES: usize = jig_client::limits::MAX_ERROR_BODY_BYTES;

fn key(server: &str) -> String {
    jig_client::secure::server_key(&crate::cmd::channel::base_http_url(server))
}

/// The DID to address request proofs to `server` to: the one its signed
/// welcome proved, as `trust` says.
pub async fn audience(server: &str, identity: &Identity, trust: Trust) -> Result<String> {
    audience_within(server, identity, trust, DISCOVERY_TIMEOUT).await
}

/// [`audience`], given up on after `within`.
async fn audience_within(
    server: &str,
    identity: &Identity,
    trust: Trust,
    within: std::time::Duration,
) -> Result<String> {
    if let Some(did) = AUDIENCES
        .lock()
        .expect("audiences")
        .get(&(trust, key(server)))
    {
        return Ok(did.clone());
    }
    // Boxed: pinning checks the server's manifest log, which can fill a gap
    // with a signed read. That read is handed this welcome's audience, so it
    // never comes back here, but the futures still name each other.
    let connect = async {
        match trust {
            Trust::Pinned => {
                Box::pin(crate::cmd::secure::connect_pinned(
                    server,
                    identity.duplicate(),
                ))
                .await
            }
            Trust::Unpinned => {
                crate::cmd::secure::connect_unpinned(server, identity.duplicate()).await
            }
        }
    };
    // Bounded as a whole, and before anything is signed. The handshake comes
    // before the request, so its failure names the server, as the request's
    // would have.
    let client = tokio::time::timeout(within, connect)
        .await
        .map_err(|_| anyhow::anyhow!("{server} did not complete a handshake within {:?}", within))
        .and_then(|r| r)
        .with_context(|| format!("handshaking with {server} to sign a request to it"))?;
    let welcome = client
        .welcome()
        .with_context(|| format!("{server} sent no welcome"))?;
    let did = jig_client::read_auth::audience_of(welcome)?;
    remember(server, trust, &did);
    Ok(did)
}

/// Record `did` as `server`'s audience, proven as `trust` says by a welcome
/// the caller holds.
pub fn remember(server: &str, trust: Trust, did: &str) {
    AUDIENCES
        .lock()
        .expect("audiences")
        .insert((trust, key(server)), did.to_string());
}

/// Drop what [`audience`] proved for `server`, so the next call handshakes.
pub fn forget(server: &str) {
    let key = key(server);
    AUDIENCES
        .lock()
        .expect("audiences")
        .retain(|(_, k), _| *k != key);
}

/// Send the request `build` makes (method, URL and body set; no proof), with
/// a proof by `identity` for `server` over `method`, `url`'s path and `body`.
///
/// On a `WRONG_AUDIENCE` refusal, prove the audience afresh and retry once,
/// signed anew: a proof is never sent twice. Any other answer is returned as
/// the server gave it.
pub async fn send(
    server: &str,
    identity: &Identity,
    method: &str,
    url: &str,
    body: &[u8],
    build: impl Fn() -> reqwest::RequestBuilder,
) -> Result<reqwest::Response> {
    send_as(server, Trust::Pinned, identity, method, url, body, build).await
}

/// [`send`], with the audience proven as `trust` says.
pub async fn send_as(
    server: &str,
    trust: Trust,
    identity: &Identity,
    method: &str,
    url: &str,
    body: &[u8],
    build: impl Fn() -> reqwest::RequestBuilder,
) -> Result<reqwest::Response> {
    let audience_now = audience(server, identity, trust).await?;
    let resp = send_once(identity, &audience_now, method, url, body, &build).await?;
    let resp = match wrong_audience(resp).await? {
        Ok(resp) => return Ok(resp),
        Err(refused) => refused,
    };
    forget(server);
    let retried = audience(server, identity, trust).await?;
    if retried == audience_now {
        // The server still signs as the DID it now refuses: a fresh proof
        // would be refused the same way.
        return Ok(resp);
    }
    send_once(identity, &retried, method, url, body, &build).await
}

async fn send_once(
    identity: &Identity,
    audience: &str,
    method: &str,
    url: &str,
    body: &[u8],
    build: &impl Fn() -> reqwest::RequestBuilder,
) -> Result<reqwest::Response> {
    let proof = ReadProof::sign_body(identity, audience, method, signable_path(url), body);
    let mut req = build();
    for (name, value) in proof.headers() {
        req = req.header(name, value);
    }
    req.send().await.with_context(|| format!("{method} {url}"))
}

/// `Ok(resp)` unless `resp` is a `WRONG_AUDIENCE` refusal, which comes back
/// as `Err(resp)`. Reading a 401's body to tell consumes it, so either way
/// the response is rebuilt from what was read.
async fn wrong_audience(
    resp: reqwest::Response,
) -> Result<Result<reqwest::Response, reqwest::Response>> {
    if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Ok(Ok(resp));
    }
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = jig_client::limits::read_capped(resp, REFUSAL_BYTES)
        .await
        .context("reading a refusal")?;
    let code = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v["code"].as_str().map(str::to_string));
    let mut rebuilt = http::Response::new(bytes);
    *rebuilt.status_mut() = status;
    *rebuilt.headers_mut() = headers;
    let rebuilt = reqwest::Response::from(rebuilt);
    Ok(if code.as_deref() == Some(WRONG_AUDIENCE) {
        Err(rebuilt)
    } else {
        Ok(rebuilt)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server is one audience whatever scheme or trailing slash names it.
    #[test]
    fn the_cache_key_ignores_scheme_and_slash() {
        assert_eq!(key("https://a.example/"), key("wss://a.example"));
        assert_eq!(key("http://127.0.0.1:7117"), key("ws://127.0.0.1:7117/"));
    }

    /// A stale audience (a pin behind a key change, say) is refused with
    /// `WRONG_AUDIENCE`; `send` proves the audience afresh from a new
    /// welcome and succeeds with a newly signed proof. Unpinned, so the test
    /// writes nothing under `~/.jig`.
    #[tokio::test]
    async fn a_wrong_audience_is_proven_afresh_and_retried_once() {
        let server = integration_tests::harness::TestJigServer::start_with_full_kinds()
            .await
            .expect("server");
        let base = server.http_url();
        let who = integration_tests::harness::test_identity();
        let stale = integration_tests::harness::test_identity().did_string();
        remember(&base, Trust::Unpinned, &stale);

        let url = format!("{base}/api/v1/channels");
        let http = reqwest::Client::new();
        let resp = send_as(&base, Trust::Unpinned, &who, "GET", &url, b"", || {
            http.get(&url)
        })
        .await
        .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            AUDIENCES
                .lock()
                .unwrap()
                .get(&(Trust::Unpinned, key(&base)))
                .cloned(),
            Some(server.server_did_string.clone()),
            "the audience the welcome proved replaces the stale one"
        );
    }

    /// A 401 too long to be a refusal is an error, never read as one.
    #[tokio::test]
    async fn an_oversized_refusal_is_an_error() {
        let mut r = http::Response::new("x".repeat(REFUSAL_BYTES + 1));
        *r.status_mut() = reqwest::StatusCode::UNAUTHORIZED;
        let err = wrong_audience(reqwest::Response::from(r))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("reading a refusal"), "{err:#}");
    }

    /// A server that accepts the connection and never answers is given up on
    /// before anything is signed.
    #[tokio::test]
    async fn a_server_that_never_answers_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        // Accept, and hold the socket open without a word.
        let _held = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
            drop(socket);
        });
        let who = integration_tests::harness::test_identity();
        let within = std::time::Duration::from_millis(300);
        let err = audience_within(&url, &who, Trust::Unpinned, within)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("did not complete a handshake"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn a_wrong_audience_refusal_is_told_apart_and_kept_whole() {
        let refusal = |code: &str| {
            let body = serde_json::json!({"code": code, "message": "m"}).to_string();
            let mut r = http::Response::new(body);
            *r.status_mut() = reqwest::StatusCode::UNAUTHORIZED;
            reqwest::Response::from(r)
        };
        let Err(kept) = wrong_audience(refusal(WRONG_AUDIENCE)).await.unwrap() else {
            panic!("WRONG_AUDIENCE must be told apart");
        };
        assert!(kept.text().await.unwrap().contains(WRONG_AUDIENCE));
        let Ok(other) = wrong_audience(refusal("INVALID_SIG")).await.unwrap() else {
            panic!("another refusal is passed through");
        };
        assert_eq!(other.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(other.text().await.unwrap().contains("INVALID_SIG"));
    }
}
