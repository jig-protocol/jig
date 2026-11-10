//! How much this client reads from a server or nameserver, at most.
//!
//! Every limit is what a legitimate peer can send, with headroom, so a
//! hostile or broken one cannot make the client hold more. Each read counts
//! the bytes it gets: a declared `Content-Length` past the limit only refuses
//! early. reqwest is built without response decompression, but the count is
//! of what the body stream yields, so it holds if that ever changes.
//!
//! Time is bounded separately: every client this crate and jig-cli build
//! sets a total request timeout, so a server that sends a byte a second
//! fails on time long before it fails on size.
//!
//! Not bounded yet: how many WebSocket messages the client queues. The
//! connection's reader hands each message to an unbounded channel, so a
//! server can still make a slow consumer hold many messages of up to
//! [`MAX_WS_MESSAGE_BYTES`] each.

use jig_core::bundle::MAX_ENVELOPE_BYTES;
use serde::de::DeserializeOwned;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// One WebSocket message from a server. The largest frame a server sends is
/// a `Block` delivery: the block's bundle in base64 with its signature,
/// record and receipts. The largest block a server takes is delivered in
/// 2 098 097 bytes (measured by `h_client_read_limits`), under this. It is
/// the same limit servers hold each other to (`[limits] max_ws_message_bytes`
/// on a federation link).
pub const MAX_WS_MESSAGE_BYTES: usize = MAX_ENVELOPE_BYTES;

/// One WebSocket frame: a message is never split, so the same.
pub const MAX_WS_FRAME_BYTES: usize = MAX_ENVELOPE_BYTES;

/// A JSON document that is not a page of blocks or records: a
/// `/.well-known/jig`, an admission status, a channel list, a submit's
/// answer. Each is a few kilobytes; a channel list of thousands of channels
/// stays well under this.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// What a nameserver or delegation host serves: a few hundred bytes each, and
/// a nameserver takes no request body past this either.
pub const MAX_NAMESERVER_BYTES: usize = 64 * 1024;

/// The part of an error response read for its message. Longer bodies are cut
/// here, not refused: a refusal's code must still reach the user.
pub const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// What one entry of a JSON page may add besides its payload: field names,
/// a delivery id, receipts.
const PAGE_OVERHEAD_BYTES: usize = 64 * 1024;

/// A page of `limit` blocks from a channel's history. Each entry is at most
/// one block envelope with its receipts and record, the same bound as a
/// [`MAX_WS_MESSAGE_BYTES`] delivery.
pub fn history_page_bytes(limit: usize) -> usize {
    limit
        .max(1)
        .saturating_mul(MAX_ENVELOPE_BYTES)
        .saturating_add(PAGE_OVERHEAD_BYTES)
}

/// A page of `limit` ingest records. A record is at most 4 KiB encoded
/// (`jig_pipeline::follow::MAX_RECORD_BYTES`); in JSON, with its hashes and
/// signature spelled out, well under 16 KiB.
pub fn records_page_bytes(limit: usize) -> usize {
    limit
        .max(1)
        .saturating_mul(16 * 1024)
        .saturating_add(PAGE_OVERHEAD_BYTES)
}

/// The WebSocket limits a client connects with.
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_WS_FRAME_BYTES))
}

/// Why a body could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("the response is larger than {max} bytes")]
    TooLarge { max: usize },
    #[error("reading the response: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("decoding the response: {0}")]
    Json(#[from] serde_json::Error),
}

/// The body of `resp`, refused once it passes `max` bytes.
pub async fn read_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>, ReadError> {
    if resp.content_length().is_some_and(|len| len > max as u64) {
        return Err(ReadError::TooLarge { max });
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > max {
            return Err(ReadError::TooLarge { max });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The body of `resp` as JSON, read as [`read_capped`] does.
pub async fn json_capped<T: DeserializeOwned>(
    resp: reqwest::Response,
    max: usize,
) -> Result<T, ReadError> {
    Ok(serde_json::from_slice(&read_capped(resp, max).await?)?)
}

/// The body of `resp` as text, cut at [`MAX_ERROR_BODY_BYTES`]: for the
/// message of a response that is already an error. A body that cannot be
/// read is empty.
pub async fn error_text(mut resp: reqwest::Response) -> String {
    let mut body = Vec::new();
    let mut cut = false;
    while let Ok(Some(chunk)) = resp.chunk().await {
        let room = MAX_ERROR_BODY_BYTES - body.len();
        if chunk.len() > room {
            body.extend_from_slice(&chunk[..room]);
            cut = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    let mut text = String::from_utf8_lossy(&body).into_owned();
    if cut {
        text.push_str(" […]");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    /// What a hostile server answers every request with.
    #[derive(Clone, Copy)]
    enum Answer {
        /// A chunked body that never ends.
        Endless,
        /// A declared length of a gigabyte, then nothing.
        HugeLength,
        /// A small gzip body that inflates to 8 MiB.
        Gzip,
    }

    const GZIP_8MIB: &[u8] = include_bytes!("../tests/data/zeros-8mib.gz");

    async fn answer<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, answer: Answer) {
        // The request head, up to its blank line.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if s.read(&mut byte).await.unwrap_or(0) == 0 {
                return;
            }
            head.push(byte[0]);
        }
        match answer {
            Answer::Endless => {
                let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                            transfer-encoding: chunked\r\n\r\n";
                if s.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                let chunk = format!("4000\r\n{}\r\n", " ".repeat(0x4000));
                while s.write_all(chunk.as_bytes()).await.is_ok() {}
            }
            Answer::HugeLength => {
                let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                            content-length: 1000000000\r\n\r\n";
                let _ = s.write_all(head.as_bytes()).await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            Answer::Gzip => {
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-encoding: gzip\r\ncontent-length: {}\r\n\r\n",
                    GZIP_8MIB.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(GZIP_8MIB).await;
            }
        }
    }

    /// A hostile server on loopback, over TLS with a self-signed certificate
    /// when `tls`. Returns its base URL.
    async fn hostile(a: Answer, tls: bool) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tls.then(|| {
            use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(ck.cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der())),
            )
            .unwrap();
            tokio_rustls::TlsAcceptor::from(Arc::new(config))
        });
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor {
                        Some(acc) => {
                            if let Ok(tls) = acc.accept(tcp).await {
                                answer(tls, a).await;
                            }
                        }
                        None => answer(tcp, a).await,
                    }
                });
            }
        });
        let scheme = if tls { "https" } else { "http" };
        format!("{scheme}://127.0.0.1:{}", addr.port())
    }

    async fn get(url: &str) -> reqwest::Response {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap()
            .get(url)
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn an_endless_body_is_refused_at_the_limit() {
        let base = hostile(Answer::Endless, false).await;
        let got = read_capped(get(&base).await, 256 * 1024).await;
        assert!(
            matches!(got, Err(ReadError::TooLarge { max: 262_144 })),
            "{got:?}"
        );
    }

    #[tokio::test]
    async fn a_declared_length_past_the_limit_is_refused_before_reading() {
        let base = hostile(Answer::HugeLength, false).await;
        let started = Instant::now();
        let got = read_capped(get(&base).await, MAX_DOCUMENT_BYTES).await;
        assert!(matches!(got, Err(ReadError::TooLarge { .. })), "{got:?}");
        // The server sends no body at all: only the early refusal ends this.
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_compressed_body_counts_what_it_inflates_to() {
        // reqwest here does not inflate: the 8 KiB arrive as they are. Were
        // it built to inflate, the count is of the 8 MiB it yields, and this
        // read is refused. Either way no more than the limit is held.
        let base = hostile(Answer::Gzip, false).await;
        match read_capped(get(&base).await, 1024 * 1024).await {
            Ok(body) => assert_eq!(body, GZIP_8MIB, "the body was inflated past the limit"),
            Err(e) => assert!(matches!(e, ReadError::TooLarge { .. }), "{e}"),
        }
    }

    #[tokio::test]
    async fn an_error_body_is_cut_not_refused() {
        let base = hostile(Answer::Endless, false).await;
        let text = error_text(get(&base).await).await;
        assert!(text.len() <= MAX_ERROR_BODY_BYTES + " […]".len());
        assert!(text.ends_with(" […]"));
    }

    // The well-known probes run before anything is pinned, against a server
    // nobody trusts yet.

    #[tokio::test]
    async fn the_unpinned_probe_refuses_an_endless_well_known() {
        let base = hostile(Answer::Endless, false).await;
        let err = crate::tls::probe(&base, None).await.err().expect("refused");
        assert!(err.to_string().contains("larger than"), "{err}");
    }

    #[tokio::test]
    async fn the_unpinned_probe_refuses_an_endless_well_known_over_tls() {
        let base = hostile(Answer::Endless, true).await;
        let err = crate::tls::probe(&base, None).await.err().expect("refused");
        assert!(err.to_string().contains("larger than"), "{err}");
    }

    #[tokio::test]
    async fn the_bound_probe_refuses_an_endless_well_known() {
        let base = hostile(Answer::Endless, true).await;
        let err = crate::tls::probe_self_bound(&base, "/.well-known/jig-ns")
            .await
            .err()
            .expect("refused");
        assert!(err.to_string().contains("larger than"), "{err}");
    }

    #[tokio::test]
    async fn the_bound_probe_refuses_a_declared_length_past_the_limit() {
        let base = hostile(Answer::HugeLength, true).await;
        let started = Instant::now();
        let err = crate::tls::probe_self_bound(&base, "/.well-known/jig-ns")
            .await
            .err()
            .expect("refused");
        assert!(err.to_string().contains("larger than"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_websocket_message_past_the_limit_ends_the_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            // A server with no limit of its own, sending one message larger
            // than any server legitimately sends.
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            use futures_util::SinkExt;
            let big = " ".repeat(MAX_WS_MESSAGE_BYTES + 1024 * 1024);
            let _ = ws
                .send(tokio_tungstenite::tungstenite::Message::Text(big.into()))
                .await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let dir = tempfile::tempdir().unwrap();
        let identity = crate::Identity::generate_for_tests(dir.path());
        let got = crate::Client::connect_with_options(
            &format!("http://127.0.0.1:{port}"),
            identity,
            crate::connection::ConnectOptions::default(),
        )
        .await;
        let Err(err) = got else {
            panic!("the oversized message is refused");
        };
        let text = err.to_string();
        assert!(
            text.contains("too long") || text.contains("limit"),
            "the connection should end on the size limit: {text}"
        );
    }
}
