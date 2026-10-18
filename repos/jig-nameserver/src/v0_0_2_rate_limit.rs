//! Rate limits for the v0.0.2 alias-mutating routes (`POST /v1/register`,
//! `/v1/rotate`, `/v1/renew`).
//!
//! A middleware layer in front of the handlers, so the handlers stay
//! untouched: it counts each request against the client's IP bucket and
//! against one bucket per DID the body names (`did`, `old_did`, `new_did`).
//! A request is admitted only if every bucket it touches has room, and only
//! an admitted request is counted. Refusals are HTTP 429 with code
//! `RATE_LIMITED` and a `Retry-After` header.
//!
//! Buckets are fixed one-minute windows held in memory, so limits reset on
//! restart and are per process. Proof of work (lane R) goes on top of this.

use crate::config::{AliasRateLimitConfig, NetworkConfig};
use crate::v0_0_2_register::ErrorBody;
use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, Method, StatusCode, header::RETRY_AFTER},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

/// Largest body the layer buffers to read the DIDs. The handlers' requests
/// are a few hundred bytes; anything bigger is refused before it is parsed.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Above this many tracked keys, buckets from earlier windows are dropped.
const PRUNE_THRESHOLD: usize = 10_000;

const WINDOW_SECS: i64 = 60;

/// Shared limiter state; clone the `Arc` into each router's layer.
pub struct AliasRateLimiter {
    cfg: AliasRateLimitConfig,
    network: NetworkConfig,
    buckets: Mutex<HashMap<String, (i64, u32)>>,
}

impl AliasRateLimiter {
    pub fn new(cfg: AliasRateLimitConfig, network: NetworkConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            network,
            buckets: Mutex::new(HashMap::new()),
        })
    }

    /// Admit or refuse one request touching `ip_key` and `did_keys` at
    /// `now_secs`. On refusal, returns the seconds until the window resets.
    fn check(&self, now_secs: i64, ip_key: &str, did_keys: &[String]) -> Result<(), u64> {
        let window = now_secs.div_euclid(WINDOW_SECS);
        let retry_after = (WINDOW_SECS - now_secs.rem_euclid(WINDOW_SECS)) as u64;

        let mut keys: Vec<(String, u32)> = vec![(ip_key.to_string(), self.cfg.per_ip_per_min)];
        for did in did_keys {
            keys.push((format!("did:{did}"), self.cfg.per_did_per_min));
        }

        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() > PRUNE_THRESHOLD {
            buckets.retain(|_, (w, _)| *w == window);
        }
        let used = |b: &HashMap<String, (i64, u32)>, k: &str| match b.get(k) {
            Some((w, n)) if *w == window => *n,
            _ => 0,
        };
        if keys.iter().any(|(k, limit)| used(&buckets, k) >= *limit) {
            return Err(retry_after);
        }
        for (k, _) in keys {
            let n = used(&buckets, &k) + 1;
            buckets.insert(k, (window, n));
        }
        Ok(())
    }

    fn client_ip(&self, req: &Request) -> Option<IpAddr> {
        if self.network.trust_proxy
            && let Some(ip) = req
                .headers()
                .get(&self.network.proxy_ip_header)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return Some(ip);
        }
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
    }
}

fn refuse(status: StatusCode, code: &str, message: String, retry_after: Option<u64>) -> Response {
    let mut resp = (
        status,
        Json(ErrorBody {
            code: code.to_string(),
            message,
        }),
    )
        .into_response();
    if let Some(secs) = retry_after
        && let Ok(v) = HeaderValue::from_str(&secs.to_string())
    {
        resp.headers_mut().insert(RETRY_AFTER, v);
    }
    resp
}

/// DIDs a register/rotate/renew body names. Unparseable bodies yield none
/// and are left for the handler to reject.
fn dids_in(body: &[u8]) -> Vec<String> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice(body) else {
        return Vec::new();
    };
    let mut dids: Vec<String> = ["did", "old_did", "new_did"]
        .iter()
        .filter_map(|k| map.get(*k).and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    dids.sort();
    dids.dedup();
    dids
}

/// `axum::middleware::from_fn_with_state` layer. Only POSTs are limited, so
/// the same layer can sit on a router that also serves `GET /v1/challenge`.
pub async fn limit(
    State(limiter): State<Arc<AliasRateLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    if !limiter.cfg.enabled || req.method() != Method::POST {
        return next.run(req).await;
    }
    let ip_key = match limiter.client_ip(&req) {
        Some(ip) => format!("ip:{ip}"),
        None => "ip:unknown".to_string(),
    };
    let (parts, body) = req.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
        return refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            "BODY_TOO_LARGE",
            format!("request body over {MAX_BODY_BYTES} bytes"),
            None,
        );
    };
    let dids = dids_in(&bytes);
    if let Err(retry_after) = limiter.check(chrono::Utc::now().timestamp(), &ip_key, &dids) {
        return refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            format!("too many requests; retry in {retry_after}s"),
            Some(retry_after),
        );
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(per_ip: u32, per_did: u32) -> Arc<AliasRateLimiter> {
        AliasRateLimiter::new(
            AliasRateLimitConfig {
                enabled: true,
                per_ip_per_min: per_ip,
                per_did_per_min: per_did,
            },
            NetworkConfig::default(),
        )
    }

    const T0: i64 = 1_800_000_000; // start of a window (divisible by 60)

    #[test]
    fn per_did_limit_admits_exactly_the_limit() {
        let l = limiter(100, 3);
        let did = vec!["did:key:zA".to_string()];
        for i in 1..=3 {
            assert!(l.check(T0, "ip:1", &did).is_ok(), "request {i} of 3");
        }
        assert_eq!(l.check(T0 + 10, "ip:1", &did), Err(50), "request 4 refused");
        // Refusals are not counted: the bucket stays at the limit, and the
        // next window admits again.
        assert!(l.check(T0 + 60, "ip:1", &did).is_ok());
    }

    #[test]
    fn per_ip_limit_admits_exactly_the_limit_across_dids() {
        let l = limiter(2, 100);
        assert!(l.check(T0, "ip:1", &["did:a".into()]).is_ok());
        assert!(l.check(T0, "ip:1", &["did:b".into()]).is_ok());
        assert!(l.check(T0, "ip:1", &["did:c".into()]).is_err());
        assert!(
            l.check(T0, "ip:2", &["did:c".into()]).is_ok(),
            "other IPs unaffected"
        );
    }

    #[test]
    fn a_refused_bucket_does_not_charge_the_others() {
        let l = limiter(100, 1);
        let a = vec!["did:a".to_string()];
        assert!(l.check(T0, "ip:1", &a).is_ok());
        // did:a is full, so this rotate (a -> b) is refused and must not use
        // up did:b's only slot.
        assert!(
            l.check(T0, "ip:1", &["did:a".into(), "did:b".into()])
                .is_err()
        );
        assert!(l.check(T0, "ip:1", &["did:b".into()]).is_ok());
    }

    #[test]
    fn dids_are_read_from_register_and_rotate_bodies() {
        assert_eq!(
            dids_in(br#"{"did":"did:key:zA","x":1}"#),
            vec!["did:key:zA"]
        );
        assert_eq!(
            dids_in(br#"{"old_did":"did:b","new_did":"did:a"}"#),
            vec!["did:a", "did:b"]
        );
        assert!(dids_in(b"not json").is_empty());
    }
}
