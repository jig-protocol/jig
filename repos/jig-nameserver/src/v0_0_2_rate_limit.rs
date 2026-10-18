//! Rate limits for the v0.0.2 alias-mutating routes (`POST /v1/register`,
//! `/v1/rotate`, `/v1/renew`).
//!
//! A middleware layer in front of the handlers, so the handlers stay
//! untouched. Two kinds of bucket:
//!
//! - **Per client IP**, charged before the handler runs, for every request
//!   admitted.
//! - **Per DID** the body names (`did`, `old_did`, `new_did`), checked before
//!   the handler but charged only when the handler returns 2xx. Each of the
//!   three handlers verifies a signature by every DID it names before it can
//!   succeed (register and renew: `proof_of_control` over the challenge;
//!   rotate: `sig_by_old` and `sig_by_new`), so only a DID's key holder can
//!   use up its bucket. Forged requests naming a victim's DID cost the
//!   sender's IP bucket and leave the victim's untouched.
//!
//! A request is refused if any bucket it touches is full, and a refusal
//! charges nothing. Refusals are HTTP 429 with code `RATE_LIMITED` and a
//! `Retry-After` header. Because the DID charge lands after the handler, a
//! key holder sending requests concurrently can exceed their own DID limit
//! by the number in flight; their IP bucket still bounds them.
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

type Buckets = HashMap<String, (i64, u32)>;

/// Shared limiter state; clone the `Arc` into each router's layer.
pub struct AliasRateLimiter {
    cfg: AliasRateLimitConfig,
    network: NetworkConfig,
    buckets: Mutex<Buckets>,
}

impl AliasRateLimiter {
    pub fn new(cfg: AliasRateLimitConfig, network: NetworkConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            network,
            buckets: Mutex::new(HashMap::new()),
        })
    }

    /// Pre-handler gate. Refuses if the IP bucket or any named DID's bucket
    /// is full; otherwise charges the IP bucket only. On refusal, returns the
    /// seconds until the window resets.
    fn admit(&self, now_secs: i64, ip_key: &str, dids: &[String]) -> Result<(), u64> {
        let window = now_secs.div_euclid(WINDOW_SECS);
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() > PRUNE_THRESHOLD {
            buckets.retain(|_, (w, _)| *w == window);
        }
        let ip_full = used(&buckets, ip_key, window) >= self.cfg.per_ip_per_min;
        let did_full = dids
            .iter()
            .any(|d| used(&buckets, &did_key(d), window) >= self.cfg.per_did_per_min);
        if ip_full || did_full {
            return Err((WINDOW_SECS - now_secs.rem_euclid(WINDOW_SECS)) as u64);
        }
        bump(&mut buckets, ip_key.to_string(), window);
        Ok(())
    }

    /// Post-handler: charge each DID once the handler has verified its
    /// signature and succeeded.
    fn charge_dids(&self, now_secs: i64, dids: &[String]) {
        let window = now_secs.div_euclid(WINDOW_SECS);
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        for d in dids {
            bump(&mut buckets, did_key(d), window);
        }
    }

    /// The connection's peer address, or with `trust_proxy` the **last**
    /// entry of `proxy_ip_header`: the one the nearest proxy appended. Earlier
    /// entries were written by the client and can be anything.
    fn client_ip(&self, req: &Request) -> Option<IpAddr> {
        if self.network.trust_proxy
            && let Some(ip) = req
                .headers()
                .get(&self.network.proxy_ip_header)
                .and_then(|v| v.to_str().ok())
                .and_then(last_forwarded)
        {
            return Some(ip);
        }
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
    }
}

fn last_forwarded(header: &str) -> Option<IpAddr> {
    header.rsplit(',').next()?.trim().parse::<IpAddr>().ok()
}

/// Bucket key for a client address. IPv4-mapped IPv6 counts as its IPv4
/// address, and IPv6 is keyed by its /64, since one host can hold a whole
/// /64 and would otherwise get a fresh bucket per address.
fn ip_key(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => format!("ip:{v4}"),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let prefix = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
            format!("ip:{prefix}/64")
        }
    }
}

fn did_key(did: &str) -> String {
    format!("did:{did}")
}

fn used(buckets: &Buckets, key: &str, window: i64) -> u32 {
    match buckets.get(key) {
        Some((w, n)) if *w == window => *n,
        _ => 0,
    }
}

fn bump(buckets: &mut Buckets, key: String, window: i64) {
    let n = used(buckets, &key, window) + 1;
    buckets.insert(key, (window, n));
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
        Some(ip) => ip_key(ip),
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
    if let Err(retry_after) = limiter.admit(chrono::Utc::now().timestamp(), &ip_key, &dids) {
        return refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            format!("too many requests; retry in {retry_after}s"),
            Some(retry_after),
        );
    }
    let resp = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;
    if resp.status().is_success() {
        limiter.charge_dids(chrono::Utc::now().timestamp(), &dids);
    }
    resp
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
    fn per_did_limit_admits_exactly_the_limit_of_verified_requests() {
        let l = limiter(100, 3);
        let did = vec!["did:key:zA".to_string()];
        for i in 1..=3 {
            assert!(l.admit(T0, "ip:1", &did).is_ok(), "request {i} of 3");
            l.charge_dids(T0, &did); // the handler succeeded
        }
        assert_eq!(l.admit(T0 + 10, "ip:1", &did), Err(50), "request 4 refused");
        assert!(l.admit(T0 + 60, "ip:1", &did).is_ok(), "next window admits");
    }

    /// The targeted-DoS case: requests the handler rejects (forged
    /// signatures) never charge the DID they name, however many arrive.
    #[test]
    fn unverified_requests_do_not_use_up_a_did_bucket() {
        let l = limiter(1_000, 2);
        let victim = vec!["did:key:zVictim".to_string()];
        for _ in 0..50 {
            assert!(l.admit(T0, "ip:attacker", &victim).is_ok());
            // handler rejected the signature: no charge_dids
        }
        assert!(l.admit(T0, "ip:victim", &victim).is_ok());
    }

    #[test]
    fn per_ip_limit_admits_exactly_the_limit_across_dids() {
        let l = limiter(2, 100);
        assert!(l.admit(T0, "ip:1", &["did:a".into()]).is_ok());
        assert!(l.admit(T0, "ip:1", &["did:b".into()]).is_ok());
        assert!(l.admit(T0, "ip:1", &["did:c".into()]).is_err());
        assert!(
            l.admit(T0, "ip:2", &["did:c".into()]).is_ok(),
            "other IPs unaffected"
        );
    }

    #[test]
    fn a_refusal_charges_nothing() {
        let l = limiter(2, 1);
        let a = vec!["did:a".to_string()];
        assert!(l.admit(T0, "ip:1", &a).is_ok());
        l.charge_dids(T0, &a);
        // did:a is full, so this is refused and must not charge the IP.
        assert!(
            l.admit(T0, "ip:1", &["did:a".into(), "did:b".into()])
                .is_err()
        );
        assert!(
            l.admit(T0, "ip:1", &["did:b".into()]).is_ok(),
            "the IP still has its second slot"
        );
    }

    #[test]
    fn ipv6_is_keyed_per_slash_64_and_mapped_v4_as_v4() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b), "same /64 shares a bucket");
        assert_ne!(ip_key(a), ip_key(other), "different /64s do not");

        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        let plain: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(ip_key(mapped), ip_key(plain));
        assert_eq!(ip_key(plain), "ip:203.0.113.7");
    }

    #[test]
    fn forwarded_header_uses_the_last_entry() {
        assert_eq!(
            last_forwarded("1.2.3.4, 5.6.7.8"),
            Some("5.6.7.8".parse().unwrap()),
            "the client-written first entry is ignored"
        );
        assert_eq!(last_forwarded("5.6.7.8"), Some("5.6.7.8".parse().unwrap()));
        assert_eq!(last_forwarded("1.2.3.4, garbage"), None);
    }

    #[test]
    fn trusted_proxy_header_keys_on_the_proxy_appended_address() {
        let l = AliasRateLimiter::new(
            AliasRateLimitConfig::default(),
            NetworkConfig {
                trust_proxy: true,
                proxy_ip_header: "x-forwarded-for".into(),
                ..NetworkConfig::default()
            },
        );
        let req = Request::builder()
            .header("x-forwarded-for", "1.2.3.4, 5.6.7.8")
            .body(Body::empty())
            .unwrap();
        assert_eq!(l.client_ip(&req), Some("5.6.7.8".parse().unwrap()));
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
