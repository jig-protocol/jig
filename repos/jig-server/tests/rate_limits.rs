//! `[auth.rate_limit]`: per-DID and per-address token buckets in front of
//! the gates.

mod support;

use std::time::Instant;

use axum::http::StatusCode;
use jig_client::blocks::build_text_render;
use jig_config::v0_0_2_server::{JigServerConfig, RateLimitSection};
use jig_core::HlcTimestamp;
use support::{Identity, TestServer};

/// Tight limits. They refill at 1/s, the slowest a rate can be (0 turns it
/// off), so a slow runner sees refills: count requests up to the first
/// refusal with [`assert_within_burst`] rather than assume exactly the burst.
fn limited(per_did_burst: u32, per_ip_burst: u32) -> TestServer {
    let mut config = JigServerConfig::default();
    config.auth.rate_limit = RateLimitSection {
        per_did_burst,
        per_did_per_second: 1,
        per_ip_burst,
        per_ip_per_second: 1,
        ..RateLimitSection::default()
    };
    TestServer::with_full_config(config)
}

/// `admitted` requests got in before the first refusal: the whole burst, and
/// no more than the burst plus one token for each second since `start`.
fn assert_within_burst(admitted: u32, burst: u32, start: Instant) {
    let refilled = start.elapsed().as_secs() as u32 + 1;
    assert!(
        (burst..=burst + refilled).contains(&admitted),
        "admitted {admitted} with a burst of {burst} over {:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn a_did_over_its_rate_is_refused_and_no_one_else_is() {
    let server = limited(3, 1_000);
    let (alice, bob) = (Identity::new(1), Identity::new(2));

    let start = Instant::now();
    let mut admitted = 0;
    let refused = loop {
        let (status, body) = server
            .send(&server.sign_get(&alice, "/api/v1/channels"))
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            break body;
        }
        assert_eq!(status, StatusCode::OK, "{body}");
        admitted += 1;
        assert!(admitted <= 64, "alice was never limited");
    };
    assert_eq!(refused["code"], "RATE_LIMITED");
    assert_within_burst(admitted, 3, start);

    let (status, body) = server
        .send(&server.sign_get(&bob, "/api/v1/channels"))
        .await;
    assert_eq!(status, StatusCode::OK, "bob has his own bucket: {body}");
}

/// Writes are charged to their author, whatever surface carried them.
#[tokio::test]
async fn writes_are_charged_to_their_author() {
    let server = limited(3, 1_000);
    let (owner, poster) = (Identity::new(1), Identity::new(2));
    server.create_channel(&owner, "#town", "open").await;

    let post = |n: u32| {
        let id = poster.as_client();
        let hlc = HlcTimestamp::now_wall(id.did().clone());
        build_text_render(&id, "#town", &format!("message {n}"), hlc)
    };
    let start = Instant::now();
    let mut admitted = 0;
    let refused = loop {
        let (status, body) = server.post_block(&post(admitted)).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            break body;
        }
        assert_eq!(status, StatusCode::OK, "{body}");
        admitted += 1;
        assert!(admitted <= 64, "the poster was never limited");
    };
    assert_eq!(refused["code"], "RATE_LIMITED");
    assert_within_burst(admitted, 3, start);
}

/// One address cannot outrun its limit by signing as many identities, or by
/// not signing at all: the address is charged before anything else.
#[tokio::test]
async fn an_address_over_its_rate_is_refused_before_any_gate() {
    let server = limited(1_000, 3);
    let flood: std::net::SocketAddr = "203.0.113.7:40000".parse().unwrap();
    let other: std::net::SocketAddr = "198.51.100.9:40000".parse().unwrap();

    let start = Instant::now();
    let mut admitted = 0;
    loop {
        let status = server.get_from(flood, "/api/v1/channels").await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "within its rate, an unsigned read reaches the gates and is refused there"
        );
        admitted += 1;
        assert!(admitted <= 64, "the address was never limited");
    }
    assert_within_burst(admitted, 3, start);
    assert_eq!(
        server.get_from(other, "/api/v1/channels").await,
        StatusCode::UNAUTHORIZED,
        "another address has its own bucket"
    );
}

#[tokio::test]
async fn a_rate_of_zero_turns_the_limit_off() {
    let mut config = JigServerConfig::default();
    config.auth.rate_limit.per_did_per_second = 0;
    config.auth.rate_limit.per_did_burst = 1;
    let server = TestServer::with_full_config(config);
    let alice = Identity::new(1);
    for _ in 0..5 {
        let (status, body) = server
            .send(&server.sign_get(&alice, "/api/v1/channels"))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}
