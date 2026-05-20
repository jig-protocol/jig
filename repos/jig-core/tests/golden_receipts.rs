use cid::Cid;
use jig_core::capability_scope::{CapabilityScopePattern, CapabilityUsageKey};
use jig_core::receipt::{
    BlockReceipt, BlockReceiptBuilder, CountersBuilder, Limits, Outcome, OutcomeStatus, ReasonCode,
    Timings,
};
use time::OffsetDateTime;

fn parse_cid() -> Cid {
    "bafkreigh2akiscaildcw453u6enm6kdwy5cae2f5z5ky3g4zz6p3r6jwhu"
        .parse()
        .expect("valid cid")
}

fn fixed_timestamp() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("timestamp")
}

fn receipt_ok() -> BlockReceipt {
    let usage = CapabilityUsageKey::without_scope("core:compute");
    let counters = CountersBuilder::new()
        .fuel_total(42)
        .add_fuel(&usage, 42)
        .bytes_tx(128)
        .bytes_rx(512)
        .build();

    BlockReceiptBuilder::new(parse_cid())
        .host("did:jig:server:ok")
        .executed_at(fixed_timestamp())
        .render_hash("sha256:abcdef")
        .renders_match(true)
        .fuel_used(42)
        .memory_peak_mb(8)
        .counters(counters)
        .timings(Timings::new(3, 2, 15))
        .limits(Limits {
            fuel_max: 100,
            memory_max_mb: 16,
            execution_timeout_ms: 200,
        })
        .outcome(Outcome {
            status: OutcomeStatus::Ok,
            affordances: vec!["email.delivered".to_string()],
            reason: None,
        })
        .capability("core:compute")
        .build()
        .expect("receipt ok")
}

fn receipt_soft_fail() -> BlockReceipt {
    let scope = CapabilityScopePattern::parse("https://api.example.com/orders/*").unwrap();
    let usage = CapabilityUsageKey::with_scope("net:http:fetch", scope.clone());
    let counters = CountersBuilder::new()
        .fuel_total(64)
        .add_fuel(&usage, 64)
        .add_status(&usage, "net_timeout")
        .bytes_tx(256)
        .bytes_rx(0)
        .build();

    BlockReceiptBuilder::new(parse_cid())
        .host("did:jig:server:soft")
        .executed_at(fixed_timestamp())
        .render_hash("sha256:123456")
        .renders_match(false)
        .fuel_used(64)
        .memory_peak_mb(10)
        .counters(counters)
        .timings(Timings::new(5, 3, 20))
        .limits(Limits {
            fuel_max: 200,
            memory_max_mb: 32,
            execution_timeout_ms: 500,
        })
        .outcome(Outcome {
            status: OutcomeStatus::SoftFail,
            affordances: Vec::new(),
            reason: Some(ReasonCode::NetTimeout),
        })
        .capability_with_scope("net:http:fetch", &scope)
        .build()
        .expect("receipt soft fail")
}

fn receipt_hard_fail() -> BlockReceipt {
    let scope = CapabilityScopePattern::parse("https://api.example.com/orders/*").unwrap();
    let usage = CapabilityUsageKey::with_scope("net:http:fetch", scope.clone());
    let counters = CountersBuilder::new()
        .fuel_total(0)
        .add_status(&usage, "capability_denied")
        .build();

    BlockReceiptBuilder::new(parse_cid())
        .host("did:jig:server:hard")
        .executed_at(fixed_timestamp())
        .render_hash("sha256:deadbeef")
        .renders_match(false)
        .fuel_used(0)
        .memory_peak_mb(0)
        .counters(counters)
        .timings(Timings::new(2, 1, 4))
        .limits(Limits {
            fuel_max: 50,
            memory_max_mb: 8,
            execution_timeout_ms: 100,
        })
        .outcome(Outcome {
            status: OutcomeStatus::HardFail,
            affordances: Vec::new(),
            reason: Some(ReasonCode::CapabilityDenied),
        })
        .capability_with_scope("net:http:fetch", &scope)
        .build()
        .expect("receipt hard fail")
}

fn compare_fixture(receipt: &BlockReceipt, fixture: &str) {
    let actual = String::from_utf8(receipt.to_canonical_bytes().expect("canonical")).expect("utf8");
    assert_eq!(actual, fixture.trim(), "canonical bytes mismatch");

    let parsed: BlockReceipt = serde_json::from_str(fixture).expect("parse fixture");
    assert_eq!(parsed, *receipt, "fixture does not round-trip to receipt");
}

#[test]
fn golden_receipt_ok() {
    let fixture = include_str!("fixtures/receipt_ok.json");
    compare_fixture(&receipt_ok(), fixture);
}

#[test]
fn golden_receipt_soft_fail() {
    let fixture = include_str!("fixtures/receipt_soft_fail.json");
    compare_fixture(&receipt_soft_fail(), fixture);
}

#[test]
fn golden_receipt_hard_fail() {
    let fixture = include_str!("fixtures/receipt_hard_fail.json");
    compare_fixture(&receipt_hard_fail(), fixture);
}
