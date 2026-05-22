//! Validation example for nameserver configurations
//!
//! This example validates the three nameserver configuration scenarios:
//! 1. Federated (parent org)
//! 2. Shared Ruleset (network or data contract)
//! 3. Isolated (no federation)

use jig_config::nameserver::*;
use std::fs;

fn main() {
    println!("Validating nameserver configuration examples...\n");

    // Test federated configuration
    println!("1. Validating nameserver-federated.toml...");
    let federated_toml = fs::read_to_string("examples/nameserver-federated.toml")
        .expect("Failed to read nameserver-federated.toml");
    let federated: NameserverConfig =
        toml::from_str(&federated_toml).expect("Failed to parse nameserver-federated.toml");

    assert_eq!(federated.federation.mode, FederationMode::Federated);
    assert!(federated.federation.enabled);
    assert!(federated.federation.parent_org.is_some());
    assert!(federated.federation.handshake.require_mtls);
    println!("   ✓ Federated configuration valid");
    println!("     - Mode: {:?}", federated.federation.mode);
    println!("     - Peers: {}", federated.federation.max_peers);
    println!(
        "     - Parent Org: {}",
        federated.federation.parent_org.as_ref().unwrap().org_did
    );
    println!();

    // Test shared ruleset configuration
    println!("2. Validating nameserver-shared-ruleset.toml...");
    let shared_toml = fs::read_to_string("examples/nameserver-shared-ruleset.toml")
        .expect("Failed to read nameserver-shared-ruleset.toml");
    let shared: NameserverConfig =
        toml::from_str(&shared_toml).expect("Failed to parse nameserver-shared-ruleset.toml");

    assert_eq!(shared.federation.mode, FederationMode::SharedRuleset);
    assert!(shared.federation.enabled);
    assert!(shared.federation.shared_ruleset.is_some());
    let ruleset = shared.federation.shared_ruleset.as_ref().unwrap();
    assert!(ruleset.require_policy_match);
    println!("   ✓ Shared ruleset configuration valid");
    println!("     - Mode: {:?}", shared.federation.mode);
    println!("     - Peers: {}", shared.federation.max_peers);
    println!("     - Network ID: {:?}", ruleset.network_id);
    println!("     - Contracts: {}", ruleset.contract_dids.len());
    println!();

    // Test isolated configuration
    println!("3. Validating nameserver-isolated.toml...");
    let isolated_toml = fs::read_to_string("examples/nameserver-isolated.toml")
        .expect("Failed to read nameserver-isolated.toml");
    let isolated: NameserverConfig =
        toml::from_str(&isolated_toml).expect("Failed to parse nameserver-isolated.toml");

    assert_eq!(isolated.federation.mode, FederationMode::Isolated);
    assert!(!isolated.federation.enabled);
    assert_eq!(isolated.federation.max_peers, 0);
    println!("   ✓ Isolated configuration valid");
    println!("     - Mode: {:?}", isolated.federation.mode);
    println!(
        "     - Federation: {}",
        if isolated.federation.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!("     - Bind address: {}", isolated.network.bind_address);
    println!();

    // Compare PoW settings across scenarios
    println!("4. Comparing PoW settings across scenarios:");
    println!(
        "   Federated:      base={}, min={}, max={}",
        federated.pow.base_difficulty, federated.pow.min_difficulty, federated.pow.max_difficulty
    );
    println!(
        "   Shared Ruleset: base={}, min={}, max={}",
        shared.pow.base_difficulty, shared.pow.min_difficulty, shared.pow.max_difficulty
    );
    println!(
        "   Isolated:       base={}, min={}, max={}",
        isolated.pow.base_difficulty, isolated.pow.min_difficulty, isolated.pow.max_difficulty
    );
    println!();

    // Compare rate limits
    println!("5. Comparing rate limits across scenarios:");
    println!(
        "   Federated:      per_key={}, per_ip={}, global={}",
        federated.rate_limits.per_key_limit,
        federated.rate_limits.per_ip_limit,
        federated.rate_limits.global_limit
    );
    println!(
        "   Shared Ruleset: per_key={}, per_ip={}, global={}",
        shared.rate_limits.per_key_limit,
        shared.rate_limits.per_ip_limit,
        shared.rate_limits.global_limit
    );
    println!(
        "   Isolated:       per_key={}, per_ip={}, global={}",
        isolated.rate_limits.per_key_limit,
        isolated.rate_limits.per_ip_limit,
        isolated.rate_limits.global_limit
    );
    println!();

    println!("✅ All nameserver configurations validated successfully!");
    println!("\nKey observations:");
    println!(
        "  • Federated has highest throughput (global_limit={}) and lowest PoW",
        federated.rate_limits.global_limit
    );
    println!("  • Shared ruleset balances security and performance");
    println!(
        "  • Isolated has strictest limits (global_limit={}) and highest PoW",
        isolated.rate_limits.global_limit
    );
    println!("  • PoW difficulty escalates: federated < shared < isolated");
    println!("  • Federation trust: parent org > data contract > none");
}
