//! Integration tests for profile system and override mechanism.

use jig_config::{execution::ExecutionConstraints, profiles::Profile};

#[test]
fn test_profile_cascade() {
    // Potato is the base
    let potato = ExecutionConstraints::default_for_profile(Profile::Potato);

    // Standard extends Potato with higher limits
    let standard = ExecutionConstraints::default_for_profile(Profile::Standard);
    assert!(standard.fuel_max > potato.fuel_max);
    assert!(standard.memory_max_mb > potato.memory_max_mb);
    assert!(standard.execution_timeout_ms > potato.execution_timeout_ms);

    // Hyperscale extends Standard with even higher limits
    let hyperscale = ExecutionConstraints::default_for_profile(Profile::Hyperscale);
    assert!(hyperscale.fuel_max > standard.fuel_max);
    assert!(hyperscale.memory_max_mb > standard.memory_max_mb);
    assert!(hyperscale.execution_timeout_ms > standard.execution_timeout_ms);

    // All maintain determinism
    assert!(potato.deterministic);
    assert!(standard.deterministic);
    assert!(hyperscale.deterministic);
}

#[test]
fn test_profile_inheritance_chain() {
    // Verify inheritance relationships
    assert_eq!(Profile::Potato.base_profile(), None);
    assert_eq!(Profile::Standard.base_profile(), Some(Profile::Potato));
    assert_eq!(Profile::Hyperscale.base_profile(), Some(Profile::Standard));
    assert_eq!(Profile::Custom.base_profile(), None);
}

#[test]
fn test_execution_constraints_merge() {
    // Start with Potato
    let mut base = ExecutionConstraints::default_for_profile(Profile::Potato);
    assert_eq!(base.fuel_max, 1_000_000);
    assert_eq!(base.memory_max_mb, 32);

    // Apply Standard overrides
    let standard_overrides = ExecutionConstraints {
        fuel_max: 5_000_000,
        memory_max_mb: 64,
        execution_timeout_ms: 500,
        deterministic: true,
        import_allowlist: vec!["jig_host::*".to_string()],
    };

    base.merge(&standard_overrides);

    // Verify merge applied
    assert_eq!(base.fuel_max, 5_000_000);
    assert_eq!(base.memory_max_mb, 64);
    assert_eq!(base.execution_timeout_ms, 500);
    assert!(base.deterministic);
}

#[test]
fn test_partial_override_preserves_base() {
    let mut base = ExecutionConstraints::default_for_profile(Profile::Potato);
    let original_timeout = base.execution_timeout_ms;

    // Override only fuel, leave other fields untouched
    let partial_override = ExecutionConstraints {
        fuel_max: 10_000_000,
        memory_max_mb: 0,        // Sentinel: don't override
        execution_timeout_ms: 0, // Sentinel: don't override
        deterministic: true,
        import_allowlist: vec![],
    };

    base.merge(&partial_override);

    // Fuel changed
    assert_eq!(base.fuel_max, 10_000_000);

    // Memory and timeout preserved from base
    assert_eq!(base.memory_max_mb, 32); // Original Potato value
    assert_eq!(base.execution_timeout_ms, original_timeout);
}

#[test]
fn test_deterministic_override() {
    let mut base = ExecutionConstraints::default_for_profile(Profile::Potato);
    assert!(base.deterministic);

    // Explicitly relax determinism (for testing only)
    let relaxed = ExecutionConstraints {
        fuel_max: 0,
        memory_max_mb: 0,
        execution_timeout_ms: 0,
        deterministic: false, // Explicit override
        import_allowlist: vec![],
    };

    base.merge(&relaxed);

    // Determinism was overridden
    assert!(!base.deterministic);
}

#[test]
fn test_import_allowlist_override() {
    let mut base = ExecutionConstraints::default_for_profile(Profile::Potato);
    let original_allowlist = base.import_allowlist.clone();
    assert!(!original_allowlist.is_empty());

    // Replace allowlist
    let custom_allowlist = vec!["custom::api::*".to_string(), "debug::*".to_string()];
    let override_constraints = ExecutionConstraints {
        fuel_max: 0,
        memory_max_mb: 0,
        execution_timeout_ms: 0,
        deterministic: true,
        import_allowlist: custom_allowlist.clone(),
    };

    base.merge(&override_constraints);

    // Allowlist was replaced
    assert_eq!(base.import_allowlist, custom_allowlist);
    assert_ne!(base.import_allowlist, original_allowlist);
}

#[test]
fn test_validation_prevents_invalid_overrides() {
    // Valid base
    let valid = ExecutionConstraints::default_for_profile(Profile::Potato);
    assert!(valid.validate().is_ok());

    // Create invalid override (zero fuel)
    let mut invalid = valid.clone();
    invalid.fuel_max = 0;
    assert!(invalid.validate().is_err());

    // Create invalid override (excessive memory)
    let mut invalid = valid.clone();
    invalid.memory_max_mb = 2048; // Over 1GB limit
    assert!(invalid.validate().is_err());

    // Create invalid override (excessive timeout)
    let mut invalid = valid.clone();
    invalid.execution_timeout_ms = 120_000; // Over 60s limit
    assert!(invalid.validate().is_err());
}

#[test]
fn test_profile_auto_start_behavior() {
    // Potato and Standard auto-start for quick setup
    assert!(Profile::Potato.auto_start());
    assert!(Profile::Standard.auto_start());

    // Hyperscale requires explicit service management
    assert!(!Profile::Hyperscale.auto_start());
    assert!(!Profile::Custom.auto_start());
}

#[test]
fn test_profile_concurrency_scaling() {
    // Concurrency limits scale with profile
    let potato_limit = Profile::Potato.max_concurrent_blocks();
    let standard_limit = Profile::Standard.max_concurrent_blocks();
    let hyperscale_limit = Profile::Hyperscale.max_concurrent_blocks();

    assert!(potato_limit < standard_limit);
    assert!(standard_limit < hyperscale_limit);

    // Verify specific values match expectations
    assert_eq!(potato_limit, 10);
    assert_eq!(standard_limit, 100);
    assert_eq!(hyperscale_limit, 10_000);
}

#[test]
fn test_custom_profile_starts_blank() {
    let custom = ExecutionConstraints::default_for_profile(Profile::Custom);

    // Custom has conservative defaults but empty allowlist
    assert!(custom.import_allowlist.is_empty());
    assert!(custom.deterministic); // Strict by default

    // Requires explicit configuration
    assert!(Profile::Custom.base_profile().is_none());
}

#[test]
fn test_profile_to_string_and_from_str() {
    let profiles = vec![
        Profile::Potato,
        Profile::Standard,
        Profile::Hyperscale,
        Profile::Custom,
    ];

    for profile in profiles {
        let stringified = profile.to_string();
        let parsed: Profile = stringified.parse().unwrap();
        assert_eq!(parsed, profile);
    }
}
