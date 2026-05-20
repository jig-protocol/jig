//! Integration tests for pricing configuration.

use jig_config::pricing::{FuelBand, MeteringMode, PricingConfig, PricingModel, ReputationTier};
use jig_config::profiles::Profile;

#[test]
fn test_pricing_potato_is_free() {
    let config = PricingConfig::default_for_profile(Profile::Potato);

    assert_eq!(config.model, PricingModel::Free);
    assert!(config.free_tier.is_some());
    assert!(config.fuel_bands.is_empty());
    assert!(!config.useful_work_discounts.enabled);
}

#[test]
fn test_pricing_standard_is_outcome_based() {
    let config = PricingConfig::default_for_profile(Profile::Standard);

    assert_eq!(config.model, PricingModel::OutcomeBased);
    assert!(config.free_tier.is_none());
    assert_eq!(config.fuel_bands.len(), 2);
    assert!(config.useful_work_discounts.enabled);
}

#[test]
fn test_pricing_hyperscale_has_all_fuel_bands() {
    let config = PricingConfig::default_for_profile(Profile::Hyperscale);

    assert_eq!(config.model, PricingModel::OutcomeBased);
    assert_eq!(config.fuel_bands.len(), 4);

    // Verify all capability types
    assert!(config.get_fuel_band("cpu").is_some());
    assert!(config.get_fuel_band("bandwidth").is_some());
    assert!(config.get_fuel_band("crypto").is_some());
    assert!(config.get_fuel_band("storage").is_some());
}

#[test]
fn test_fuel_band_cost_fields() {
    let config = PricingConfig::default_for_profile(Profile::Hyperscale);

    // CPU band uses cost_per_million
    let cpu = config.get_fuel_band("cpu").unwrap();
    assert_eq!(cpu.cost_per_million, Some(0.001));
    assert!(cpu.cost_per_gb.is_none());

    // Bandwidth band uses cost_per_gb
    let bandwidth = config.get_fuel_band("bandwidth").unwrap();
    assert_eq!(bandwidth.cost_per_gb, Some(0.05));
    assert!(bandwidth.cost_per_million.is_none());

    // Crypto band uses cost_per_operation
    let crypto = config.get_fuel_band("crypto").unwrap();
    assert_eq!(crypto.cost_per_operation, Some(0.0001));

    // Storage band uses cost_per_gb_hour
    let storage = config.get_fuel_band("storage").unwrap();
    assert_eq!(storage.cost_per_gb_hour, Some(0.0001));
}

#[test]
fn test_metering_modes_match_capability_types() {
    let config = PricingConfig::default_for_profile(Profile::Hyperscale);

    assert_eq!(
        config.get_fuel_band("cpu").unwrap().metering_mode,
        MeteringMode::Fuel
    );
    assert_eq!(
        config.get_fuel_band("bandwidth").unwrap().metering_mode,
        MeteringMode::Bandwidth
    );
    assert_eq!(
        config.get_fuel_band("crypto").unwrap().metering_mode,
        MeteringMode::Operations
    );
    assert_eq!(
        config.get_fuel_band("storage").unwrap().metering_mode,
        MeteringMode::Storage
    );
}

#[test]
fn test_useful_work_discounts_scale_with_profile() {
    let potato = PricingConfig::default_for_profile(Profile::Potato);
    assert!(!potato.useful_work_discounts.enabled);

    let standard = PricingConfig::default_for_profile(Profile::Standard);
    assert!(standard.useful_work_discounts.enabled);
    assert_eq!(standard.useful_work_discounts.verified_discount_pct, 25);
    assert_eq!(standard.useful_work_discounts.min_streak_days, 7);

    let hyperscale = PricingConfig::default_for_profile(Profile::Hyperscale);
    assert!(hyperscale.useful_work_discounts.enabled);
    assert_eq!(hyperscale.useful_work_discounts.verified_discount_pct, 40);
    assert_eq!(hyperscale.useful_work_discounts.min_streak_days, 30);
}

#[test]
fn test_discount_calculation_requires_minimum_streak() {
    let config = PricingConfig::default_for_profile(Profile::Hyperscale);

    // Below minimum (30 days)
    assert_eq!(config.calculate_discount(ReputationTier::Verified, 10), 0);
    assert_eq!(config.calculate_discount(ReputationTier::HighSec, 10), 0);

    // At minimum
    assert_eq!(config.calculate_discount(ReputationTier::Verified, 30), 40);
    assert_eq!(config.calculate_discount(ReputationTier::HighSec, 30), 25);

    // Above minimum
    assert_eq!(config.calculate_discount(ReputationTier::Verified, 365), 40);
}

#[test]
fn test_discount_calculation_respects_max_cap() {
    let mut config = PricingConfig::default_for_profile(Profile::Hyperscale);
    config.useful_work_discounts.verified_discount_pct = 70; // Over cap
    config.useful_work_discounts.max_discount_pct = 50; // Cap at 50%

    let discount = config.calculate_discount(ReputationTier::Verified, 30);
    assert_eq!(discount, 50); // Capped
}

#[test]
fn test_discount_tiers_increase_monotonically() {
    let config = PricingConfig::default_for_profile(Profile::Hyperscale);

    let null_sec = config.calculate_discount(ReputationTier::NullSec, 30);
    let low_sec = config.calculate_discount(ReputationTier::LowSec, 30);
    let high_sec = config.calculate_discount(ReputationTier::HighSec, 30);
    let verified = config.calculate_discount(ReputationTier::Verified, 30);

    assert!(null_sec <= low_sec);
    assert!(low_sec <= high_sec);
    assert!(high_sec <= verified);
}

#[test]
fn test_outcome_adjustments_defaults() {
    let config = PricingConfig::default();

    assert!(config.outcome_adjustments.charge_on_success);
    assert!(!config.outcome_adjustments.charge_on_soft_fail);
    assert!(!config.outcome_adjustments.charge_on_hard_fail);
    assert_eq!(config.outcome_adjustments.soft_fail_refund_pct, 100);
    assert_eq!(config.outcome_adjustments.hard_fail_refund_pct, 100);
}

#[test]
fn test_validation_rejects_empty_capability_type() {
    let mut config = PricingConfig::default();
    config.fuel_bands.push(FuelBand {
        capability_type: String::new(),
        cost_per_million: Some(0.001),
        cost_per_gb: None,
        cost_per_operation: None,
        cost_per_gb_hour: None,
        metering_mode: MeteringMode::Fuel,
    });

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("capability_type cannot be empty")
    );
}

#[test]
fn test_validation_rejects_fuel_band_without_cost() {
    let mut config = PricingConfig::default();
    config.fuel_bands.push(FuelBand {
        capability_type: "test".to_string(),
        cost_per_million: None,
        cost_per_gb: None,
        cost_per_operation: None,
        cost_per_gb_hour: None,
        metering_mode: MeteringMode::Fuel,
    });

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("must have at least one cost field")
    );
}

#[test]
fn test_validation_rejects_excessive_discounts() {
    let mut config = PricingConfig::default();
    config.useful_work_discounts.enabled = true;
    config.useful_work_discounts.verified_discount_pct = 150;

    assert!(config.validate().is_err());
    assert!(config.validate().unwrap_err().contains("cannot exceed 100"));
}

#[test]
fn test_validation_rejects_excessive_refunds() {
    let mut config = PricingConfig::default();
    config.outcome_adjustments.soft_fail_refund_pct = 150;

    assert!(config.validate().is_err());
    assert!(config.validate().unwrap_err().contains("cannot exceed 100"));
}

#[test]
fn test_toml_deserialization_basic() {
    let toml = r#"
        model = "outcome_based"

        [[fuel_bands]]
        capability_type = "cpu"
        cost_per_million = 0.001
        metering_mode = "fuel"

        [[fuel_bands]]
        capability_type = "bandwidth"
        cost_per_gb = 0.05
        metering_mode = "bandwidth"

        [useful_work_discounts]
        enabled = true
        verified_discount_pct = 25
        min_streak_days = 30

        [outcome_adjustments]
        charge_on_success = true
        charge_on_soft_fail = false
    "#;

    let config: PricingConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.model, PricingModel::OutcomeBased);
    assert_eq!(config.fuel_bands.len(), 2);
    assert!(config.useful_work_discounts.enabled);
    assert!(config.outcome_adjustments.charge_on_success);
}

#[test]
fn test_toml_serialization_roundtrip() {
    let config = PricingConfig::default_for_profile(Profile::Hyperscale);

    // Serialize to TOML
    let toml_str = toml::to_string(&config).expect("failed to serialize");

    // Deserialize back
    let parsed: PricingConfig = toml::from_str(&toml_str).expect("failed to deserialize");

    // Should match original
    assert_eq!(config.model, parsed.model);
    assert_eq!(config.fuel_bands.len(), parsed.fuel_bands.len());
    assert_eq!(
        config.useful_work_discounts.enabled,
        parsed.useful_work_discounts.enabled
    );
}

#[test]
fn test_pricing_model_serialization() {
    assert_eq!(
        serde_json::to_string(&PricingModel::Free).unwrap(),
        r#""free""#
    );
    assert_eq!(
        serde_json::to_string(&PricingModel::OutcomeBased).unwrap(),
        r#""outcome_based""#
    );
    assert_eq!(
        serde_json::to_string(&PricingModel::TimeBased).unwrap(),
        r#""time_based""#
    );
}

#[test]
fn test_metering_mode_serialization() {
    assert_eq!(
        serde_json::to_string(&MeteringMode::Fuel).unwrap(),
        r#""fuel""#
    );
    assert_eq!(
        serde_json::to_string(&MeteringMode::Bandwidth).unwrap(),
        r#""bandwidth""#
    );
    assert_eq!(
        serde_json::to_string(&MeteringMode::Operations).unwrap(),
        r#""operations""#
    );
    assert_eq!(
        serde_json::to_string(&MeteringMode::Storage).unwrap(),
        r#""storage""#
    );
}

#[test]
fn test_reputation_tier_serialization() {
    assert_eq!(
        serde_json::to_string(&ReputationTier::NullSec).unwrap(),
        r#""null_sec""#
    );
    assert_eq!(
        serde_json::to_string(&ReputationTier::Verified).unwrap(),
        r#""verified""#
    );
}

#[test]
fn test_free_tier_limits() {
    let config = PricingConfig::default_for_profile(Profile::Potato);

    let limits = config.free_tier.expect("potato should have free tier");
    assert_eq!(limits.fuel_per_month, 1_000_000_000);
    assert_eq!(limits.bandwidth_per_month, 10 * 1024 * 1024 * 1024);
    assert_eq!(limits.operations_per_month, 10_000);
}

#[test]
fn test_custom_profile_pricing_defaults() {
    let config = PricingConfig::default_for_profile(Profile::Custom);

    assert_eq!(config.model, PricingModel::Free);
    assert!(config.fuel_bands.is_empty());
    assert!(!config.useful_work_discounts.enabled);
}
