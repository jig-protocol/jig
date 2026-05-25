//! Pricing configuration for outcome-based metering and useful work incentives.
//!
//! Supports:
//! - Per-capability fuel bands (CPU, bandwidth, crypto, storage)
//! - Reputation-based useful work discounts
//! - Free, development, and paid pricing tiers
//! - Outcome adjustments (success vs failure pricing)

use serde::{Deserialize, Serialize};

use crate::profiles::Profile;

/// Pricing model type.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingModel {
    /// Free tier (no billing)
    #[default]
    Free,

    /// Outcome-based pricing (pay per execution outcome)
    OutcomeBased,

    /// Time-based pricing (pay per compute time)
    TimeBased,

    /// Custom pricing (user-defined)
    Custom,
}

/// Pricing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingConfig {
    /// Pricing model
    #[serde(default)]
    pub model: PricingModel,

    /// Per-capability fuel bands
    #[serde(default)]
    pub fuel_bands: Vec<FuelBand>,

    /// Useful work discounts (reputation-based)
    #[serde(default)]
    pub useful_work_discounts: UsefulWorkDiscounts,

    /// Outcome-based adjustments
    #[serde(default)]
    pub outcome_adjustments: OutcomeAdjustments,

    /// Free tier limits (when model = Free)
    #[serde(default)]
    pub free_tier: Option<FreeTierLimits>,
}

/// Fuel band for per-capability pricing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FuelBand {
    /// Capability type (e.g., "cpu", "bandwidth", "crypto", "storage")
    pub capability_type: String,

    /// Cost per million fuel units (for CPU/crypto)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_per_million: Option<f64>,

    /// Cost per gigabyte (for bandwidth)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_per_gb: Option<f64>,

    /// Cost per operation (for crypto)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_per_operation: Option<f64>,

    /// Cost per gigabyte-hour (for storage)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_per_gb_hour: Option<f64>,

    /// Metering mode
    #[serde(default = "default_metering_mode")]
    pub metering_mode: MeteringMode,
}

/// Metering mode for fuel consumption.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MeteringMode {
    /// Meter by fuel (CPU instructions)
    #[default]
    Fuel,

    /// Meter by bytes transferred
    Bandwidth,

    /// Meter by operation count
    Operations,

    /// Meter by storage capacity × time
    Storage,
}

/// Useful work discounts based on reputation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsefulWorkDiscounts {
    /// Enable useful work discounts
    #[serde(default = "default_false")]
    pub enabled: bool,

    /// Discount percentage for null-sec tier (unverified)
    #[serde(default)]
    pub null_sec_discount_pct: u8,

    /// Discount percentage for low-sec tier (some reputation)
    #[serde(default)]
    pub low_sec_discount_pct: u8,

    /// Discount percentage for high-sec tier (high reputation)
    #[serde(default)]
    pub high_sec_discount_pct: u8,

    /// Discount percentage for verified tier (verified identity)
    #[serde(default)]
    pub verified_discount_pct: u8,

    /// Minimum streak days to qualify for discount
    #[serde(default)]
    pub min_streak_days: u32,

    /// Maximum discount percentage (cap)
    #[serde(default = "default_max_discount")]
    pub max_discount_pct: u8,
}

/// Outcome-based pricing adjustments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeAdjustments {
    /// Charge for successful executions
    #[serde(default = "default_true")]
    pub charge_on_success: bool,

    /// Charge for soft failures
    #[serde(default = "default_false")]
    pub charge_on_soft_fail: bool,

    /// Charge for hard failures
    #[serde(default = "default_false")]
    pub charge_on_hard_fail: bool,

    /// Refund percentage for soft failures
    #[serde(default)]
    pub soft_fail_refund_pct: u8,

    /// Refund percentage for hard failures
    #[serde(default)]
    pub hard_fail_refund_pct: u8,
}

/// Free tier limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeTierLimits {
    /// Monthly fuel limit
    pub fuel_per_month: u64,

    /// Monthly bandwidth limit (bytes)
    pub bandwidth_per_month: u64,

    /// Monthly operation limit
    pub operations_per_month: u64,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            model: PricingModel::Free,
            fuel_bands: vec![],
            useful_work_discounts: UsefulWorkDiscounts::default(),
            outcome_adjustments: OutcomeAdjustments::default(),
            free_tier: Some(FreeTierLimits::default()),
        }
    }
}

impl Default for UsefulWorkDiscounts {
    fn default() -> Self {
        Self {
            enabled: false,
            null_sec_discount_pct: 0,
            low_sec_discount_pct: 0,
            high_sec_discount_pct: 0,
            verified_discount_pct: 0,
            min_streak_days: 0,
            max_discount_pct: 50, // Cap at 50%
        }
    }
}

impl Default for OutcomeAdjustments {
    fn default() -> Self {
        Self {
            charge_on_success: true,
            charge_on_soft_fail: false,
            charge_on_hard_fail: false,
            soft_fail_refund_pct: 100,
            hard_fail_refund_pct: 100,
        }
    }
}

impl Default for FreeTierLimits {
    fn default() -> Self {
        Self {
            fuel_per_month: 1_000_000_000,                // 1B fuel/month
            bandwidth_per_month: 10 * 1024 * 1024 * 1024, // 10 GB/month
            operations_per_month: 10_000,                 // 10K operations/month
        }
    }
}

impl PricingConfig {
    /// Create default pricing config for a given profile.
    pub fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self {
                model: PricingModel::Free,
                fuel_bands: vec![],
                useful_work_discounts: UsefulWorkDiscounts::default(),
                outcome_adjustments: OutcomeAdjustments::default(),
                free_tier: Some(FreeTierLimits::default()),
            },
            Profile::Standard => Self {
                model: PricingModel::OutcomeBased,
                fuel_bands: vec![
                    FuelBand {
                        capability_type: "cpu".to_string(),
                        cost_per_million: Some(0.001),
                        cost_per_gb: None,
                        cost_per_operation: None,
                        cost_per_gb_hour: None,
                        metering_mode: MeteringMode::Fuel,
                    },
                    FuelBand {
                        capability_type: "bandwidth".to_string(),
                        cost_per_million: None,
                        cost_per_gb: Some(0.05),
                        cost_per_operation: None,
                        cost_per_gb_hour: None,
                        metering_mode: MeteringMode::Bandwidth,
                    },
                ],
                useful_work_discounts: UsefulWorkDiscounts {
                    enabled: true,
                    null_sec_discount_pct: 0,
                    low_sec_discount_pct: 5,
                    high_sec_discount_pct: 15,
                    verified_discount_pct: 25,
                    min_streak_days: 7,
                    max_discount_pct: 50,
                },
                outcome_adjustments: OutcomeAdjustments {
                    charge_on_success: true,
                    charge_on_soft_fail: false,
                    charge_on_hard_fail: false,
                    soft_fail_refund_pct: 100,
                    hard_fail_refund_pct: 100,
                },
                free_tier: None,
            },
            Profile::Hyperscale => Self {
                model: PricingModel::OutcomeBased,
                fuel_bands: vec![
                    FuelBand {
                        capability_type: "cpu".to_string(),
                        cost_per_million: Some(0.001),
                        cost_per_gb: None,
                        cost_per_operation: None,
                        cost_per_gb_hour: None,
                        metering_mode: MeteringMode::Fuel,
                    },
                    FuelBand {
                        capability_type: "bandwidth".to_string(),
                        cost_per_million: None,
                        cost_per_gb: Some(0.05),
                        cost_per_operation: None,
                        cost_per_gb_hour: None,
                        metering_mode: MeteringMode::Bandwidth,
                    },
                    FuelBand {
                        capability_type: "crypto".to_string(),
                        cost_per_million: None,
                        cost_per_gb: None,
                        cost_per_operation: Some(0.0001),
                        cost_per_gb_hour: None,
                        metering_mode: MeteringMode::Operations,
                    },
                    FuelBand {
                        capability_type: "storage".to_string(),
                        cost_per_million: None,
                        cost_per_gb: None,
                        cost_per_operation: None,
                        cost_per_gb_hour: Some(0.0001),
                        metering_mode: MeteringMode::Storage,
                    },
                ],
                useful_work_discounts: UsefulWorkDiscounts {
                    enabled: true,
                    null_sec_discount_pct: 0,
                    low_sec_discount_pct: 10,
                    high_sec_discount_pct: 25,
                    verified_discount_pct: 40,
                    min_streak_days: 30,
                    max_discount_pct: 50,
                },
                outcome_adjustments: OutcomeAdjustments {
                    charge_on_success: true,
                    charge_on_soft_fail: false,
                    charge_on_hard_fail: false,
                    soft_fail_refund_pct: 100,
                    hard_fail_refund_pct: 100,
                },
                free_tier: None,
            },
            Profile::Custom => Self::default(),
        }
    }

    /// Validate pricing configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Validate fuel bands
        for band in &self.fuel_bands {
            if band.capability_type.is_empty() {
                return Err("fuel band capability_type cannot be empty".to_string());
            }

            // Check that at least one cost field is set
            let has_cost = band.cost_per_million.is_some()
                || band.cost_per_gb.is_some()
                || band.cost_per_operation.is_some()
                || band.cost_per_gb_hour.is_some();

            if !has_cost {
                return Err(format!(
                    "fuel band '{}' must have at least one cost field set",
                    band.capability_type
                ));
            }
        }

        // Validate discount percentages
        if self.useful_work_discounts.enabled {
            if self.useful_work_discounts.null_sec_discount_pct > 100 {
                return Err("discount percentages cannot exceed 100".to_string());
            }
            if self.useful_work_discounts.low_sec_discount_pct > 100 {
                return Err("discount percentages cannot exceed 100".to_string());
            }
            if self.useful_work_discounts.high_sec_discount_pct > 100 {
                return Err("discount percentages cannot exceed 100".to_string());
            }
            if self.useful_work_discounts.verified_discount_pct > 100 {
                return Err("discount percentages cannot exceed 100".to_string());
            }
            if self.useful_work_discounts.max_discount_pct > 100 {
                return Err("max_discount_pct cannot exceed 100".to_string());
            }
        }

        // Validate refund percentages
        if self.outcome_adjustments.soft_fail_refund_pct > 100 {
            return Err("soft_fail_refund_pct cannot exceed 100".to_string());
        }
        if self.outcome_adjustments.hard_fail_refund_pct > 100 {
            return Err("hard_fail_refund_pct cannot exceed 100".to_string());
        }

        Ok(())
    }

    /// Get fuel band for a specific capability type.
    pub fn get_fuel_band(&self, capability_type: &str) -> Option<&FuelBand> {
        self.fuel_bands
            .iter()
            .find(|b| b.capability_type == capability_type)
    }

    /// Calculate discount percentage for a given reputation tier.
    pub fn calculate_discount(&self, tier: ReputationTier, streak_days: u32) -> u8 {
        if !self.useful_work_discounts.enabled {
            return 0;
        }

        if streak_days < self.useful_work_discounts.min_streak_days {
            return 0;
        }

        let base_discount = match tier {
            ReputationTier::NullSec => self.useful_work_discounts.null_sec_discount_pct,
            ReputationTier::LowSec => self.useful_work_discounts.low_sec_discount_pct,
            ReputationTier::HighSec => self.useful_work_discounts.high_sec_discount_pct,
            ReputationTier::Verified => self.useful_work_discounts.verified_discount_pct,
        };

        base_discount.min(self.useful_work_discounts.max_discount_pct)
    }
}

/// Reputation tier for useful work discounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReputationTier {
    /// No reputation (new user)
    NullSec,

    /// Low reputation (some history)
    LowSec,

    /// High reputation (good track record)
    HighSec,

    /// Verified identity (KYC)
    Verified,
}

// Serde helper functions
fn default_false() -> bool {
    false
}

fn default_true() -> bool {
    true
}

fn default_metering_mode() -> MeteringMode {
    MeteringMode::Fuel
}

fn default_max_discount() -> u8 {
    50
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pricing_config_defaults() {
        let config = PricingConfig::default();
        assert_eq!(config.model, PricingModel::Free);
        assert!(config.fuel_bands.is_empty());
        assert!(!config.useful_work_discounts.enabled);
        assert!(config.outcome_adjustments.charge_on_success);
        assert!(config.free_tier.is_some());
    }

    #[test]
    fn test_profile_specific_pricing() {
        let potato = PricingConfig::default_for_profile(Profile::Potato);
        assert_eq!(potato.model, PricingModel::Free);
        assert!(potato.free_tier.is_some());

        let standard = PricingConfig::default_for_profile(Profile::Standard);
        assert_eq!(standard.model, PricingModel::OutcomeBased);
        assert_eq!(standard.fuel_bands.len(), 2);

        let hyperscale = PricingConfig::default_for_profile(Profile::Hyperscale);
        assert_eq!(hyperscale.model, PricingModel::OutcomeBased);
        assert_eq!(hyperscale.fuel_bands.len(), 4);
    }

    #[test]
    fn test_fuel_band_validation() {
        let mut config = PricingConfig::default();

        // Empty capability_type
        config.fuel_bands.push(FuelBand {
            capability_type: String::new(),
            cost_per_million: Some(0.001),
            cost_per_gb: None,
            cost_per_operation: None,
            cost_per_gb_hour: None,
            metering_mode: MeteringMode::Fuel,
        });
        assert!(config.validate().is_err());

        // No cost fields set
        config.fuel_bands.clear();
        config.fuel_bands.push(FuelBand {
            capability_type: "test".to_string(),
            cost_per_million: None,
            cost_per_gb: None,
            cost_per_operation: None,
            cost_per_gb_hour: None,
            metering_mode: MeteringMode::Fuel,
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_discount_validation() {
        let mut config = PricingConfig::default();
        config.useful_work_discounts.enabled = true;
        config.useful_work_discounts.null_sec_discount_pct = 150;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_get_fuel_band() {
        let config = PricingConfig::default_for_profile(Profile::Hyperscale);

        let cpu_band = config.get_fuel_band("cpu");
        assert!(cpu_band.is_some());
        assert_eq!(cpu_band.unwrap().cost_per_million, Some(0.001));

        let missing_band = config.get_fuel_band("gpu");
        assert!(missing_band.is_none());
    }

    #[test]
    fn test_calculate_discount() {
        let config = PricingConfig::default_for_profile(Profile::Hyperscale);

        // Below minimum streak
        assert_eq!(config.calculate_discount(ReputationTier::HighSec, 10), 0);

        // Above minimum streak
        assert_eq!(config.calculate_discount(ReputationTier::HighSec, 30), 25);
        assert_eq!(config.calculate_discount(ReputationTier::Verified, 30), 40);

        // Capped at max_discount
        assert_eq!(config.calculate_discount(ReputationTier::Verified, 365), 40);
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
    }

    #[test]
    fn test_reputation_tier_ordering() {
        let tiers = [
            ReputationTier::NullSec,
            ReputationTier::LowSec,
            ReputationTier::HighSec,
            ReputationTier::Verified,
        ];

        let config = PricingConfig::default_for_profile(Profile::Hyperscale);

        let discounts: Vec<u8> = tiers
            .iter()
            .map(|tier| config.calculate_discount(*tier, 30))
            .collect();

        // Discounts should increase with tier
        assert_eq!(discounts, vec![0, 10, 25, 40]);
    }

    #[test]
    fn test_outcome_adjustments_defaults() {
        let adjustments = OutcomeAdjustments::default();
        assert!(adjustments.charge_on_success);
        assert!(!adjustments.charge_on_soft_fail);
        assert!(!adjustments.charge_on_hard_fail);
        assert_eq!(adjustments.soft_fail_refund_pct, 100);
        assert_eq!(adjustments.hard_fail_refund_pct, 100);
    }

    #[test]
    fn test_free_tier_limits() {
        let limits = FreeTierLimits::default();
        assert_eq!(limits.fuel_per_month, 1_000_000_000);
        assert_eq!(limits.bandwidth_per_month, 10 * 1024 * 1024 * 1024);
        assert_eq!(limits.operations_per_month, 10_000);
    }

    #[test]
    fn test_useful_work_discounts_disabled_by_default() {
        let discounts = UsefulWorkDiscounts::default();
        assert!(!discounts.enabled);
        assert_eq!(discounts.null_sec_discount_pct, 0);
        assert_eq!(discounts.max_discount_pct, 50);
    }
}
