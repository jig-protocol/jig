//! Receipt v0.2 - Pull from jig-core with CLI-specific helpers
//!
//! This module re-exports jig-core's Receipt v0.2 types and adds
//! CLI-specific functionality like pretty-printing and validation helpers.

use anyhow::Result;
use std::fmt;

// Re-export jig-core receipt types
pub use jig_core::BlockReceipt;

/// CLI-specific extensions for BlockReceipt
pub trait ReceiptExt {
    /// Pretty-print the receipt for terminal display
    fn pretty(&self) -> PrettyReceipt<'_>;

    /// Validate the receipt and return helpful error messages
    fn validate_cli(&self) -> Result<()>;
}

impl ReceiptExt for BlockReceipt {
    fn pretty(&self) -> PrettyReceipt<'_> {
        PrettyReceipt(self)
    }

    fn validate_cli(&self) -> Result<()> {
        // Delegate to jig-core's validation
        self.validate()?;

        // Additional CLI-specific checks can go here
        Ok(())
    }
}

/// Wrapper for pretty-printing receipts
pub struct PrettyReceipt<'a>(&'a BlockReceipt);

impl<'a> fmt::Display for PrettyReceipt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let receipt = self.0;

        writeln!(f, "Receipt for block: {}", receipt.block_id)?;
        writeln!(f, "Host: {}", receipt.host)?;
        writeln!(f, "Executed at: {}", receipt.executed_at)?;
        writeln!(f)?;

        writeln!(f, "Render:")?;
        writeln!(f, "  Hash: {}", receipt.render_hash)?;
        if let Some(matches) = receipt.renders_match {
            writeln!(f, "  Matches manifest: {}", if matches { "✓" } else { "✗" })?;
        }
        writeln!(f)?;

        writeln!(f, "Resources:")?;
        writeln!(f, "  Fuel used: {}", receipt.fuel_used)?;
        if let Some(mem) = receipt.memory_peak_mb {
            writeln!(f, "  Memory peak: {} MB", mem)?;
        }
        writeln!(f)?;

        // v0.2 fields
        if let Some(counters) = &receipt.counters {
            writeln!(f, "Counters:")?;
            writeln!(f, "  Fuel total: {}", counters.fuel_total)?;
            if !counters.fuel_by_capability.is_empty() {
                writeln!(f, "  Fuel by capability:")?;
                for (cap, fuel) in &counters.fuel_by_capability {
                    writeln!(f, "    {}: {}", cap, fuel)?;
                }
            }
            writeln!(f, "  Bytes TX: {}", counters.bytes_tx)?;
            writeln!(f, "  Bytes RX: {}", counters.bytes_rx)?;
            writeln!(f)?;
        }

        if let Some(timings) = &receipt.timings_ms {
            writeln!(f, "Timings (ms):")?;
            writeln!(f, "  Queue wait: {}", timings.queue_wait)?;
            writeln!(f, "  Init: {}", timings.init)?;
            writeln!(f, "  Exec: {}", timings.exec)?;
            writeln!(f, "  Total: {}", timings.total)?;
            writeln!(f)?;
        }

        if let Some(limits) = &receipt.limits {
            writeln!(f, "Limits:")?;
            writeln!(f, "  Fuel max: {}", limits.fuel_max)?;
            writeln!(f, "  Memory max: {} MB", limits.memory_max_mb)?;
            writeln!(f, "  Execution timeout: {} ms", limits.execution_timeout_ms)?;
            writeln!(f)?;
        }

        if let Some(outcome) = &receipt.outcome {
            writeln!(f, "Outcome:")?;
            writeln!(f, "  Status: {:?}", outcome.status)?;
            if !outcome.affordances.is_empty() {
                writeln!(f, "  Affordances: {}", outcome.affordances.join(", "))?;
            }
            if let Some(reason) = &outcome.reason {
                writeln!(f, "  Reason: {:?}", reason)?;
            }
            writeln!(f)?;
        }

        if !receipt.capabilities_used.is_empty() {
            writeln!(f, "Capabilities used:")?;
            for cap in &receipt.capabilities_used {
                writeln!(f, "  - {}", cap)?;
            }
            writeln!(f)?;
        }

        if let Some(sig) = &receipt.signature {
            writeln!(f, "Signature: {}...", &sig[..20.min(sig.len())])?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::Cid;
    use std::str::FromStr;

    #[test]
    fn test_pretty_print_basic_receipt() {
        let block_id =
            Cid::from_str("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi").unwrap();

        let receipt = BlockReceipt::builder(block_id)
            .host("did:jig:test-host")
            .render_hash("sha256:abc123")
            .fuel_used(100_000)
            .build()
            .unwrap();

        let pretty = receipt.pretty().to_string();
        assert!(pretty.contains("Receipt for block"));
        assert!(pretty.contains("Fuel used: 100000"));
    }

    #[test]
    fn test_validate_cli_delegates_to_core() {
        let block_id =
            Cid::from_str("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi").unwrap();

        let receipt = BlockReceipt::builder(block_id)
            .host("did:jig:test-host")
            .render_hash("sha256:abc123")
            .fuel_used(100_000)
            .build()
            .unwrap();

        assert!(receipt.validate_cli().is_ok());
    }
}
