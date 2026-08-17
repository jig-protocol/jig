//! Receipt viewing and inspection commands

use crate::http_client::JigHttpClient;
use crate::receipt::v0_2::{BlockReceipt, ReceiptExt};
use anyhow::{Result, anyhow};
use cid::Cid;

/// View a receipt by block ID or from a file
pub async fn view_receipt(
    client: Option<&JigHttpClient>,
    receipt_source: ReceiptSource,
    json_output: bool,
) -> Result<()> {
    let receipt = match receipt_source {
        ReceiptSource::BlockId(cid) => {
            let client = client
                .ok_or_else(|| anyhow!("Client required for fetching receipts by block ID"))?;
            fetch_receipt_from_server(client, &cid).await?
        }
        ReceiptSource::File(path) => load_receipt_from_file(&path)?,
    };

    // Validate receipt
    if let Err(e) = receipt.validate_cli() {
        eprintln!("Warning: Receipt validation failed: {}", e);
    }

    // Output
    if json_output {
        let json = serde_json::to_string_pretty(&receipt)?;
        println!("{}", json);
    } else {
        print!("{}", receipt.pretty());
    }

    Ok(())
}

/// Compare two receipts (for parity testing)
pub async fn compare_receipts(
    client: Option<&JigHttpClient>,
    receipt_a: ReceiptSource,
    receipt_b: ReceiptSource,
) -> Result<()> {
    let a = match receipt_a {
        ReceiptSource::BlockId(cid) => {
            let client = client.ok_or_else(|| anyhow!("Client required for fetching receipts"))?;
            fetch_receipt_from_server(client, &cid).await?
        }
        ReceiptSource::File(path) => load_receipt_from_file(&path)?,
    };

    let b = match receipt_b {
        ReceiptSource::BlockId(cid) => {
            let client = client.ok_or_else(|| anyhow!("Client required for fetching receipts"))?;
            fetch_receipt_from_server(client, &cid).await?
        }
        ReceiptSource::File(path) => load_receipt_from_file(&path)?,
    };

    println!("Comparing receipts...\n");

    // Block IDs should match
    if a.block_id != b.block_id {
        println!("❌ Block IDs differ:");
        println!("  A: {}", a.block_id);
        println!("  B: {}", b.block_id);
    } else {
        println!("✓ Block IDs match: {}", a.block_id);
    }

    // Render hashes should match for determinism
    if a.render_hash != b.render_hash {
        println!("❌ Render hashes differ:");
        println!("  A: {}", a.render_hash);
        println!("  B: {}", b.render_hash);
    } else {
        println!("✓ Render hashes match");
    }

    // Fuel usage (may differ slightly due to host overhead)
    if a.fuel_used != b.fuel_used {
        let diff = (a.fuel_used as i64 - b.fuel_used as i64).abs();
        let pct = (diff as f64 / a.fuel_used as f64) * 100.0;
        if pct > 5.0 {
            println!("⚠️  Fuel usage differs significantly:");
            println!("  A: {}", a.fuel_used);
            println!("  B: {}", b.fuel_used);
            println!("  Diff: {} ({:.2}%)", diff, pct);
        } else {
            println!("✓ Fuel usage similar (within 5%)");
        }
    } else {
        println!("✓ Fuel usage identical: {}", a.fuel_used);
    }

    // Host and engine are expected to differ
    if a.host != b.host {
        println!("ℹ️  Hosts differ (expected):");
        println!("  A: {}", a.host);
        println!("  B: {}", b.host);
    }

    // Capabilities used should match
    if a.capabilities_used != b.capabilities_used {
        println!("❌ Capabilities used differ:");
        println!("  A: {:?}", a.capabilities_used);
        println!("  B: {:?}", b.capabilities_used);
    } else if !a.capabilities_used.is_empty() {
        println!("✓ Capabilities used match: {:?}", a.capabilities_used);
    }

    // v0.2 counters comparison
    if let (Some(counters_a), Some(counters_b)) = (&a.counters, &b.counters) {
        println!("\nCounters comparison:");

        if counters_a.fuel_total != counters_b.fuel_total {
            println!(
                "  ⚠️  Fuel total differs: {} vs {}",
                counters_a.fuel_total, counters_b.fuel_total
            );
        } else {
            println!("  ✓ Fuel total matches: {}", counters_a.fuel_total);
        }

        if counters_a.bytes_tx != counters_b.bytes_tx {
            println!(
                "  ⚠️  Bytes TX differs: {} vs {}",
                counters_a.bytes_tx, counters_b.bytes_tx
            );
        }

        if counters_a.bytes_rx != counters_b.bytes_rx {
            println!(
                "  ⚠️  Bytes RX differs: {} vs {}",
                counters_a.bytes_rx, counters_b.bytes_rx
            );
        }
    }

    // Outcome comparison
    if let (Some(outcome_a), Some(outcome_b)) = (&a.outcome, &b.outcome) {
        println!("\nOutcome comparison:");

        if outcome_a.status != outcome_b.status {
            println!(
                "  ❌ Status differs: {:?} vs {:?}",
                outcome_a.status, outcome_b.status
            );
        } else {
            println!("  ✓ Status matches: {:?}", outcome_a.status);
        }

        if outcome_a.affordances != outcome_b.affordances {
            println!("  ⚠️  Affordances differ");
        } else if !outcome_a.affordances.is_empty() {
            println!("  ✓ Affordances match: {:?}", outcome_a.affordances);
        }
    }

    println!("\nComparison complete.");
    Ok(())
}

pub enum ReceiptSource {
    BlockId(Cid),
    File(String),
}

async fn fetch_receipt_from_server(_client: &JigHttpClient, _cid: &Cid) -> Result<BlockReceipt> {
    // Note: This assumes the server has a /receipts/{cid} endpoint
    // which needs to be implemented in jig-server
    // For now, return error with helpful message
    Err(anyhow!(
        "Fetching receipts from server not yet implemented.\n\
         Server needs /receipts/{{cid}} endpoint.\n\
         Use --file <path> to load receipt from file instead."
    ))
}

fn load_receipt_from_file(path: &str) -> Result<BlockReceipt> {
    let content = std::fs::read_to_string(path)?;
    let receipt: BlockReceipt = serde_json::from_str(&content)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_load_receipt_from_json() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let block_id =
            Cid::from_str("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi").unwrap();

        let receipt = BlockReceipt::builder(block_id)
            .host("did:jig:test-host")
            .render_hash("sha256:abc123")
            .fuel_used(100_000)
            .build()
            .unwrap();

        // Write to temp file
        let mut file = NamedTempFile::new().unwrap();
        let json = serde_json::to_string_pretty(&receipt).unwrap();
        file.write_all(json.as_bytes()).unwrap();
        file.flush().unwrap();

        // Load it back
        let loaded = load_receipt_from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(loaded.block_id, receipt.block_id);
        assert_eq!(loaded.fuel_used, receipt.fuel_used);
    }
}
