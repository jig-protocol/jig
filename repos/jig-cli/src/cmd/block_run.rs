//! Block execution command - run WASM locally with jig-runtime

#![cfg(feature = "local-runtime")]

use anyhow::{Context, Result};
use std::path::Path;

use crate::runtime::{ExecutionLimits, ExecutionSpec, LocalRuntime};

/// Execute a WASM block locally and display the receipt
pub fn run_block(
    wasm_path: &str,
    seed: Option<u64>,
    fuel: Option<u64>,
    memory_mb: Option<u32>,
    timeout_ms: Option<u64>,
    capabilities: Vec<String>,
    receipt_out: Option<&str>,
    json_output: bool,
    enable_pricing: bool,
) -> Result<()> {
    // 1. Load WASM bytes
    let wasm_bytes = std::fs::read(wasm_path)
        .with_context(|| format!("Failed to read WASM file: {}", wasm_path))?;

    println!("📦 Loaded WASM: {} ({} bytes)", wasm_path, wasm_bytes.len());

    // 2. Build execution spec
    let limits = if fuel.is_some() || memory_mb.is_some() || timeout_ms.is_some() {
        Some(ExecutionLimits {
            fuel,
            memory_mb,
            timeout_ms,
        })
    } else {
        None
    };

    let block_id = Path::new(wasm_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string());

    let spec = ExecutionSpec {
        wasm_bytes,
        block_id: block_id.clone(),
        seed,
        limits,
        capability_allowlist: capabilities.clone(),
    };

    // 3. Create runtime (with pricing if requested)
    let runtime = if enable_pricing {
        let mut config = jig_runtime::RuntimeConfig::default();
        config.pricing.enabled = true;
        config.pricing.cost_per_fuel_unit = 0.000001; // 1 micro-unit per fuel
        config.pricing.currency = Some("units".to_string());
        LocalRuntime::with_config(config)?
    } else {
        LocalRuntime::new()?
    };

    println!("🚀 Executing...");
    if let Some(s) = seed {
        println!("   Seed: {}", s);
    }
    if let Some(f) = fuel {
        println!("   Fuel limit: {}", f);
    }
    if let Some(m) = memory_mb {
        println!("   Memory limit: {}MB", m);
    }
    if !capabilities.is_empty() {
        println!("   Capabilities: {}", capabilities.join(", "));
    }

    // 4. Execute
    let receipt = runtime.execute(spec)?;

    // 5. Display results
    println!("\n✅ Execution complete\n");

    if json_output {
        // JSON output
        let json = receipt.to_json()?;
        println!("{}", json);
    } else {
        // Pretty output
        println!("Block ID:     {}", receipt.block.block_id);
        println!("Host:         {}", receipt.block.host);
        println!("Executed at:  {}", receipt.block.executed_at);
        println!("Outcome:      {:?}", receipt.outcome);

        if let Some(hash) = &receipt.module_hash {
            let v = &hash.value;
            let preview = if v.len() >= 16 { &v[..16] } else { v.as_str() };
            println!("Module hash:  {}...", preview);
        }

        println!("\n📊 Metrics:");
        let fuel_used = receipt.fuel_used();
        let fuel_max = receipt
            .block
            .limits
            .as_ref()
            .map(|l| l.fuel_max)
            .unwrap_or(0);
        println!("  Fuel used:   {} / {}", fuel_used, fuel_max);
        println!("  Duration:    {}μs", receipt.duration_ns / 1000);
        let memory_peak = receipt.block.memory_peak_mb.unwrap_or(0);
        println!("  Memory peak: {}MB", memory_peak);

        if let Some(pricing) = &receipt.pricing {
            println!("\n💰 Pricing:");
            println!("  Cost/fuel:   {}", pricing.cost_per_fuel_unit);
            println!(
                "  Total cost:  {} {}",
                pricing.total_cost,
                pricing.currency.as_deref().unwrap_or("units")
            );
        }

        if !receipt.capability_calls.is_empty() {
            println!("\n🔌 Capability Calls:");
            for call in &receipt.capability_calls {
                println!(
                    "  {} → {} (fuel: {})",
                    call.capability, call.operation, call.fuel_used
                );
            }
        }

        if let Some(err) = &receipt.error {
            println!("\n⚠️  Error:");
            println!("  Code:    {}", err.code);
            println!("  Message: {}", err.message.as_deref().unwrap_or(""));
        }
    }

    // 6. Write receipt to file if requested
    if let Some(out_path) = receipt_out {
        let json = receipt.to_json()?;
        std::fs::write(out_path, json)
            .with_context(|| format!("Failed to write receipt to: {}", out_path))?;
        println!("\n📄 Receipt written to: {}", out_path);
    }

    // 7. Exit with appropriate code
    if receipt.outcome != jig_runtime::ExecutionOutcome::Success {
        anyhow::bail!("Execution did not complete successfully");
    }

    Ok(())
}
