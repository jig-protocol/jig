//! Block execution command - run WASM locally with jig-runtime

#![cfg(feature = "local-runtime")]

use anyhow::{Context, Result};
use std::path::Path;

use crate::runtime::{ExecutionLimits, ExecutionSpec, LocalRuntime};

/// Arguments for [`run_block`], grouped to keep the function signature small.
pub struct RunBlockArgs<'a> {
    pub wasm_path: &'a str,
    pub seed: Option<u64>,
    pub fuel: Option<u64>,
    pub memory_mb: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub capabilities: Vec<String>,
    pub receipt_out: Option<&'a str>,
    pub json_output: bool,
    pub enable_pricing: bool,
}

/// Execute a WASM block locally and display the receipt
pub fn run_block(args: RunBlockArgs<'_>) -> Result<()> {
    let RunBlockArgs {
        wasm_path,
        seed,
        fuel,
        memory_mb,
        timeout_ms,
        capabilities,
        receipt_out,
        json_output,
        enable_pricing,
    } = args;

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

/// The component inputs `jig block run` takes; each `None` keeps the
/// [`InvocationSpec`](super::block_exec::InvocationSpec) default.
pub struct ComponentRunArgs<'a> {
    pub input: Option<&'a str>,
    pub input_file: Option<&'a Path>,
    pub media_type: &'a str,
    pub sender: Option<&'a str>,
    pub channel: Option<&'a str>,
    pub seq: Option<u64>,
    pub fuel: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub json: bool,
}

/// Run a component once through the shared component path and print the outcome.
pub fn run_component(target: &super::block_exec::Target, args: ComponentRunArgs<'_>) -> Result<()> {
    use super::block_exec::{Executor, InvocationSpec, limits};

    let mut spec = InvocationSpec {
        media_type: args.media_type.to_string(),
        ..InvocationSpec::default()
    };
    if let Some(i) = args.input {
        spec.input = i.to_string();
    }
    if let Some(f) = args.input_file {
        let body = std::fs::read(f).with_context(|| format!("reading {}", f.display()))?;
        match String::from_utf8(body) {
            Ok(text) => spec.input = text,
            Err(e) => {
                spec.input_hex = Some(e.into_bytes().iter().map(|b| format!("{b:02x}")).collect())
            }
        }
    }
    if let Some(s) = args.sender {
        spec.sender = s.to_string();
    }
    if let Some(c) = args.channel {
        spec.channel = c.to_string();
    }
    if let Some(n) = args.seq {
        spec.seq = n;
    }

    let exec = Executor::new(target, limits(args.fuel, args.timeout_ms))?;
    let report = exec.run(&spec)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", report.render());
    }
    Ok(())
}

/// Run a project's vectors and report each; fail if any fails or, without `bless`, has no
/// expected outcome.
pub fn run_vectors(
    path: &Path,
    bless: bool,
    fuel: Option<u64>,
    timeout_ms: Option<u64>,
) -> Result<()> {
    use super::block_exec::{
        Executor, VECTORS_DIR, VectorResult, limits, load_target, test_vectors,
    };

    let target = load_target(path)?;
    let project_dir = target
        .project_dir
        .clone()
        .context("`jig block test` runs a project's vectors; pass a block project directory")?;
    let exec = Executor::new(&target, limits(fuel, timeout_ms))?;
    let results = test_vectors(&exec, &project_dir, bless)?;
    if results.is_empty() {
        anyhow::bail!("no vectors in {}", project_dir.join(VECTORS_DIR).display());
    }

    let (mut failed, mut unblessed) = (0, 0);
    for (file, result) in &results {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        match result {
            VectorResult::Pass => println!("pass        {name}"),
            VectorResult::Blessed(e) => println!(
                "blessed     {name}: {}{}",
                e.outcome,
                e.hash
                    .as_deref()
                    .map(|h| format!(" {h}"))
                    .unwrap_or_default()
            ),
            VectorResult::Incomplete(r) => println!(
                "incomplete  {name}: {} (no verdict; raise --fuel or --timeout)",
                r.reason.as_deref().unwrap_or("")
            ),
            VectorResult::Unblessed(r) => {
                unblessed += 1;
                println!(
                    "unblessed   {name}: {}{} (run with --bless to record it)",
                    r.outcome,
                    r.hash
                        .as_deref()
                        .map(|h| format!(" {h}"))
                        .unwrap_or_default()
                );
            }
            VectorResult::Fail { expected, got } => {
                failed += 1;
                println!("FAIL        {name}");
                println!(
                    "  expected  {} {}",
                    expected.outcome,
                    expected
                        .hash
                        .as_deref()
                        .or(expected.trap.as_deref())
                        .unwrap_or("")
                );
                println!(
                    "  got       {} {}",
                    got.outcome,
                    got.hash.as_deref().or(got.trap.as_deref()).unwrap_or("")
                );
            }
        }
    }
    if failed > 0 {
        anyhow::bail!("{failed} vector(s) failed");
    }
    if unblessed > 0 {
        anyhow::bail!(
            "{unblessed} vector(s) have no expected outcome; run `jig block test --bless`"
        );
    }
    Ok(())
}
