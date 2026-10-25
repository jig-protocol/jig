//! `jig block run` and `jig block test`: run a block's component locally.

#![cfg(feature = "local-runtime")]

use anyhow::{Context, Result};
use std::path::Path;

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
