//! Jig Block - Rust WASI Template
//!
//! This is a minimal template for creating Jig Blocks in Rust with WASI support.
//!
//! Capabilities are injected by the runtime based on the block manifest.
//! The block runs in a sandboxed WebAssembly environment with resource limits.

use std::io::{self, Write};

/// Main entry point for the block
///
/// This function is called by the Jig runtime when the block is executed.
/// It has access to capabilities specified in block.toml.
#[no_mangle]
pub extern "C" fn execute() -> i32 {
    match run() {
        Ok(()) => 0,  // Success
        Err(e) => {
            eprintln!("Block execution failed: {}", e);
            1  // Error
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Your block logic goes here
    println!("Hello from Jig Block!");

    // Example: Read from stdin (if permitted by capabilities)
    let mut input = String::new();
    if let Ok(_) = io::stdin().read_line(&mut input) {
        println!("Received input: {}", input.trim());
    }

    // Example: Write structured output
    let output = serde_json::json!({
        "status": "ok",
        "message": "Block executed successfully",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    io::stdout().write_all(serde_json::to_string_pretty(&output)?.as_bytes())?;
    io::stdout().flush()?;

    Ok(())
}

// Optional: Metadata function for runtime introspection
#[no_mangle]
pub extern "C" fn metadata() -> *const u8 {
    let meta = r#"{"version":"0.1.0","runtime":"wasi"}"#;
    meta.as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run() {
        assert!(run().is_ok());
    }
}
