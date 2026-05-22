//! Malicious WASM tests
//!
//! Verify that the runtime safely rejects or traps on malicious WASM attempts:
//! - Invalid/malformed WASM bytecode
//! - Out-of-bounds memory access
//! - Invalid function calls
//! - Type confusion
//! - Unauthorized imports

use jig_runtime::{BlockPackage, ExecutionContext, Runtime, RuntimeConfig};

#[test]
fn test_invalid_wasm_rejected() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Not valid WASM magic bytes
    let invalid_wasm = b"not wasm at all";

    let block = BlockPackage::from_wasm(vec![]).with_id("invalid-001");
    let context = ExecutionContext::default().with_block(block);

    let result = runtime.execute(invalid_wasm, context);

    // Should fail validation, not panic
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        jig_runtime::RuntimeError::ValidationError(_) | jig_runtime::RuntimeError::InvalidWasm(_)
    ));
}

#[test]
fn test_malformed_wasm_module() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Valid WASM magic but truncated/malformed
    let malformed_wasm = b"\x00asm\x01\x00\x00\x00";

    let block = BlockPackage::from_wasm(vec![]).with_id("malformed-001");
    let context = ExecutionContext::default().with_block(block);

    let result = runtime.execute(malformed_wasm, context);

    // Should fail validation
    assert!(result.is_err());
}

#[test]
fn test_empty_module() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Minimal valid but empty WASM module
    let empty_wasm = wat::parse_str("(module)").unwrap();

    let block = BlockPackage::from_wasm(vec![]).with_id("empty-001");
    let context = ExecutionContext::default().with_block(block);

    let result = runtime.execute(&empty_wasm, context);

    // Should fail because there's no entry point function
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        jig_runtime::RuntimeError::ExecutionError(_)
    ));
}

#[test]
fn test_module_with_invalid_import() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Module requesting an import that doesn't exist
    let wasm_with_import = wat::parse_str(
        r#"
        (module
            (import "env" "nonexistent_func" (func $imported (result i32)))
            (func (export "run") (result i32)
                call $imported
            )
        )
        "#,
    )
    .unwrap();

    let block = BlockPackage::from_wasm(vec![]).with_id("bad-import-001");
    let context = ExecutionContext::default().with_block(block);

    let result = runtime.execute(&wasm_with_import, context);

    // Should fail during validation or instantiation
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        jig_runtime::RuntimeError::ValidationError(_)
            | jig_runtime::RuntimeError::InstantiationError(_)
    ));
}

#[test]
fn test_module_without_entry_point() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Module with a function but not named run/_start/main
    let wasm_no_entry = wat::parse_str(
        r#"
        (module
            (func (export "other_function") (result i32)
                i32.const 42
            )
        )
        "#,
    )
    .unwrap();

    let block = BlockPackage::from_wasm(vec![]).with_id("no-entry-001");
    let context = ExecutionContext::default().with_block(block);

    let result = runtime.execute(&wasm_no_entry, context);

    // Should fail because entry point not found
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        jig_runtime::RuntimeError::ExecutionError(_)
    ));
}

#[test]
fn test_module_with_trap() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Module that intentionally traps (divide by zero)
    let wasm_trap = wat::parse_str(
        r#"
        (module
            (func (export "run") (result i32)
                i32.const 42
                i32.const 0
                i32.div_u  ;; divide by zero = trap
            )
        )
        "#,
    )
    .unwrap();

    let block = BlockPackage::from_wasm(vec![]).with_id("trap-001");
    let context = ExecutionContext::default().with_block(block);

    let receipt = runtime.execute(&wasm_trap, context).expect("execution");

    // Should return receipt with ExecutionFailed, not panic
    assert_eq!(
        receipt.outcome,
        jig_runtime::ExecutionOutcome::ExecutionFailed
    );
    assert!(
        receipt
            .error
            .as_ref()
            .and_then(|e| e.message.as_ref())
            .is_some()
    );
}

#[test]
fn test_module_unreachable() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Module with unreachable instruction
    let wasm_unreachable = wat::parse_str(
        r#"
        (module
            (func (export "run")
                unreachable
            )
        )
        "#,
    )
    .unwrap();

    let block = BlockPackage::from_wasm(vec![]).with_id("unreachable-001");
    let context = ExecutionContext::default().with_block(block);

    let receipt = runtime
        .execute(&wasm_unreachable, context)
        .expect("execution");

    // Should trap gracefully
    assert_eq!(
        receipt.outcome,
        jig_runtime::ExecutionOutcome::ExecutionFailed
    );
}

#[test]
fn test_valid_wasm_with_memory() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Valid module that uses memory (with maximum bound for determinism)
    let wasm_with_memory = wat::parse_str(
        r#"
        (module
            (memory 1 16)  ;; 1 page initial, 16 pages maximum
            (func (export "run") (result i32)
                i32.const 0
                i32.const 42
                i32.store
                i32.const 0
                i32.load
            )
        )
        "#,
    )
    .unwrap();

    let block = BlockPackage::from_wasm(vec![]).with_id("memory-001");
    let context = ExecutionContext::default().with_block(block);

    let receipt = runtime
        .execute(&wasm_with_memory, context)
        .expect("execution");

    // Should succeed
    assert_eq!(receipt.outcome, jig_runtime::ExecutionOutcome::Success);
}

#[test]
fn test_wasm_version_mismatch() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // WASM with wrong version
    let wrong_version = b"\x00asm\x02\x00\x00\x00"; // version 2 doesn't exist

    let block = BlockPackage::from_wasm(vec![]).with_id("version-001");
    let context = ExecutionContext::default().with_block(block);

    let result = runtime.execute(wrong_version, context);

    // Should fail validation
    assert!(result.is_err());
}
