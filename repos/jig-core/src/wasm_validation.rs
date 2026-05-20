//! Wasm module validation for deterministic execution.
//!
//! `jig-core` execute blocks strictly-deterministically by default. That means:
//! - Only an explicit host import allowlist is honored.
//! - Clocks, randomness, sockets, and other ambient authority are denied.
//! - Linear memory/table growth stays within pre-agreed policy limits.
//! - Floating point ops are rejected unless a caller explicitly opts-in for testing.
//!
//! Even with strict init, we guardrail at runtime to catch any violations.
//! Hosts should call [`verify_determinism`] prior to instantiation and fail fast
//! when a module pierces these guardrails.

use crate::error::{JigError, Result};
use crate::manifest::Constraints;
use std::collections::{HashMap, HashSet};
use std::fmt;
use wasmparser::{MemoryType, Operator, Parser, Payload, TableType, TypeRef};

const DEFAULT_MEMORY_LIMIT_PAGES: u32 = 512; // 32 MiB
const DEFAULT_TABLE_LIMIT_ELEMENTS: u32 = 1_024;

/// Validation report summarizing determinism analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterminismReport {
    pub violations: Vec<DeterminismViolation>,
    pub imports: Vec<(String, String)>, // (module, name)
}

impl DeterminismReport {
    pub fn is_compliant(&self) -> bool {
        self.violations.is_empty()
    }

    pub fn has_import_violations(&self) -> bool {
        self.violations.iter().any(|v| {
            matches!(
                v,
                DeterminismViolation::DisallowedImport { .. }
                    | DeterminismViolation::ForbiddenImport { .. }
            )
        })
    }
}

/// Specific determinism constraint violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeterminismViolation {
    FloatInstruction(String),
    DisallowedImport { module: String, name: String },
    ForbiddenImport { module: String, name: String },
    MemoryMinimumExceedsLimit { declared: u64, limit: u32 },
    MemoryMaximumExceedsLimit { declared: u64, limit: u32 },
    MemoryMissingMaximum,
    Memory64NotSupported,
    SharedMemoryNotSupported,
    TableMaximumExceedsLimit { declared: u32, limit: u32 },
    TableMissingMaximum,
}

impl fmt::Display for DeterminismViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeterminismViolation::FloatInstruction(op) => {
                write!(f, "floating-point instruction detected: {op}")
            }
            DeterminismViolation::DisallowedImport { module, name } => {
                write!(f, "import {module}::{name} not in allowlist")
            }
            DeterminismViolation::ForbiddenImport { module, name } => {
                write!(f, "import {module}::{name} is explicitly forbidden")
            }
            DeterminismViolation::MemoryMinimumExceedsLimit { declared, limit } => {
                write!(f, "memory minimum {declared} pages exceeds limit {limit}")
            }
            DeterminismViolation::MemoryMaximumExceedsLimit { declared, limit } => {
                write!(f, "memory maximum {declared} pages exceeds limit {limit}")
            }
            DeterminismViolation::MemoryMissingMaximum => {
                write!(f, "memory definition missing maximum bound")
            }
            DeterminismViolation::Memory64NotSupported => {
                write!(f, "memory64 is not supported for deterministic execution")
            }
            DeterminismViolation::SharedMemoryNotSupported => {
                write!(
                    f,
                    "shared memories are not supported for deterministic execution"
                )
            }
            DeterminismViolation::TableMaximumExceedsLimit { declared, limit } => {
                write!(f, "table maximum {declared} elements exceeds limit {limit}")
            }
            DeterminismViolation::TableMissingMaximum => {
                write!(f, "table definition missing maximum bound")
            }
        }
    }
}

/// Host import allowlist defining safe imports.
#[derive(Debug, Clone)]
pub struct HostImportAllowlist {
    modules: HashMap<String, AllowedModule>,
}

#[derive(Debug, Clone)]
pub struct AllowedModule {
    pub name: String,
    pub allowed_functions: HashSet<String>,
}

impl HostImportAllowlist {
    /// Create empty allowlist (denies all imports).
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    /// Add a module with allowed functions.
    pub fn allow_module(mut self, name: impl Into<String>, functions: Vec<String>) -> Self {
        let name = name.into();
        let entry = self
            .modules
            .entry(name.clone())
            .or_insert_with(|| AllowedModule {
                name: name.clone(),
                allowed_functions: HashSet::new(),
            });
        entry.allowed_functions.extend(functions);
        self
    }

    /// Allow a single function on a module (merges with existing entries).
    pub fn allow_function(
        mut self,
        module: impl Into<String>,
        function: impl Into<String>,
    ) -> Self {
        let module = module.into();
        let entry = self
            .modules
            .entry(module.clone())
            .or_insert_with(|| AllowedModule {
                name: module.clone(),
                allowed_functions: HashSet::new(),
            });
        entry.allowed_functions.insert(function.into());
        self
    }

    /// Check if an import is allowed.
    pub fn is_allowed(&self, module: &str, function: &str) -> bool {
        self.modules
            .get(module)
            .map(|m| m.allowed_functions.contains(function))
            .unwrap_or(false)
    }

    /// Default allowlist for Jig host functions (deterministic core).
    pub fn default_jig_allowlist() -> Self {
        Self::new()
            // Core deterministic capabilities.
            .allow_module(
                "jig_host",
                vec!["log".into(), "emit_message".into(), "read_resource".into()],
            )
            // WASI preview1 safe subset (no random, clock, etc).
            .allow_module("wasi_snapshot_preview1", vec!["proc_exit".into()])
    }

    /// WASI-safe allowlist for deterministic WASI preview1 modules.
    ///
    /// Allows controlled I/O operations while maintaining determinism:
    /// - stdio: fd_read, fd_write, fd_close, fd_prestat_*
    /// - environment: environ_* (read-only, deterministic)
    /// - process: proc_exit, args_*
    ///
    /// Explicitly excludes non-deterministic operations:
    /// - random_get (entropy source)
    /// - clock_* (wall-clock time)
    /// - sock_* (network I/O)
    pub fn wasi_preview1_deterministic() -> Self {
        Self::new().allow_module(
            "wasi_snapshot_preview1",
            vec![
                // Process lifecycle
                "proc_exit".into(),
                "args_get".into(),
                "args_sizes_get".into(),
                // Environment (read-only, deterministic from context)
                "environ_get".into(),
                "environ_sizes_get".into(),
                // File descriptors (stdio only, memory-backed)
                "fd_close".into(),
                "fd_fdstat_get".into(),
                "fd_fdstat_set_flags".into(),
                "fd_prestat_get".into(),
                "fd_prestat_dir_name".into(),
                "fd_read".into(),
                "fd_seek".into(),
                "fd_write".into(),
                // Path operations (needed for fd resolution)
                "path_open".into(),
                "path_filestat_get".into(),
            ],
        )
    }
}

impl Default for HostImportAllowlist {
    fn default() -> Self {
        Self::default_jig_allowlist()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ImportKey {
    module: String,
    name: String,
}

/// Determinism policy describing the strict execution posture.
#[derive(Debug, Clone)]
pub struct DeterminismPolicy {
    allowlist: HostImportAllowlist,
    forbidden_imports: HashSet<ImportKey>,
    allow_floats: bool,
    max_memory_pages: Option<u32>,
    max_table_elements: Option<u32>,
    require_memory_maximum: bool,
    require_table_maximum: bool,
}

impl DeterminismPolicy {
    pub fn strict() -> Self {
        Self {
            allowlist: HostImportAllowlist::default(),
            forbidden_imports: default_forbidden_imports(),
            allow_floats: false,
            max_memory_pages: Some(DEFAULT_MEMORY_LIMIT_PAGES),
            max_table_elements: Some(DEFAULT_TABLE_LIMIT_ELEMENTS),
            require_memory_maximum: true,
            require_table_maximum: true,
        }
    }

    pub fn with_allowlist(mut self, allowlist: HostImportAllowlist) -> Self {
        self.allowlist = allowlist;
        self
    }

    pub fn with_forbidden_import(
        mut self,
        module: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        self.forbidden_imports.insert(ImportKey {
            module: module.into(),
            name: name.into(),
        });
        self
    }

    pub fn with_memory_limit_pages(mut self, pages: u32) -> Self {
        self.max_memory_pages = Some(pages);
        self
    }

    pub fn without_memory_limit(mut self) -> Self {
        self.max_memory_pages = None;
        self
    }

    pub fn with_table_limit(mut self, max_elements: u32) -> Self {
        self.max_table_elements = Some(max_elements);
        self
    }

    /// Permit floating point instructions (relaxes determinism guardrails).
    pub fn with_floats_allowed(mut self) -> Self {
        self.allow_floats = true;
        self
    }

    pub fn without_table_limit(mut self) -> Self {
        self.max_table_elements = None;
        self
    }

    #[cfg(test)]
    pub fn allow_floats_for_tests(mut self) -> Self {
        self.allow_floats = true;
        self
    }
}

fn default_forbidden_imports() -> HashSet<ImportKey> {
    [
        ("wasi_snapshot_preview1", "random_get"),
        ("wasi_snapshot_preview1", "clock_time_get"),
        ("wasi_snapshot_preview1", "clock_res_get"),
        ("wasi_snapshot_preview1", "sock_accept"),
        ("wasi_snapshot_preview1", "sock_recv"),
        ("wasi_snapshot_preview1", "sock_send"),
        ("wasi_snapshot_preview1", "sock_open"),
        ("wasi_snapshot_preview1", "sock_connect"),
    ]
    .into_iter()
    .map(|(module, name)| ImportKey {
        module: module.into(),
        name: name.into(),
    })
    .collect()
}

/// Verify that Wasm module adheres to the provided determinism policy.
pub fn verify_determinism(
    code_bytes: &[u8],
    policy: &DeterminismPolicy,
) -> Result<DeterminismReport> {
    let mut report = DeterminismReport {
        violations: Vec::new(),
        imports: Vec::new(),
    };

    if code_bytes.is_empty() {
        return Ok(report);
    }

    let parser = Parser::new(0);

    for payload in parser.parse_all(code_bytes) {
        let payload =
            payload.map_err(|e| JigError::Validation(format!("wasm parse error: {e}")))?;

        match payload {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import
                        .map_err(|e| JigError::Validation(format!("import section error: {e}")))?;

                    let module = import.module.to_string();
                    let name = import.name.to_string();
                    report.imports.push((module.clone(), name.clone()));

                    if !policy.allowlist.is_allowed(&module, &name) {
                        report
                            .violations
                            .push(DeterminismViolation::DisallowedImport {
                                module: module.clone(),
                                name: name.clone(),
                            });
                    }

                    if policy.forbidden_imports.contains(&ImportKey {
                        module: module.clone(),
                        name: name.clone(),
                    }) {
                        report
                            .violations
                            .push(DeterminismViolation::ForbiddenImport { module, name });
                        continue;
                    }

                    match import.ty {
                        TypeRef::Memory(mem) => {
                            check_memory_type(mem, &mut report, policy)?;
                        }
                        TypeRef::Table(table) => {
                            check_table_type(table, &mut report, policy)?;
                        }
                        _ => {}
                    }
                }
            }
            Payload::MemorySection(reader) => {
                for memory in reader {
                    let memory =
                        memory.map_err(|e| JigError::Validation(format!("memory section: {e}")))?;
                    check_memory_type(memory, &mut report, policy)?;
                }
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    let table =
                        table.map_err(|e| JigError::Validation(format!("table section: {e}")))?;
                    check_table_type(table.ty, &mut report, policy)?;
                }
            }
            Payload::CodeSectionEntry(body) => {
                let mut reader = body
                    .get_operators_reader()
                    .map_err(|e| JigError::Validation(format!("code section error: {e}")))?;

                while !reader.eof() {
                    let op = reader
                        .read()
                        .map_err(|e| JigError::Validation(format!("operator read error: {e}")))?;

                    if let Some(violation) = detect_float_violation(&op, policy.allow_floats) {
                        report.violations.push(violation);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(report)
}

fn detect_float_violation(op: &Operator, allow_floats: bool) -> Option<DeterminismViolation> {
    if allow_floats {
        return None;
    }

    match op {
        Operator::F32Const { .. }
        | Operator::F64Const { .. }
        | Operator::F32Load { .. }
        | Operator::F64Load { .. }
        | Operator::F32Store { .. }
        | Operator::F64Store { .. }
        | Operator::F32Abs
        | Operator::F32Neg
        | Operator::F32Ceil
        | Operator::F32Floor
        | Operator::F32Trunc
        | Operator::F32Nearest
        | Operator::F32Sqrt
        | Operator::F32Add
        | Operator::F32Sub
        | Operator::F32Mul
        | Operator::F32Div
        | Operator::F32Min
        | Operator::F32Max
        | Operator::F32Copysign
        | Operator::F64Abs
        | Operator::F64Neg
        | Operator::F64Ceil
        | Operator::F64Floor
        | Operator::F64Trunc
        | Operator::F64Nearest
        | Operator::F64Sqrt
        | Operator::F64Add
        | Operator::F64Sub
        | Operator::F64Mul
        | Operator::F64Div
        | Operator::F64Min
        | Operator::F64Max
        | Operator::F64Copysign
        | Operator::F32Eq
        | Operator::F32Ne
        | Operator::F32Lt
        | Operator::F32Gt
        | Operator::F32Le
        | Operator::F32Ge
        | Operator::F64Eq
        | Operator::F64Ne
        | Operator::F64Lt
        | Operator::F64Gt
        | Operator::F64Le
        | Operator::F64Ge
        | Operator::I32TruncF32S
        | Operator::I32TruncF32U
        | Operator::I32TruncF64S
        | Operator::I32TruncF64U
        | Operator::I64TruncF32S
        | Operator::I64TruncF32U
        | Operator::I64TruncF64S
        | Operator::I64TruncF64U
        | Operator::F32ConvertI32S
        | Operator::F32ConvertI32U
        | Operator::F32ConvertI64S
        | Operator::F32ConvertI64U
        | Operator::F32DemoteF64
        | Operator::F64ConvertI32S
        | Operator::F64ConvertI32U
        | Operator::F64ConvertI64S
        | Operator::F64ConvertI64U
        | Operator::F64PromoteF32
        | Operator::I32ReinterpretF32
        | Operator::I64ReinterpretF64
        | Operator::F32ReinterpretI32
        | Operator::F64ReinterpretI64 => {
            Some(DeterminismViolation::FloatInstruction(format!("{op:?}")))
        }
        _ => None,
    }
}

fn check_memory_type(
    memory: MemoryType,
    report: &mut DeterminismReport,
    policy: &DeterminismPolicy,
) -> Result<()> {
    if memory.memory64 {
        report
            .violations
            .push(DeterminismViolation::Memory64NotSupported);
    }
    if memory.shared {
        report
            .violations
            .push(DeterminismViolation::SharedMemoryNotSupported);
    }

    if let Some(limit) = policy.max_memory_pages {
        if memory.initial > u64::from(limit) {
            report
                .violations
                .push(DeterminismViolation::MemoryMinimumExceedsLimit {
                    declared: memory.initial,
                    limit,
                });
        }
        if let Some(max) = memory.maximum
            && max > u64::from(limit)
        {
            report
                .violations
                .push(DeterminismViolation::MemoryMaximumExceedsLimit {
                    declared: max,
                    limit,
                });
        }
    }

    if policy.require_memory_maximum && memory.maximum.is_none() {
        report
            .violations
            .push(DeterminismViolation::MemoryMissingMaximum);
    }

    Ok(())
}

fn check_table_type(
    table: TableType,
    report: &mut DeterminismReport,
    policy: &DeterminismPolicy,
) -> Result<()> {
    if policy.require_table_maximum && table.maximum.is_none() {
        report
            .violations
            .push(DeterminismViolation::TableMissingMaximum);
    }

    if let (Some(limit), Some(max)) = (policy.max_table_elements, table.maximum)
        && max > limit
    {
        report
            .violations
            .push(DeterminismViolation::TableMaximumExceedsLimit {
                declared: max,
                limit,
            });
    }

    Ok(())
}

/// Convenience wrapper that applies the default strict policy.
pub fn validate_determinism(code_bytes: &[u8]) -> Result<DeterminismReport> {
    verify_determinism(code_bytes, &DeterminismPolicy::strict())
}

/// Convenience wrapper using the strict default allowlist and policy.
pub fn verify_determinism_default(code_bytes: &[u8]) -> Result<DeterminismReport> {
    verify_determinism(code_bytes, &DeterminismPolicy::strict())
}

/// Build a determinism policy derived from execution constraints and an import allowlist.
pub fn policy_from_constraints(
    constraints: &Constraints,
    allowlist: HostImportAllowlist,
) -> DeterminismPolicy {
    let mut policy = DeterminismPolicy::strict().with_allowlist(allowlist);

    if !constraints.deterministic {
        policy = policy.with_floats_allowed();
    }

    if constraints.memory_max_mb > 0 {
        let pages = constraints.memory_max_mb.saturating_mul(16);
        policy = policy.with_memory_limit_pages(pages);
    }

    policy
}

/// Legacy helper retained for compatibility. It only surfaces import violations.
pub fn check_imports(code_bytes: &[u8], allowlist: &HostImportAllowlist) -> Result<()> {
    let policy = DeterminismPolicy::strict().with_allowlist(allowlist.clone());
    let report = verify_determinism(code_bytes, &policy)?;
    if report.has_import_violations() {
        let details = report
            .violations
            .into_iter()
            .filter(|v| {
                matches!(
                    v,
                    DeterminismViolation::DisallowedImport { .. }
                        | DeterminismViolation::ForbiddenImport { .. }
                )
            })
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(JigError::Validation(format!(
            "disallowed imports: {details}"
        )));
    }
    Ok(())
}

/// Infer appropriate execution limits from Wasm module structure.
///
/// Analyzes the module to suggest safe execution limits without inspecting code contents.
/// This is critical for E2EE scenarios where block contents are encrypted but limits
/// must still be set appropriately to distinguish real failures from insufficient resources.
pub fn infer_limits(code_bytes: &[u8]) -> Result<crate::receipt::Limits> {
    use wasmparser::{Parser, Payload};

    let mut instruction_count = 0u64;
    let mut import_count = 0u64;
    let mut max_memory_pages = 1u32; // 64KB default
    let mut function_count = 0u64;

    let parser = Parser::new(0);

    for payload in parser.parse_all(code_bytes) {
        let payload = payload.map_err(|e| JigError::Validation(format!("wasm parse: {e}")))?;

        match payload {
            Payload::ImportSection(reader) => {
                import_count = reader.count() as u64;
            }
            Payload::FunctionSection(reader) => {
                function_count = reader.count() as u64;
            }
            Payload::MemorySection(reader) => {
                for memory in reader {
                    let memory =
                        memory.map_err(|e| JigError::Validation(format!("memory section: {e}")))?;
                    max_memory_pages = max_memory_pages.max(memory.initial as u32);
                }
            }
            Payload::CodeSectionEntry(body) => {
                let mut reader = body
                    .get_operators_reader()
                    .map_err(|e| JigError::Validation(format!("code section: {e}")))?;

                while !reader.eof() {
                    reader
                        .read()
                        .map_err(|e| JigError::Validation(format!("operator read: {e}")))?;
                    instruction_count += 1;
                }
            }
            _ => {}
        }
    }

    let base_fuel = 100_000u64;
    let instruction_fuel = instruction_count.saturating_mul(10);
    let import_fuel = import_count.saturating_mul(50_000);
    let function_fuel = function_count.saturating_mul(1_000);
    let calculated_fuel = base_fuel
        .saturating_add(instruction_fuel)
        .saturating_add(import_fuel)
        .saturating_add(function_fuel);

    let fuel_max = calculated_fuel.max(100_000);

    let memory_max_mb = (max_memory_pages * 64 / 1024).max(16);

    let complexity_units = (instruction_count + import_count + function_count) / 1000;
    let execution_timeout_ms =
        5000u32.saturating_add((complexity_units as u32).saturating_mul(100));

    Ok(crate::receipt::Limits {
        fuel_max,
        memory_max_mb,
        execution_timeout_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Author, BlockManifestBuilder, Constraints};
    use semver::Version;

    fn wasm_empty() -> Vec<u8> {
        wat::parse_str("(module)").unwrap()
    }

    #[test]
    fn empty_module_is_deterministic() {
        let wasm = wasm_empty();
        let report = verify_determinism(&wasm, &DeterminismPolicy::strict()).unwrap();
        assert!(report.is_compliant());
    }

    #[test]
    fn float_operations_violate_determinism() {
        let wasm = wat::parse_str(
            r#"(module
                (func (export "add") (param f32 f32) (result f32)
                    local.get 0
                    local.get 1
                    f32.add))
            "#,
        )
        .unwrap();

        let report = verify_determinism(&wasm, &DeterminismPolicy::strict()).unwrap();
        assert!(!report.is_compliant());
        assert!(
            report
                .violations
                .iter()
                .any(|v| matches!(v, DeterminismViolation::FloatInstruction(_)))
        );
    }

    #[test]
    fn allowlist_permits_approved_imports() {
        let wasm = wat::parse_str(
            r#"(module
                (import "jig_host" "log" (func $log (param i32 i32)))
                (func (export "main")
                    i32.const 0
                    i32.const 0
                    call $log))
            "#,
        )
        .unwrap();

        let report = verify_determinism(&wasm, &DeterminismPolicy::strict()).unwrap();
        assert!(report.is_compliant());
    }

    #[test]
    fn disallowed_imports_are_detected() {
        let wasm = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "fd_read" (func))
            )"#,
        )
        .unwrap();

        let report = verify_determinism(&wasm, &DeterminismPolicy::strict()).unwrap();
        assert!(
            report
                .violations
                .iter()
                .any(|v| matches!(v, DeterminismViolation::DisallowedImport { .. }))
        );
    }

    #[test]
    fn forbidden_imports_are_blocked_even_if_allowlisted() {
        let wasm = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "random_get" (func))
            )"#,
        )
        .unwrap();

        let mut allowlist = HostImportAllowlist::default();
        allowlist = allowlist.allow_module(
            "wasi_snapshot_preview1",
            vec!["proc_exit".into(), "random_get".into()],
        );

        let policy = DeterminismPolicy::strict().with_allowlist(allowlist);
        let report = verify_determinism(&wasm, &policy).unwrap();
        assert!(
            report
                .violations
                .iter()
                .any(|v| matches!(v, DeterminismViolation::ForbiddenImport { .. }))
        );
    }

    #[test]
    fn memory_limits_enforced() {
        let wasm = wat::parse_str(
            r#"
            (module
                (memory 513 1024)
            )
            "#,
        )
        .unwrap();

        let policy = DeterminismPolicy::strict().with_memory_limit_pages(512);
        let report = verify_determinism(&wasm, &policy).unwrap();
        assert!(
            report
                .violations
                .iter()
                .any(|v| matches!(v, DeterminismViolation::MemoryMinimumExceedsLimit { .. }))
        );
    }

    #[test]
    fn table_requires_maximum() {
        let wasm = wat::parse_str(
            r#"
            (module
                (table 1 funcref)
            )
            "#,
        )
        .unwrap();

        let report = verify_determinism(&wasm, &DeterminismPolicy::strict()).unwrap();
        assert!(
            report
                .violations
                .iter()
                .any(|v| matches!(v, DeterminismViolation::TableMissingMaximum))
        );
    }

    #[test]
    fn infer_limits_respects_module_structure() {
        let wasm = wat::parse_str(
            r#"
            (module
                (memory 2)
                (func (export "add") (param i32 i32) (result i32)
                    local.get 0
                    local.get 1
                    i32.add)
            )
            "#,
        )
        .unwrap();

        let limits = infer_limits(&wasm).unwrap();
        assert!(limits.fuel_max >= 100_000);
        assert!(limits.memory_max_mb >= 16);
    }

    #[test]
    fn bundle_validation_uses_policy() {
        use crate::bundle::{Artifact, BlockBundle};

        let manifest = BlockManifestBuilder::default()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .constraints(Constraints {
                fuel_max: 1_000_000,
                memory_max_mb: 32,
                execution_timeout_ms: 250,
                deterministic: true,
            })
            .build()
            .unwrap();

        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let wasm = wat::parse_str(
            r#"(module
                (import "jig_host" "log" (func $log (param i32 i32)))
                (func (export "main")
                    i32.const 0
                    i32.const 0
                    call $log)
            )"#,
        )
        .unwrap();

        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &wasm,
            resources: vec![Artifact {
                label: "data",
                bytes: b"hello",
            }],
        };

        assert!(bundle.validate_code(&manifest.constraints).is_ok());
    }
}
