//! Validation of block components against the determinism profile `jig-det-1` (JEP-0006,
//! design decision A2).
//!
//! A block is a WebAssembly component that implements one `jig:block` world. Before a host runs
//! one, it checks:
//!
//! 1. The whole binary validates with exactly the WebAssembly 2.0 features minus SIMD, plus the
//!    component model without its async, threading, error-context or other gated extensions.
//! 2. No nested component contains code. Block nesting goes through `jig:host/compose`, not
//!    composition inside one binary. A nested component with no core module is allowed:
//!    `wit-component` emits one to give the exported instance its exact type.
//! 3. Every core module inside passes the same checks as a standalone block module: no float
//!    instruction, declared maxima for memories and tables, within the limit. A core module's
//!    own imports are wired inside the component, so only the component's imports face the
//!    host; those are checked next.
//! 4. Imports: no `wasi:*` interface ever. `jig:block/types` is always allowed: it holds only
//!    type definitions, so the host provides nothing for it. Beyond that, a renderer may import
//!    only `jig:host/compose`, and a bot only `jig:host/*` interfaces, each of them granted.
//! 5. Exports: exactly the one interface of the declared world, plus any type exports.
//!
//! Interface versions are matched the way the component model matches them: `0.x.*` with
//! `0.x.*`, `1.*` with `1.*`.

use std::fmt;

use semver::Version;
use wasmparser::{ComponentExternalKind, Encoding, Parser, Payload, Validator, WasmFeatures};

use crate::error::{JigError, Result};
use crate::wasm_validation::{
    DETERMINISTIC_FEATURES, DeterminismPolicy, DeterminismViolation, verify_determinism,
};

/// The features a block component may use: the core set every block module is held to, plus
/// the component model itself and none of its gated extensions.
pub const COMPONENT_FEATURES: WasmFeatures =
    DETERMINISTIC_FEATURES.union(WasmFeatures::COMPONENT_MODEL);

/// The `jig:block` world a component declares it implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockWorld {
    /// Exports `jig:block/render`. Verifiable by re-execution anywhere.
    Renderer,
    /// Exports `jig:block/handler`. Capability-bearing.
    Bot,
}

impl BlockWorld {
    /// The interface the world exports, without a version.
    pub fn export(self) -> &'static str {
        match self {
            BlockWorld::Renderer => "jig:block/render",
            BlockWorld::Bot => "jig:block/handler",
        }
    }
}

/// The version of `jig:block` this crate validates against.
pub const JIG_BLOCK_VERSION: &str = "0.1.0";

/// What a host checks a component against.
#[derive(Debug, Clone)]
pub struct ComponentProfile<'a> {
    /// The world the block's manifest declares.
    pub world: BlockWorld,
    /// Interfaces the block's install (or, for children, its parent) grants, with versions, for
    /// example `jig:host/compose@0.1.0`.
    pub granted: &'a [&'a str],
    /// The manifest's memory limit, in 64 KiB pages. Every memory in every core module must
    /// declare a maximum no larger than this.
    pub max_memory_pages: u32,
}

/// One reason a component fails the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentViolation {
    /// The bytes are a core module or not WebAssembly at all.
    NotAComponent,
    /// The binary does not validate with [`COMPONENT_FEATURES`].
    OutsideFeatureSet(String),
    /// A component nested inside this one contains a core module.
    NestedComponent,
    /// A core module inside the component breaks a module-level rule. `module` counts core
    /// modules in binary order from 0.
    CoreModule {
        module: usize,
        violation: DeterminismViolation,
    },
    /// The component imports a WASI interface.
    WasiImport(String),
    /// The world does not allow this import at all.
    ImportNotInWorld(String),
    /// The import is allowed by the world but not granted.
    UngrantedImport(String),
    /// The world's interface is not exported.
    MissingExport(String),
    /// Something other than the world's interface (or a type) is exported.
    UnexpectedExport(String),
}

impl fmt::Display for ComponentViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComponentViolation::NotAComponent => write!(f, "not a WebAssembly component"),
            ComponentViolation::OutsideFeatureSet(e) => write!(
                f,
                "component does not validate with WebAssembly 2.0 minus SIMD plus the plain \
                 component model: {e}"
            ),
            ComponentViolation::NestedComponent => {
                write!(
                    f,
                    "a nested component contains code; nested blocks use jig:host/compose"
                )
            }
            ComponentViolation::CoreModule { module, violation } => {
                write!(f, "core module {module}: {violation}")
            }
            ComponentViolation::WasiImport(name) => {
                write!(f, "imports {name}: no WASI interface is allowed")
            }
            ComponentViolation::ImportNotInWorld(name) => {
                write!(f, "imports {name}, which this world does not allow")
            }
            ComponentViolation::UngrantedImport(name) => write!(f, "imports {name}, not granted"),
            ComponentViolation::MissingExport(name) => write!(f, "does not export {name}"),
            ComponentViolation::UnexpectedExport(name) => write!(f, "unexpected export {name}"),
        }
    }
}

/// What validation found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComponentReport {
    pub violations: Vec<ComponentViolation>,
    /// The component's imports, full names with versions.
    pub imports: Vec<String>,
    /// The component's non-type exports, full names with versions.
    pub exports: Vec<String>,
}

impl ComponentReport {
    pub fn is_compliant(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Check `bytes` against `profile`. `Err` means the bytes could not be parsed far enough to
/// judge; a parsed component that fails the profile comes back as a report with violations.
pub fn validate_component(bytes: &[u8], profile: &ComponentProfile<'_>) -> Result<ComponentReport> {
    let mut report = ComponentReport::default();

    if !Parser::is_component(bytes) {
        report.violations.push(ComponentViolation::NotAComponent);
        return Ok(report);
    }

    if let Err(e) = Validator::new_with_features(COMPONENT_FEATURES).validate_all(bytes) {
        report
            .violations
            .push(ComponentViolation::OutsideFeatureSet(e.to_string()));
    }

    let module_policy =
        DeterminismPolicy::strict().with_memory_limit_pages(profile.max_memory_pages);
    // One entry per open component or module: `true` for a component nested below the top.
    let mut frames: Vec<bool> = Vec::new();
    // Report code in nested components once, however many modules it holds.
    let mut reported_nested = false;
    let mut module_index = 0usize;

    for payload in Parser::new(0).parse_all(bytes) {
        let payload =
            payload.map_err(|e| JigError::Validation(format!("wasm parse error: {e}")))?;
        match payload {
            Payload::Version { encoding, .. } => {
                frames.push(!frames.is_empty() && encoding == Encoding::Component);
            }
            Payload::End(_) => {
                frames.pop();
            }
            Payload::ModuleSection {
                unchecked_range, ..
            } => {
                if frames.iter().any(|nested| *nested) && !reported_nested {
                    report.violations.push(ComponentViolation::NestedComponent);
                    reported_nested = true;
                }
                let range = usize::try_from(unchecked_range.start)
                    .and_then(|start| Ok(start..usize::try_from(unchecked_range.end)?))
                    .map_err(|_| JigError::Validation("core module offset overflows".into()))?;
                let module = bytes.get(range).ok_or_else(|| {
                    JigError::Validation("core module range out of bounds".into())
                })?;
                let module_report = verify_determinism(module, &module_policy)?;
                for violation in module_report.violations {
                    // A core module's imports are satisfied inside the component; the host sees
                    // only the component's imports, checked below.
                    if matches!(violation, DeterminismViolation::DisallowedImport { .. }) {
                        continue;
                    }
                    report.violations.push(ComponentViolation::CoreModule {
                        module: module_index,
                        violation,
                    });
                }
                module_index += 1;
            }
            Payload::ComponentImportSection(reader) if frames.len() == 1 => {
                for import in reader {
                    let import = import
                        .map_err(|e| JigError::Validation(format!("component import: {e}")))?;
                    let name = import.name.full_name().into_owned();
                    if let Some(v) = check_import(&name, profile) {
                        report.violations.push(v);
                    }
                    report.imports.push(name);
                }
            }
            Payload::ComponentExportSection(reader) if frames.len() == 1 => {
                for export in reader {
                    let export = export
                        .map_err(|e| JigError::Validation(format!("component export: {e}")))?;
                    if export.kind == ComponentExternalKind::Type {
                        continue;
                    }
                    report.exports.push(export.name.full_name().into_owned());
                }
            }
            _ => {}
        }
    }

    check_exports(&mut report, profile.world);
    Ok(report)
}

fn check_import(name: &str, profile: &ComponentProfile<'_>) -> Option<ComponentViolation> {
    let (base, _) = split_version(name);
    if base.starts_with("wasi:") {
        return Some(ComponentViolation::WasiImport(name.to_string()));
    }
    if compatible(name, &format!("jig:block/types@{JIG_BLOCK_VERSION}")) {
        return None;
    }
    let in_world = match profile.world {
        BlockWorld::Renderer => base == "jig:host/compose",
        BlockWorld::Bot => base.starts_with("jig:host/"),
    };
    if !in_world {
        return Some(ComponentViolation::ImportNotInWorld(name.to_string()));
    }
    if !profile.granted.iter().any(|g| compatible(name, g)) {
        return Some(ComponentViolation::UngrantedImport(name.to_string()));
    }
    None
}

fn check_exports(report: &mut ComponentReport, world: BlockWorld) {
    let wanted = format!("{}@{JIG_BLOCK_VERSION}", world.export());
    let mut found = false;
    for name in &report.exports {
        if !found && compatible(name, &wanted) {
            found = true;
        } else {
            report
                .violations
                .push(ComponentViolation::UnexpectedExport(name.clone()));
        }
    }
    if !found {
        report
            .violations
            .push(ComponentViolation::MissingExport(wanted));
    }
}

/// `ns:pkg/iface@1.2.3` → (`ns:pkg/iface`, `Some("1.2.3")`).
fn split_version(name: &str) -> (&str, Option<&str>) {
    match name.split_once('@') {
        Some((base, v)) => (base, Some(v)),
        None => (name, None),
    }
}

/// Whether two interface names match under component-model semver rules. Both must carry a
/// version, and the versions must agree on their first non-zero component.
fn compatible(a: &str, b: &str) -> bool {
    let (base_a, va) = split_version(a);
    let (base_b, vb) = split_version(b);
    if base_a != base_b {
        return false;
    }
    let (Some(Ok(va)), Some(Ok(vb))) = (va.map(Version::parse), vb.map(Version::parse)) else {
        return false;
    };
    if !va.pre.is_empty() || !vb.pre.is_empty() {
        return va == vb;
    }
    match (va.major, vb.major) {
        (0, 0) if va.minor == 0 && vb.minor == 0 => va.patch == vb.patch,
        (0, 0) => va.minor == vb.minor,
        (a, b) => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal core module that passes the module-level rules.
    const GOOD_CORE: &str = r#"(core module $m
        (memory (export "memory") 1 1)
        (func (export "f") (result i32) i32.const 0))"#;

    /// A component exporting an instance under `export_name`, optionally importing
    /// `import_name` as an empty instance, with `core` as its one core module.
    fn component(import_name: Option<&str>, export_name: &str, core: &str) -> Vec<u8> {
        let import = import_name
            .map(|n| format!(r#"(import "{n}" (instance))"#))
            .unwrap_or_default();
        let wat = format!(
            r#"(component
                {import}
                {core}
                (core instance $i (instantiate $m))
                (type $t (func (result u32)))
                (func $f (type $t) (canon lift (core func $i "f")))
                (instance $e (export "f" (func $f)))
                (export "{export_name}" (instance $e)))"#
        );
        wat::parse_str(wat).expect("test component WAT parses")
    }

    fn renderer(granted: &'static [&'static str]) -> ComponentProfile<'static> {
        ComponentProfile {
            world: BlockWorld::Renderer,
            granted,
            max_memory_pages: 16,
        }
    }

    fn bot(granted: &'static [&'static str]) -> ComponentProfile<'static> {
        ComponentProfile {
            world: BlockWorld::Bot,
            granted,
            max_memory_pages: 16,
        }
    }

    fn check(bytes: &[u8], profile: &ComponentProfile<'_>) -> Vec<ComponentViolation> {
        validate_component(bytes, profile).unwrap().violations
    }

    #[test]
    fn a_minimal_renderer_passes() {
        let c = component(None, "jig:block/render@0.1.0", GOOD_CORE);
        let report = validate_component(&c, &renderer(&[])).unwrap();
        assert!(report.is_compliant(), "{:?}", report.violations);
        assert_eq!(report.exports, ["jig:block/render@0.1.0"]);
    }

    #[test]
    fn a_compatible_patch_version_passes_and_an_incompatible_minor_does_not() {
        let patch = component(None, "jig:block/render@0.1.7", GOOD_CORE);
        assert!(check(&patch, &renderer(&[])).is_empty());
        let minor = component(None, "jig:block/render@0.2.0", GOOD_CORE);
        let v = check(&minor, &renderer(&[]));
        assert!(v.contains(&ComponentViolation::MissingExport(
            "jig:block/render@0.1.0".into()
        )));
        assert!(v.contains(&ComponentViolation::UnexpectedExport(
            "jig:block/render@0.2.0".into()
        )));
    }

    #[test]
    fn a_core_module_is_refused() {
        let core = wat::parse_str("(module)").unwrap();
        assert_eq!(
            check(&core, &renderer(&[])),
            [ComponentViolation::NotAComponent]
        );
    }

    #[test]
    fn the_wrong_world_export_is_refused() {
        let c = component(None, "jig:block/handler@0.1.0", GOOD_CORE);
        let v = check(&c, &renderer(&[]));
        assert!(v.contains(&ComponentViolation::MissingExport(
            "jig:block/render@0.1.0".into()
        )));
    }

    #[test]
    fn a_wasi_import_is_refused_even_if_granted() {
        let c = component(
            Some("wasi:clocks/wall-clock@0.2.0"),
            "jig:block/handler@0.1.0",
            GOOD_CORE,
        );
        let v = check(&c, &bot(&["wasi:clocks/wall-clock@0.2.0"]));
        assert_eq!(
            v,
            [ComponentViolation::WasiImport(
                "wasi:clocks/wall-clock@0.2.0".into()
            )]
        );
    }

    #[test]
    fn a_renderer_may_import_only_compose_and_only_when_granted() {
        let compose = component(
            Some("jig:host/compose@0.1.0"),
            "jig:block/render@0.1.0",
            GOOD_CORE,
        );
        assert!(check(&compose, &renderer(&["jig:host/compose@0.1.0"])).is_empty());
        assert_eq!(
            check(&compose, &renderer(&[])),
            [ComponentViolation::UngrantedImport(
                "jig:host/compose@0.1.0".into()
            )]
        );
        let state = component(
            Some("jig:host/fetch@0.1.0"),
            "jig:block/render@0.1.0",
            GOOD_CORE,
        );
        assert_eq!(
            check(&state, &renderer(&["jig:host/fetch@0.1.0"])),
            [ComponentViolation::ImportNotInWorld(
                "jig:host/fetch@0.1.0".into()
            )]
        );
    }

    #[test]
    fn a_bot_import_must_be_granted() {
        let c = component(
            Some("jig:host/fetch@0.1.0"),
            "jig:block/handler@0.1.0",
            GOOD_CORE,
        );
        assert!(check(&c, &bot(&["jig:host/fetch@0.1.0"])).is_empty());
        assert_eq!(
            check(&c, &bot(&[])),
            [ComponentViolation::UngrantedImport(
                "jig:host/fetch@0.1.0".into()
            )]
        );
    }

    #[test]
    fn a_float_in_a_core_module_is_refused() {
        let core = r#"(core module $m
            (memory (export "memory") 1 1)
            (func (export "f") (result i32)
                f32.const 1 f32.const 2 f32.add drop i32.const 0))"#;
        let c = component(None, "jig:block/render@0.1.0", core);
        let v = check(&c, &renderer(&[]));
        assert!(
            v.iter().any(|v| matches!(
                v,
                ComponentViolation::CoreModule {
                    module: 0,
                    violation: DeterminismViolation::FloatInstruction(_)
                }
            )),
            "{v:?}"
        );
    }

    #[test]
    fn a_memory_without_a_maximum_or_over_the_limit_is_refused() {
        let unbounded = r#"(core module $m (memory (export "memory") 1)
            (func (export "f") (result i32) i32.const 0))"#;
        let v = check(
            &component(None, "jig:block/render@0.1.0", unbounded),
            &renderer(&[]),
        );
        assert!(v.contains(&ComponentViolation::CoreModule {
            module: 0,
            violation: DeterminismViolation::MemoryMissingMaximum
        }));
        let too_big = r#"(core module $m (memory (export "memory") 1 64)
            (func (export "f") (result i32) i32.const 0))"#;
        let v = check(
            &component(None, "jig:block/render@0.1.0", too_big),
            &renderer(&[]),
        );
        assert!(
            v.iter().any(|v| matches!(
                v,
                ComponentViolation::CoreModule {
                    violation: DeterminismViolation::MemoryMaximumExceedsLimit { .. },
                    ..
                }
            )),
            "{v:?}"
        );
    }

    #[test]
    fn simd_in_a_core_module_is_outside_the_feature_set() {
        let core = r#"(core module $m (memory (export "memory") 1 1)
            (func (export "f") (result i32) v128.const i32x4 0 0 0 0 drop i32.const 0))"#;
        let v = check(
            &component(None, "jig:block/render@0.1.0", core),
            &renderer(&[]),
        );
        assert!(
            v.iter()
                .any(|v| matches!(v, ComponentViolation::OutsideFeatureSet(_))),
            "{v:?}"
        );
    }

    #[test]
    fn a_code_free_nested_component_and_the_types_import_pass() {
        // The shape wit-component emits: `jig:block/types` imported, and the export typed by
        // instantiating an inner component that holds no code.
        let wat = r#"(component
            (import "jig:block/types@0.1.0" (instance $types))
            (core module $m (memory (export "memory") 1 1)
                (func (export "f") (result i32) i32.const 0))
            (core instance $i (instantiate $m))
            (type $t (func (result u32)))
            (func $f (type $t) (canon lift (core func $i "f")))
            (component $shim
                (import "import-func-f" (func $g (result u32)))
                (export "f" (func $g)))
            (instance $e (instantiate $shim (with "import-func-f" (func $f))))
            (export "jig:block/render@0.1.0" (instance $e)))"#;
        let c = wat::parse_str(wat).unwrap();
        let report = validate_component(&c, &renderer(&[])).unwrap();
        assert!(report.is_compliant(), "{:?}", report.violations);
        assert_eq!(report.imports, ["jig:block/types@0.1.0"]);
    }

    #[test]
    fn a_nested_component_with_code_is_refused() {
        let wat = r#"(component
            (component $inner
                (core module $hidden (func (export "g"))))
            (core module $m (memory (export "memory") 1 1)
                (func (export "f") (result i32) i32.const 0))
            (core instance $i (instantiate $m))
            (type $t (func (result u32)))
            (func $f (type $t) (canon lift (core func $i "f")))
            (instance $e (export "f" (func $f)))
            (export "jig:block/render@0.1.0" (instance $e)))"#;
        let c = wat::parse_str(wat).unwrap();
        assert!(check(&c, &renderer(&[])).contains(&ComponentViolation::NestedComponent));
    }

    #[test]
    fn async_lifting_is_outside_the_feature_set() {
        let wat = r#"(component
            (core module $m (memory (export "memory") 1 1)
                (func (export "f") (result i32) i32.const 0))
            (core instance $i (instantiate $m))
            (type $t (func (result u32)))
            (func $f (type $t) (canon lift (core func $i "f") async))
            (instance $e (export "f" (func $f)))
            (export "jig:block/render@0.1.0" (instance $e)))"#;
        let c = wat::parse_str(wat).expect("async lift parses as text");
        let v = check(&c, &renderer(&[]));
        assert!(
            v.iter()
                .any(|v| matches!(v, ComponentViolation::OutsideFeatureSet(_))),
            "{v:?}"
        );
    }

    #[test]
    fn version_compatibility_follows_component_model_rules() {
        assert!(compatible("a:b/c@0.1.0", "a:b/c@0.1.9"));
        assert!(!compatible("a:b/c@0.1.0", "a:b/c@0.2.0"));
        assert!(compatible("a:b/c@1.0.0", "a:b/c@1.4.2"));
        assert!(!compatible("a:b/c@1.0.0", "a:b/c@2.0.0"));
        assert!(!compatible("a:b/c@0.0.1", "a:b/c@0.0.2"));
        assert!(!compatible("a:b/c", "a:b/c@0.1.0"));
        assert!(!compatible("a:b/c@0.1.0", "a:b/d@0.1.0"));
    }
}
