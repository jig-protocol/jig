//! `jig block lint`: check a component against the determinism profile `jig-det-1`.
//!
//! The checks are jig-core's [`validate_component`], the same ones a host runs before it
//! compiles a block, so passing here means a host will not refuse the component on those
//! grounds. What this module adds is explanation: each violation comes with the usual cause and
//! fix, and a float instruction is traced to the functions that contain it.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use jig_core::component_validation::{
    BlockWorld, ComponentProfile, ComponentReport, ComponentViolation, validate_component,
};
use jig_core::wasm_validation::DeterminismViolation;
use wasmparser::{Encoding, KnownCustom, Name, Parser, Payload};

use crate::cmd::block_project::Project;

/// The outcome of linting one component.
#[derive(Debug)]
pub struct Lint {
    pub report: ComponentReport,
    /// Functions containing float instructions, by name where the binary keeps names.
    pub float_functions: Vec<String>,
}

impl Lint {
    pub fn passes(&self) -> bool {
        self.report.is_compliant()
    }

    /// One line per violation, each followed by its hint, then the float functions.
    pub fn render(&self) -> String {
        let mut out = String::new();
        if self.passes() {
            out.push_str("ok: passes jig-det-1\n");
            return out;
        }
        // A float-using build has hundreds of float instructions; one line per module says it.
        let mut floats: BTreeMap<usize, usize> = BTreeMap::new();
        for v in &self.report.violations {
            if let ComponentViolation::CoreModule {
                module,
                violation: DeterminismViolation::FloatInstruction(_),
            } = v
            {
                *floats.entry(*module).or_default() += 1;
                continue;
            }
            out.push_str(&format!("error: {v}\n"));
            if let Some(hint) = hint(v) {
                out.push_str(&format!("  hint: {hint}\n"));
            }
        }
        for (module, n) in &floats {
            out.push_str(&format!(
                "error: core module {module}: {n} floating-point instruction{}\n  hint: {FLOAT_HINT}\n",
                if *n == 1 { "" } else { "s" }
            ));
        }
        if !self.float_functions.is_empty() {
            out.push_str("  float instructions are in:\n");
            for f in &self.float_functions {
                out.push_str(&format!("    {f}\n"));
            }
        }
        out
    }
}

/// Lint `bytes` as a block of `world` that may use at most `max_memory_pages`. A renderer is
/// granted nothing, so any import beyond `jig:block/types` is refused.
pub fn lint(bytes: &[u8], world: BlockWorld, max_memory_pages: u32) -> Result<Lint> {
    let report = validate_component(
        bytes,
        &ComponentProfile {
            world,
            granted: &[],
            max_memory_pages,
        },
    )
    .context("the file could not be read as WebAssembly")?;
    let has_float = report.violations.iter().any(|v| {
        matches!(
            v,
            ComponentViolation::CoreModule {
                violation: DeterminismViolation::FloatInstruction(_),
                ..
            }
        )
    });
    let float_functions = if has_float {
        float_functions(bytes)
    } else {
        Vec::new()
    };
    Ok(Lint {
        report,
        float_functions,
    })
}

/// Lint `path`: a block project directory (its built component, with the project's world and
/// memory limit), or a `.wasm` file (as a renderer limited to `max_memory_pages`).
pub fn lint_path(path: &Path, max_memory_pages: u32) -> Result<Lint> {
    let (file, world, pages) = if path.is_dir() {
        let project = Project::load(path)?;
        let file = project.component_path();
        if !file.exists() {
            bail!(
                "{} has not been built; run `jig block build` first",
                path.display()
            );
        }
        let world = project.file.block.world.block_world();
        (file, world, project.file.limits.memory_max_pages)
    } else {
        (path.to_path_buf(), BlockWorld::Renderer, max_memory_pages)
    };
    let bytes = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
    lint(&bytes, world, pages)
}

const FLOAT_HINT: &str = "blocks may not contain floating-point instructions, even unused ones; \
                          the usual causes are serde_json, float formatting (`{:.2}`) and `as f64`";

/// The usual cause of a violation, and what to do about it.
fn hint(v: &ComponentViolation) -> Option<&'static str> {
    Some(match v {
        ComponentViolation::NotAComponent => {
            "this is a core module or not WebAssembly; `jig block build` turns a module into a \
             component"
        }
        ComponentViolation::WasiImport(_) => {
            "blocks get nothing from WASI; build for wasm32-unknown-unknown (set in \
             .cargo/config.toml by `jig block new`), not wasm32-wasip1 or wasm32-wasip2"
        }
        ComponentViolation::ImportNotInWorld(_) | ComponentViolation::UngrantedImport(_) => {
            "a renderer imports only jig:block/types; remove the code that needs this import"
        }
        ComponentViolation::MissingExport(_) | ComponentViolation::UnexpectedExport(_) => {
            "check that `wit_bindgen::generate!` names the world in jig-block.toml, and that \
             `export!` is called once"
        }
        ComponentViolation::CoreModule { violation, .. } => match violation {
            DeterminismViolation::FloatInstruction(_) => FLOAT_HINT,
            DeterminismViolation::MemoryMissingMaximum => {
                "add `-C link-arg=--max-memory=<bytes>` to rustflags in .cargo/config.toml; \
                 `jig block new` sets it"
            }
            DeterminismViolation::MemoryMaximumExceedsLimit { .. }
            | DeterminismViolation::MemoryMinimumExceedsLimit { .. } => {
                "make --max-memory in .cargo/config.toml (bytes) and memory_max_pages in \
                 jig-block.toml (64 KiB pages) agree"
            }
            DeterminismViolation::DisallowedImport { .. }
            | DeterminismViolation::ForbiddenImport { .. } => {
                "a core module imports from the host; build for wasm32-unknown-unknown"
            }
            _ => return None,
        },
        _ => return None,
    })
}

/// Every function, in every core module, that contains a float instruction: its demangled name
/// if the name section has one, else `module N, function M`.
fn float_functions(bytes: &[u8]) -> Vec<String> {
    #[derive(Default)]
    struct Module {
        imported_funcs: u32,
        bodies_seen: u32,
        floats: Vec<u32>,
        names: BTreeMap<u32, String>,
    }
    fn finish(index: usize, m: Module, out: &mut Vec<String>) {
        for f in m.floats {
            out.push(match m.names.get(&f) {
                Some(n) => format!("{:#}", rustc_demangle::demangle(n)),
                None => format!("module {index}, function {f}"),
            });
        }
    }

    let mut out = Vec::new();
    // Core modules nest inside components; `parse_all` walks them depth-first, so a stack of
    // open modules tracks which one each payload belongs to.
    let mut stack: Vec<Option<(usize, Module)>> = Vec::new();
    let mut next_module = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else { break };
        match payload {
            Payload::Version { encoding, .. } => {
                if encoding == Encoding::Module {
                    stack.push(Some((next_module, Module::default())));
                    next_module += 1;
                } else {
                    stack.push(None);
                }
            }
            Payload::End(_) => {
                if let Some(Some((i, m))) = stack.pop() {
                    finish(i, m, &mut out);
                }
            }
            Payload::ImportSection(reader) => {
                if let Some(Some((_, m))) = stack.last_mut() {
                    for imp in reader.into_imports().flatten() {
                        if matches!(imp.ty, wasmparser::TypeRef::Func(_)) {
                            m.imported_funcs += 1;
                        }
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                if let Some(Some((_, m))) = stack.last_mut() {
                    let index = m.imported_funcs + m.bodies_seen;
                    m.bodies_seen += 1;
                    if body_has_float(&body) {
                        m.floats.push(index);
                    }
                }
            }
            Payload::CustomSection(section) => {
                if let (Some(Some((_, m))), KnownCustom::Name(reader)) =
                    (stack.last_mut(), section.as_known())
                {
                    for name in reader.into_iter().flatten() {
                        if let Name::Function(map) = name {
                            for naming in map.into_iter().flatten() {
                                m.names.insert(naming.index, naming.name.to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn body_has_float(body: &wasmparser::FunctionBody<'_>) -> bool {
    let Ok(mut ops) = body.get_operators_reader() else {
        return false;
    };
    while !ops.eof() {
        let Ok(op) = ops.read() else { return false };
        let name = format!("{op:?}");
        if name.contains("F32") || name.contains("F64") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGES: u32 = 256;

    /// A renderer-shaped component around one core module. The component does not export the
    /// render interface, so it also fails on the missing export; tests look for their own
    /// violation.
    fn component(core: &str) -> Vec<u8> {
        wat::parse_str(format!(
            "(component (core module $m {core}) (core instance (instantiate $m)))"
        ))
        .expect("test WAT parses")
    }

    fn rendered(bytes: &[u8]) -> String {
        lint(bytes, BlockWorld::Renderer, PAGES).unwrap().render()
    }

    #[test]
    fn a_float_is_traced_to_its_function_by_name() {
        let bytes = component(
            r#"(memory 1 1)
               (func $fine (result i32) i32.const 1)
               (func $_ZN5hello7average17h0123456789abcdefE (result f64) f64.const 0.5)"#,
        );
        let l = lint(&bytes, BlockWorld::Renderer, PAGES).unwrap();
        assert!(!l.passes());
        assert_eq!(l.float_functions, vec!["hello::average".to_string()]);
        let text = l.render();
        assert!(text.contains("serde_json"), "{text}");
        assert!(text.contains("hello::average"), "{text}");
        assert!(
            text.contains("core module 0: 1 floating-point instruction\n"),
            "{text}"
        );
        assert_eq!(
            text.matches("floating-point").count(),
            2,
            "one error and one hint: {text}"
        );
    }

    #[test]
    fn an_unnamed_float_function_is_reported_by_index() {
        // A function import shifts the defined function's index to 1.
        let bytes = wat::parse_str(
            r#"(component
                (core module $i (func (export "f")))
                (core instance $ii (instantiate $i))
                (core module $m
                    (import "i" "f" (func))
                    (memory 1 1)
                    (func (result f32) f32.const 1))
                (core instance (instantiate $m (with "i" (instance $ii)))))"#,
        )
        .unwrap();
        let l = lint(&bytes, BlockWorld::Renderer, PAGES).unwrap();
        assert_eq!(l.float_functions, vec!["module 1, function 1".to_string()]);
    }

    #[test]
    fn a_missing_memory_maximum_gets_the_rustflags_hint() {
        let text = rendered(&component("(memory 1)"));
        assert!(text.contains("missing maximum"), "{text}");
        assert!(text.contains("--max-memory"), "{text}");
    }

    #[test]
    fn a_memory_over_the_project_limit_gets_the_agree_hint() {
        let text = rendered(&component("(memory 1 512)"));
        assert!(text.contains("memory_max_pages"), "{text}");
    }

    #[test]
    fn a_core_module_is_told_to_build() {
        let core = wat::parse_str("(module (memory 1 1))").unwrap();
        let text = rendered(&core);
        assert!(text.contains("jig block build"), "{text}");
    }
}
