//! One component linker per grant (JEP-0007 §3.2).
//!
//! A block reaches a host function only if its effective authority grants the interface, and
//! the enforcement is structural: an interface that is not granted is absent from the linker, so
//! a component importing it fails to instantiate. A bug in a later scope check cannot expose a
//! function that was never linked.
//!
//! Every linker defines `jig:block/types` as an empty instance (it carries types only, and every
//! wit-bindgen component imports it), plus exactly the granted import interfaces. An interface is
//! added only by a provider the host registered for it with [`GrantLinkers::provide`]. A granted
//! interface with no provider is refused when its linker is built: nothing is ever stubbed, and
//! no unknown import is ever defined as a trap.
//!
//! Effects (`post`, `state`, `timer`) are returned, not called, so they never reach a linker; only
//! [`Capability::is_import`] capabilities do.
//!
//! Building a linker and pre-instantiating a component are both cached: linkers by the set of
//! granted imports, `InstancePre`s by component hash and that set. Running the same block under
//! the same grant shape costs one cache lookup.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use jig_core::grant::{Capability, Grant};
use wasmtime::Engine;
use wasmtime::component::{Component, InstancePre, Linker};

use crate::error::{Result, RuntimeError};

/// The version of `jig:block/types` every linker defines as an empty instance.
pub const TYPES_INTERFACE: &str = "jig:block/types@0.1.0";

/// Adds one host interface to a linker.
pub type Provider<T> = fn(&mut Linker<T>) -> wasmtime::Result<()>;

type ImportSet = BTreeSet<Capability>;

/// The per-grant linkers of one engine.
pub struct GrantLinkers<T: 'static> {
    engine: Engine,
    providers: BTreeMap<Capability, Provider<T>>,
    linkers: Mutex<HashMap<ImportSet, Arc<Linker<T>>>>,
    pres: Mutex<HashMap<(String, ImportSet), InstancePre<T>>>,
}

impl<T: 'static> GrantLinkers<T> {
    /// Linkers for `engine` with no host interfaces provided yet.
    pub fn new(engine: &Engine) -> Self {
        Self {
            engine: engine.clone(),
            providers: BTreeMap::new(),
            linkers: Mutex::new(HashMap::new()),
            pres: Mutex::new(HashMap::new()),
        }
    }

    /// Register the provider of an import capability. Providing an effect capability, or the
    /// same capability twice, is refused.
    pub fn provide(&mut self, capability: Capability, provider: Provider<T>) -> Result<()> {
        if !capability.is_import() {
            return Err(RuntimeError::InvalidConfig(format!(
                "{} is an effect, not an import; it is never linked",
                capability.name()
            )));
        }
        if self.providers.insert(capability, provider).is_some() {
            return Err(RuntimeError::InvalidConfig(format!(
                "{} provided twice",
                capability.name()
            )));
        }
        // A new provider can change what a cached linker would have refused.
        self.linkers.lock().expect("linker cache poisoned").clear();
        self.pres.lock().expect("pre cache poisoned").clear();
        Ok(())
    }

    /// The linker for `grant`: `jig:block/types` and the granted imports, nothing else.
    pub fn for_grant(&self, grant: &Grant) -> Result<Arc<Linker<T>>> {
        self.for_imports(grant.imports().collect())
    }

    fn for_imports(&self, imports: ImportSet) -> Result<Arc<Linker<T>>> {
        let mut cache = self.linkers.lock().expect("linker cache poisoned");
        if let Some(linker) = cache.get(&imports) {
            return Ok(Arc::clone(linker));
        }
        let mut linker = Linker::new(&self.engine);
        linker
            .instance(TYPES_INTERFACE)
            .map_err(|e| RuntimeError::InternalError(format!("linking {TYPES_INTERFACE}: {e}")))?;
        for capability in &imports {
            let provider =
                self.providers
                    .get(capability)
                    .ok_or_else(|| RuntimeError::CapabilityDenied {
                        capability: format!("{} is not provided by this host", capability.name()),
                    })?;
            provider(&mut linker).map_err(|e| {
                RuntimeError::InternalError(format!("linking {}: {e:#}", capability.name()))
            })?;
        }
        let linker = Arc::new(linker);
        cache.insert(imports, Arc::clone(&linker));
        Ok(linker)
    }

    /// Type-check `component` against the linker for `grant`, once per (component, grant shape).
    ///
    /// `component_hash` must identify the component's bytes; callers pass the `blake3:` hash
    /// they already computed. A component that imports anything the linker does not define is
    /// refused here, before any instance exists.
    pub fn instantiate_pre(
        &self,
        component_hash: &str,
        component: &Component,
        grant: &Grant,
    ) -> Result<InstancePre<T>> {
        let imports: ImportSet = grant.imports().collect();
        let key = (component_hash.to_string(), imports.clone());
        if let Some(pre) = self.pres.lock().expect("pre cache poisoned").get(&key) {
            return Ok(pre.clone());
        }
        let linker = self.for_imports(imports)?;
        let pre = linker
            .instantiate_pre(component)
            .map_err(|e| RuntimeError::InstantiationError(format!("{e:#}")))?;
        self.pres
            .lock()
            .expect("pre cache poisoned")
            .insert(key, pre.clone());
        Ok(pre)
    }

    /// How many distinct linkers have been built (for tests and metrics).
    pub fn linker_count(&self) -> usize {
        self.linkers.lock().expect("linker cache poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_core::grant::Scope;
    use std::collections::BTreeSet;
    use wasmtime::{Config, Store};

    fn engine() -> Engine {
        let mut config = Config::new();
        config.wasm_component_model(true);
        Engine::new(&config).expect("engine")
    }

    fn blocks_grant() -> Grant {
        Grant::from_scopes([Scope::Blocks {
            channels: BTreeSet::new(),
            cids: BTreeSet::new(),
            max_bytes: 1,
            max_calls: 1,
        }])
        .unwrap()
    }

    fn state_grant() -> Grant {
        Grant::from_scopes([Scope::State { max_bytes: 1 }]).unwrap()
    }

    /// A stand-in for the slice-6 provider: `jig:host/blocks` with one function.
    fn dummy_blocks(linker: &mut Linker<()>) -> wasmtime::Result<()> {
        linker
            .instance("jig:host/blocks@0.1.0")?
            .func_wrap("probe", |_store, (): ()| Ok((7u32,)))?;
        Ok(())
    }

    /// A component that imports `jig:host/blocks@0.1.0#probe` and calls it from a start function.
    fn imports_blocks() -> Component {
        component(
            r#"(component
                (import "jig:host/blocks@0.1.0" (instance $h (export "probe" (func (result u32)))))
                (core func $probe (canon lower (func $h "probe")))
                (core module $m
                    (import "h" "probe" (func $p (result i32)))
                    (func $f (drop (call $p)))
                    (start $f))
                (core instance (instantiate $m (with "h" (instance (export "probe" (func $probe)))))))"#,
        )
    }

    /// A component that imports only `jig:block/types`.
    fn imports_types_only() -> Component {
        component(r#"(component (import "jig:block/types@0.1.0" (instance)))"#)
    }

    fn component(wat: &str) -> Component {
        Component::new(&engine_cache(), wat::parse_str(wat).expect("WAT")).expect("compiles")
    }

    // Components must be compiled by the engine that links them.
    fn engine_cache() -> Engine {
        thread_local!(static ENGINE: Engine = engine());
        ENGINE.with(Clone::clone)
    }

    fn linkers() -> GrantLinkers<()> {
        let mut l = GrantLinkers::new(&engine_cache());
        l.provide(Capability::Blocks, dummy_blocks).unwrap();
        l
    }

    #[test]
    fn a_granted_import_links_and_runs() {
        let l = linkers();
        let pre = l
            .instantiate_pre("blake3:a", &imports_blocks(), &blocks_grant())
            .expect("granted import links");
        let mut store = Store::new(&engine_cache(), ());
        pre.instantiate(&mut store).expect("instantiates");
    }

    #[test]
    fn an_ungranted_import_fails_before_any_instance_exists() {
        let l = linkers();
        for grant in [Grant::empty(), state_grant()] {
            let Err(err) = l.instantiate_pre("blake3:a", &imports_blocks(), &grant) else {
                panic!("ungranted import must not link");
            };
            assert!(matches!(err, RuntimeError::InstantiationError(_)), "{err}");
            assert!(err.to_string().contains("jig:host/blocks"), "{err}");
        }
    }

    #[test]
    fn types_link_under_an_empty_grant() {
        let l = linkers();
        let pre = l
            .instantiate_pre("blake3:t", &imports_types_only(), &Grant::empty())
            .expect("jig:block/types is always linked");
        pre.instantiate(&mut Store::new(&engine_cache(), ()))
            .expect("instantiates");
    }

    #[test]
    fn the_wit_bindgen_text_block_links_under_an_empty_grant() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../text-block/artifacts/text_block.component.wasm"
        ))
        .expect("text-block component artifact");
        let c = Component::new(&engine_cache(), bytes).expect("compiles");
        let l = linkers();
        l.instantiate_pre("blake3:text-block", &c, &Grant::empty())
            .expect("a renderer needs only jig:block/types");
    }

    #[test]
    fn a_wasi_import_is_refused_under_every_grant() {
        let c = component(
            r#"(component (import "wasi:clocks/wall-clock@0.2.0" (instance (export "now" (func (result u64))))))"#,
        );
        let l = linkers();
        for grant in [Grant::empty(), blocks_grant(), state_grant()] {
            let Err(err) = l.instantiate_pre("blake3:w", &c, &grant) else {
                panic!("wasi is never linked");
            };
            assert!(err.to_string().contains("wasi:clocks"), "{err}");
        }
    }

    #[test]
    fn a_granted_import_with_no_provider_is_refused() {
        let l: GrantLinkers<()> = GrantLinkers::new(&engine_cache());
        let Err(err) = l.for_grant(&blocks_grant()) else {
            panic!("no provider, no linker");
        };
        assert!(
            matches!(err, RuntimeError::CapabilityDenied { .. }),
            "{err}"
        );
    }

    #[test]
    fn effects_are_never_linked_or_provided() {
        let mut l = linkers();
        // A grant of effects only builds the bare linker.
        l.for_grant(&state_grant()).unwrap();
        l.for_grant(&Grant::empty()).unwrap();
        assert_eq!(l.linker_count(), 1, "effects add nothing to a linker");
        assert!(l.provide(Capability::State, dummy_blocks).is_err());
        assert!(
            l.provide(Capability::Blocks, dummy_blocks).is_err(),
            "twice"
        );
    }

    #[test]
    fn linkers_and_pres_are_cached_by_grant_shape() {
        let l = linkers();
        let c = imports_blocks();
        let a = l.for_grant(&blocks_grant()).unwrap();
        let b = l.for_grant(&blocks_grant()).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        l.instantiate_pre("blake3:a", &c, &blocks_grant()).unwrap();
        l.instantiate_pre("blake3:a", &c, &blocks_grant()).unwrap();
        assert_eq!(l.linker_count(), 1);
        assert_eq!(l.pres.lock().unwrap().len(), 1);
    }
}
