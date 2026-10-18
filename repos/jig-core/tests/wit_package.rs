//! The `jig:block` WIT package (JEP-0006) parses and has the shape the design fixes.
//!
//! The package lives with the spec, in `repos/jig-spec/wit/jig-block/`. This test keeps it
//! valid WIT, and fails if a world gains an import or loses its export without a matching
//! spec change.

use std::path::Path;

use wit_parser::{Resolve, WorldItem, WorldKey};

fn resolve() -> (Resolve, wit_parser::PackageId) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../jig-spec/wit/jig-block");
    let mut resolve = Resolve::default();
    let (pkg, _files) = resolve
        .push_dir(&dir)
        .unwrap_or_else(|e| panic!("jig:block WIT does not parse: {e:?}"));
    (resolve, pkg)
}

fn interface_name(resolve: &Resolve, key: &WorldKey) -> String {
    match key {
        WorldKey::Name(n) => n.clone(),
        WorldKey::Interface(id) => resolve.interfaces[*id]
            .name
            .clone()
            .expect("exported interfaces are named"),
    }
}

/// The interfaces a world exports, ignoring the `types` interface it pulls in by `use`.
fn exports(resolve: &Resolve, pkg: wit_parser::PackageId, world: &str) -> Vec<String> {
    let id = resolve
        .select_world(&[pkg], Some(world))
        .unwrap_or_else(|e| panic!("world `{world}` missing: {e:?}"));
    resolve.worlds[id]
        .exports
        .keys()
        .map(|k| interface_name(resolve, k))
        .collect()
}

/// The interfaces a world imports, other than the package's own `types`, which `use` adds.
fn foreign_imports(resolve: &Resolve, pkg: wit_parser::PackageId, world: &str) -> Vec<String> {
    let id = resolve.select_world(&[pkg], Some(world)).unwrap();
    resolve.worlds[id]
        .imports
        .iter()
        .filter_map(|(k, item)| match item {
            WorldItem::Interface { id, .. } => {
                let iface = &resolve.interfaces[*id];
                let own = iface.package == Some(pkg) && iface.name.as_deref() == Some("types");
                (!own).then(|| interface_name(resolve, k))
            }
            _ => Some(interface_name(resolve, k)),
        })
        .collect()
}

#[test]
fn the_package_is_jig_block_at_0_1_0() {
    let (resolve, pkg) = resolve();
    let name = &resolve.packages[pkg].name;
    assert_eq!(name.namespace, "jig");
    assert_eq!(name.name, "block");
    assert_eq!(
        name.version.as_ref().map(|v| v.to_string()).as_deref(),
        Some("0.1.0")
    );
}

#[test]
fn renderer_exports_render_and_imports_nothing_yet() {
    let (resolve, pkg) = resolve();
    assert_eq!(exports(&resolve, pkg, "renderer"), ["render"]);
    // `jig:host/compose` is added by JEP-0007's package, not declared here.
    assert!(foreign_imports(&resolve, pkg, "renderer").is_empty());
}

#[test]
fn bot_exports_handler_and_imports_nothing_yet() {
    let (resolve, pkg) = resolve();
    assert_eq!(exports(&resolve, pkg, "bot"), ["handler"]);
    assert!(foreign_imports(&resolve, pkg, "bot").is_empty());
}

#[test]
fn no_type_in_the_package_is_a_float() {
    use wit_parser::{Type, TypeDefKind};

    let (resolve, pkg) = resolve();
    let is_float = |t: &Type| matches!(t, Type::F32 | Type::F64);
    for (_, def) in resolve.types.iter() {
        let Some(owner_pkg) = (match def.owner {
            wit_parser::TypeOwner::Interface(i) => resolve.interfaces[i].package,
            wit_parser::TypeOwner::World(w) => resolve.worlds[w].package,
            wit_parser::TypeOwner::None => None,
        }) else {
            continue;
        };
        if owner_pkg != pkg {
            continue;
        }
        let floats = match &def.kind {
            TypeDefKind::Record(r) => r.fields.iter().any(|f| is_float(&f.ty)),
            TypeDefKind::Variant(v) => v.cases.iter().any(|c| c.ty.as_ref().is_some_and(is_float)),
            TypeDefKind::List(t) | TypeDefKind::Option(t) | TypeDefKind::Type(t) => is_float(t),
            TypeDefKind::Tuple(t) => t.types.iter().any(is_float),
            TypeDefKind::Result(r) => {
                r.ok.as_ref().is_some_and(is_float) || r.err.as_ref().is_some_and(is_float)
            }
            _ => false,
        };
        assert!(
            !floats,
            "type {:?} uses f32/f64; jig-det-1 forbids floats",
            def.name
        );
    }
    for (_, f) in resolve
        .interfaces
        .iter()
        .filter(|(_, i)| i.package == Some(pkg))
        .flat_map(|(_, i)| i.functions.iter())
    {
        let params = f.params.iter().any(|p| is_float(&p.ty));
        let result = f.result.as_ref().is_some_and(is_float);
        assert!(!params && !result, "function {} uses f32/f64", f.name);
    }
}
