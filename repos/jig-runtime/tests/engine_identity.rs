//! The engine identity recorded beside fuel numbers.

use jig_runtime::component::{Backend, ComponentRuntime};
use jig_runtime::{FUEL_SCHEDULE_VERSION, RuntimeConfig, WASMTIME_VERSION};

/// The identity names wasmtime, not this crate. `RUNTIME_VERSION` used to be
/// jig-runtime's own version, "0.1.0" across wasmtime 24 to 49.
#[test]
fn the_identity_names_the_wasmtime_version_and_schedule() {
    let identity = ComponentRuntime::new().expect("runtime").engine_identity();
    assert_eq!(identity.wasmtime, WASMTIME_VERSION);
    assert_ne!(
        identity.wasmtime,
        env!("CARGO_PKG_VERSION"),
        "the identity must not be jig-runtime's own crate version"
    );
    assert!(
        identity.wasmtime.split('.').count() == 3,
        "expected a full semver, got {}",
        identity.wasmtime
    );
    assert_eq!(identity.fuel_schedule, FUEL_SCHEDULE_VERSION);
}

/// The fingerprint is stable for one configuration and moves with any engine
/// setting that changes how a module compiles or is metered.
#[test]
fn the_fingerprint_tracks_the_engine_configuration() {
    let fingerprint = |config: RuntimeConfig| {
        ComponentRuntime::with_config(&config, Backend::Native)
            .expect("runtime")
            .engine_identity()
            .config_fingerprint
    };

    let default = fingerprint(RuntimeConfig::default());
    assert!(default.starts_with("blake3:"), "got {default}");
    assert_eq!(
        default,
        fingerprint(RuntimeConfig::default()),
        "one configuration must give one fingerprint"
    );

    let mut no_fuel = RuntimeConfig::default();
    no_fuel.fuel.enabled = false;
    assert_ne!(default, fingerprint(no_fuel), "fuel metering must count");

    let mut no_nan_canonicalization = RuntimeConfig::default();
    no_nan_canonicalization.engine.canonicalize_nans = false;
    assert_ne!(
        default,
        fingerprint(no_nan_canonicalization),
        "NaN canonicalization must count"
    );

    let mut bigger_memory = RuntimeConfig::default();
    bigger_memory.limits.memory_max_mb *= 2;
    assert_ne!(
        default,
        fingerprint(bigger_memory),
        "the memory layout must count"
    );
}
