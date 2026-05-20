#[test]
fn parse_podman_options_from_toml() {
    let s = r#"
        [runtime]
        engine = "podman"
        target = "ghcr.io/jig/server:latest"
        inherit_stdio = true

        [runtime.podman]
        network = "bridge"
        pull_policy = "missing"
        dangerously-run_as_root = false
        shamefully-disable_userns_remap = true

        [[runtime.podman.mounts]]
        host = "/var/jig/data"
        container = "/data"
        mode = "rw"
    "#;
    let cfg: jig_config::RuntimeConfig = toml::from_str(s).expect("parse toml");
    assert_eq!(cfg.runtime.common.engine.as_deref(), Some("podman"));
    assert_eq!(
        cfg.runtime.common.target.as_deref(),
        Some("ghcr.io/jig/server:latest")
    );
    assert!(cfg.runtime.common.inherit_stdio);
    assert_eq!(cfg.runtime.podman.network.as_deref(), Some("bridge"));
    assert_eq!(cfg.runtime.podman.pull_policy.as_deref(), Some("missing"));
    assert_eq!(cfg.runtime.podman.dangerously_run_as_root, Some(false));
    assert_eq!(
        cfg.runtime.podman.shamefully_disable_userns_remap,
        Some(true)
    );
    assert_eq!(cfg.runtime.podman.mounts.len(), 1);
    let m = &cfg.runtime.podman.mounts[0];
    assert_eq!(m.host, "/var/jig/data");
    assert_eq!(m.container, "/data");
    assert_eq!(m.mode.as_deref(), Some("rw"));
}
