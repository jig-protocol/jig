# jig-config

Configuration types shared by `jig-server` and `jig-nameserver`.

- `v0_0_2_server`: `JigServerConfig`, the `[server]`, `[identity]`, `[federation]`, `[auth]`,
  `[bridges]`, `[nameserver]` and `[debug]` sections a jig-server `--config` file carries.
  `unsafe_options_active()` lists the antipattern flags a server advertises at
  `/.well-known/jig`.
- `default_config_path()`: `~/.jig/config.toml`.
- `profiles` and `storage`: v0.0.1 profile and storage-tier types, kept only for jig-server's
  jig-config file discovery.

The root-level server keys (`database_path`, `bind_address`, `port`, `[execution]`, `[tls]`)
live in `jig-server`'s own `ServerConfig`.
