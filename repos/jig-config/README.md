# jig-config

Configuration types shared by `jig-server` and `jig-nameserver`.

- `v0_0_2_server`: `JigServerConfig`, the `[server]`, `[identity]`, `[federation]`, `[auth]`,
  `[bridges]`, `[nameserver]` and `[debug]` sections a jig-server `--config` file carries.
  `unsafe_options_active()` lists the antipattern flags a server advertises at
  `/.well-known/jig`.
- `default_config_path()`: `~/.jig/config.toml`. jig-server only reads it to warn that the file
  is ignored; `jig-nameserver` still loads it.

The root-level server keys (`database_path`, `bind_address`, `port`, `[execution]`, `[tls]`)
live in `jig-server`'s own `ServerConfig`.
