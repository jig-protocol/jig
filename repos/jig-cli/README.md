# jig-cli

Command-line interface for the Jig executable internet.

## Overview

`jig-cli` lets you publish and inspect Jig Blocks from a terminal. It talks to a running `jig-server` over the HTTP block API, building manifests and receipts with the same `jig-core` primitives used by the rest of the stack.

## Features

- **Block-native**: Sends canonical manifests with author DID and metadata.
- **Transport**: WebSocket `/api/v1/ws` for live chat (signed `Subscribe`, `Submit`), signed
  REST reads of `/api/v1/channels[/:slug/blocks]` for listing and backfill, and the
  `POST /api/v1/channels*` routes for channel ops. (`jig read` still calls the legacy `/blocks`
  route, which is off by default.)
- **Pipeline friendly**: Works with stdin/stdout; no local SQLite dependency.
- **Configurable**: `~/.jig/config.toml` stores server URL, author DID, and default channel.

## Quick Start

```bash
# Ensure a jig-server is running (see repos/jig-server)

# Initialise config (~/.jig/cli.toml)
jig init

# Send a block to the default channel
jig send "Hello, Jig!"

# Override channel and server on the fly
jig --server http://127.0.0.1:7117 send --channel '#ops' "Deploying now"

# Read the latest blocks
jig read --limit 20

# Follow new blocks in real-time
jig tail '#ops'
```

Example config (`~/.jig/cli.toml`):

```toml
[server]
base_url = "http://127.0.0.1:7117"

[user]
did = "did:jig:alice"
display_name = "alice"
default_channel = "#general"
```

## Commands

- `jig init` – create a config file if none exists.
- `jig send <message>` – publish a text block (optional `--channel`; flag-only,
  because the positional slot is the message body).
- `jig read [channel]` – list recent blocks (`--limit`, `--json`).
- `jig tail [channel]` – stream new blocks on a channel over the WebSocket
  subscribe path.
- `jig chat [channel]` – interactive TUI: scrolling history plus an input box.
- Piping: `echo "alert" | jig --channel '#alerts'`

`read`, `tail`, and `chat` accept the channel either positionally or as
`--channel <CHANNEL>`, and fall back to `[user] default_channel` when neither is
given. Supplying both forms at once is a usage error, not a silent pick.

## Installation

```bash
cargo install --path .
```

(Pre-built binaries and scripts will return once we stabilise the block workflow.)

## License

MIT. See [LICENSE](LICENSE).
