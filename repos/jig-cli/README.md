# jig-cli

Command-line interface for the Jig executable internet.

## Overview

`jig-cli` lets you publish and inspect Jig Blocks from a terminal. It talks to a running `jig-server` over the HTTP block API, building manifests and receipts with the same `jig-core` primitives used by the rest of the stack.

## Features

- **Block-native**: Sends canonical manifests with author DID and metadata.
- **HTTP transport**: Uses the `/blocks` and `/receipts` endpoints exposed by `jig-server`.
- **Pipeline friendly**: Works with stdin/stdout; no local SQLite dependency.
- **Configurable**: `~/.jig/config.toml` stores server URL, author DID, and default channel.

## Quick Start

```bash
# Ensure a jig-server is running (see repos/jig-server)

# Initialise config (~/.jig/config.toml)
jig init

# Send a block to the default channel
jig send "Hello, Jig!"

# Override channel and server on the fly
jig --server http://127.0.0.1:7117 send --channel #ops "Deploying now"

# Read the latest blocks
ojig read --limit 20

# Follow new blocks in real-time
jig tail --channel #ops
```

Example config (`~/.jig/config.toml`):

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
- `jig send <message>` – publish a text block (optional `--channel`).
- `jig read` – list recent blocks (filterable by `--channel`, `--limit`, `--json`).
- `jig tail` – poll the server for new blocks on a channel.
- Piping: `echo "alert" | jig --channel #alerts`

## Installation

```bash
cargo install --path .
```

(Pre-built binaries and scripts will return once we stabilise the block workflow.)

## License

MIT. See [LICENSE](LICENSE).
