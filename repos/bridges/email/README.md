# Jig Email Bridge

Bidirectional email gateway for the Jig protocol.

## Overview

This bridge allows Jig messages to be sent and received via standard email protocols (SMTP/IMAP), enabling communication between Jig users and email users.

## Features

- SMTP server for receiving emails
- SMTP client for sending emails  
- Email to JigMessage conversion
- Thread preservation
- HTML/plain text formatting

## Building

```bash
cargo build --release
```

## Quickstart: Send a Hello World email (Resend — no SMTP server)

1. Create a config file (copy the example):
   ```bash
   cp email-bridge.example.toml email-bridge.toml
   # set outbound_transport = "resend"
   # set resend_client.from_address = "noreply@yourdomain.com"
   ```
2. Provide API key via environment (don’t put secrets in files):
   ```bash
   export RESEND_API_KEY=...   # or use your preferred secret manager to set this
   ```
3. Send a message as an email:
   ```bash
   ./target/release/jig-bridge-email \
     --config email-bridge.toml \
     send-email --to you@example.com \
     --subject "Hello from Jig" \
     --body "This is a test."
   ```

## Alternative: SMTP relay (if available)

- Switch outbound_transport = "smtp" and configure [smtp_client] in email-bridge.toml.

## Running as a service (queue worker + inbound stub)

```bash
./target/release/jig-bridge-email --config email-bridge.toml
```

## Queue and worker usage

- Enqueue an email to be sent by the background worker:
  ```bash
  ./target/release/jig-bridge-email \
    --config email-bridge.toml \
    --database ~/.jig/email.db \
    enqueue-email --to you@example.com \
    --subject "Queued hello" \
    --body "Message body"
  ```
- Start the worker (as above). It will send pending items every few seconds.

## Configuration

- See `email-bridge.toml` for runtime options.
- Use `email-bridge.example.toml` as a starting point.
- Toggles:
  - formatting.add_signature = true|false
  - formatting.add_x_jig_header = true|false
  - formatting.add_thread_headers = true|false

## License

MIT
