# Riverdance - Jig Protocol GUI Client

A lightweight, config-driven desktop and mobile messaging client for the Jig protocol, built with Rust and Dioxus.

## Overview

Riverdance is the official-ish GUI client for the Jig protocol, designed to provide a Slack/Discord/Teams-like experience while maintaining the core principles of being lightweight, fast, and heavily config-driven. The client supports full compatibility with jig-core and jig-client for seamless interoperability.

(Similar to Matrix or other protocols, there may be other clients driven by us or the community in the future, and that's fine. This is more of the reference implementation than the official / only one.)

### Key Design Principles

- **Lightweight**: Minimal memory footprint and fast startup times
- **Config-as-Code**: Extensively customizable through TOML configuration files. Similar to VSCode, all settings should be a) in TOML, b) control basically every aspect of the app, c) be indexed and searchable/modifiable directly via command-bar, d) hot-reload in-app whenever possible (i.e. restarts should be minimal). Users shouldn't need to find a UI pane to change something if they don't want to, and they should be able to change pretty much anything.
- **Modular Compatibility**: Users never _need_ the GUI - all functionality available via core/CLI. The GUI depends on core, but not the other way around, and they're independently-versioned.
- **Multi-Tenant**: Support for multiple organizations, tenants, and user profiles by default. Every new user has to be in a minimum of one account + tenant + org, even if all three are just for themselves.
- **Privacy-First**: E2E encryption, federation, and zero-trust architecture, respecting the security zones of jig protocol and making it easy to navigate / be aware of context switching between them.
- **Block-Based Messaging**: Notion/Airtable-style composable message blocks, with the GUI making those blocks easier to manipulate on the fly.

## Architecture

### Core Components

- **Frontend**: Dioxus-based cross-platform UI (desktop & mobile)
- **Backend Integration**: Direct integration with jig-core and jig-config
- **Configuration**: TOML-driven with live reload capabilities
- **Authentication**: Multi-tenant auth supporting client, server, and nameserver administration

### Dependencies

- **Dioxus**: Cross-platform UI framework
- **jig-core**: Core protocol implementation
- **jig-config**: Configuration management
- **jig-client**: Client library integration
- **jig-server**: Server library integration
- **jig-nameserver**: Nameserver library integration
- Authn, authz, and encryption: pulled from state-of-art OSS (never roll your own crypto)
- Minimal external dependencies otherwise where we can pull it off (but higher tolerance for dependencies _here_ versus other aspects of jig)

## Features

### MVP Requirements

#### Core Messaging

- Real-time messaging with WebSocket/gRPC support
- Block-based message composition (transparent to users)
- Threading support (Linear, Slack-style, Forum, Nested)
- Message editing, deletion, and reactions
- Draft management and send-later functionality

#### Multi-Tenant Support

- Organization/tenant/team switching
- Role-based access control (RBAC/ABAC)
- Profile isolation with no cross-contamination
- Server administration capabilities (where authorized)

#### Configuration Management

- Live TOML editing with syntax highlighting
- UI mode vs "Pro mode" raw config editing
- Context-aware settings (channel, user, org, global)
- Theme system with preset and custom themes
- Auto-save with selective restart requirements

#### User Experience

- Command bar for power users
- Collapsible navigation with sections
- Context menus and hover actions
- Keyboard shortcuts and accessibility
- Drag-and-drop organization

### Extended Features (Post-MVP)

#### Advanced Messaging

- File sharing and media handling
- Voice/video integration
- Rich text with Markdown/LaTeX support
- Code blocks with syntax highlighting
- Message forwarding and save-for-later

#### Federation & Privacy

- Server-to-server federation
- Multiple encryption modes (Plaintext, E2E, Homomorphic, Ring-Fenced)
- NORAD redaction protocol
- Audit logging and compliance

#### Enterprise Features

- HSM integration
- Advanced RBAC policies
- Compliance reporting
- Custom branding and themes

## Performance Goals

- **Startup Time**: < 3 seconds cold start
- **Memory Usage**: < 150MB baseline
- **Package Size**: < 50MB installed
- **Build Time**: < 2 minutes from source
- **Message Latency**: < 100ms local processing

Compare to reference implementations:

- Slack Desktop: ~500MB memory, ~200MB package
- Discord: ~300MB memory, ~150MB package
- Teams: ~400MB memory, ~300MB package

## Configuration

### Primary Config Files

#### `client.toml`

GUI-specific parameters including:

- Window management and layout
- Theme and appearance settings
- Keyboard shortcuts and behavior
- Local caching and performance
- Debug and development options

#### `jig-config.toml`

Protocol-level configuration:

- Server and nameserver endpoints
- Federation settings
- Encryption preferences
- Channel and user defaults
- Audit and logging levels

#### `account.toml` (User-specific)

Per-user settings for shared servers:

- Personal preferences
- Notification settings
- Custom shortcuts
- Private themes and layouts

### Configuration Hierarchy

1. **Global**: System-wide defaults
2. **Organization**: Org-level policies and branding
3. **Tenant**: Team/workspace settings
4. **User**: Personal preferences
5. **Session**: Temporary runtime settings

Settings cascade down the hierarchy with user settings taking precedence for personal preferences while respecting organizational policies.

## Development

### Prerequisites

- Rust 1.75+ with 2024 edition support
- Dioxus CLI for development and building
- jig-core development environment

### Quick Start

```bash
# Clone and build
git clone https://github.com/jig-protocol/jig-gui
cd jig-gui
cargo build --release

# Development mode
dx serve --hot-reload

# Desktop build
dx build --release --platform desktop

# Mobile build (iOS/Android)
dx build --release --platform mobile
```

### Project Structure

```
src/
├── main.rs              # Application entry point
├── app.rs               # Root app component
├── config/              # Configuration management
├── components/          # Reusable UI components
│   ├── navigation/      # Navigation and routing
│   ├── messaging/       # Message and thread components
│   ├── settings/        # Configuration UI
│   └── common/          # Shared components
├── views/               # Main application views
│   ├── chat.rs         # Chat interface
│   ├── dms.rs          # Direct messages
│   ├── threads.rs      # Thread management
│   ├── saved.rs        # Saved items
│   └── settings.rs     # Settings interface
├── services/            # Business logic
│   ├── auth.rs         # Authentication
│   ├── messaging.rs    # Message handling
│   └── config.rs       # Config management
└── utils/               # Utilities and helpers
```

### Testing

```bash
# Run all tests
cargo nextest run

# UI component tests
cargo nextest run --package riverdance-components

# Integration tests with jig-core
cargo nextest run --package riverdance-integration

# E2E tests
cargo nextest run --package riverdance-e2e
```

## Deployment

### Desktop Distribution

- **macOS**: DMG with code signing
- **Windows**: MSI installer with digital signature
- **Linux**: AppImage, .deb, and .rpm packages

### Mobile Distribution

- **iOS**: App Store distribution
- **Android**: Play Store and F-Droid

### Self-Hosting

Riverdance can be deployed alongside jig-core for integrated server management:

```bash
# Deploy with jig-core
curl -L https://jig.onl | sh
# GUI client automatically configured for local server
```

## Security

### Client Security

- No credential storage - delegates to jig-core
- Configuration encryption for sensitive settings
- Automatic security updates
- Sandboxed execution environment

### Network Security

- TLS 1.3 for all communications
- Certificate pinning for known servers
- Zero-trust federation model
- End-to-end message encryption

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for detailed technical specifications.

### Code Style

- Follow Rust 2024 edition conventions
- Use `rustfmt` and `clippy` for consistency
- Document all public APIs
- Write tests for new functionality

## License

AGPL-3.0 - See [LICENSE](LICENSE) for details.

## Support

- **Documentation**: https://docs.jig.onl/gui
- **Issues**: https://github.com/jig-protocol/jig-gui/issues
- **Discussions**: https://github.com/jig-protocol/jig-gui/discussions
- **Chat**: #riverdance on the Jig protocol network
