# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

### Executable Internet Reminder (2025-10-24)
- Anchor your work to `executable-internet-master-plan/PLAN_STRUCTURE.md` and the new repo-specific plans (`implementation/repos/`).
- Treat Wasm-backed Jig Blocks, Rust core crates, and (optional) Elixir supervision layers as the only sanctioned runtime stack.
- Prioritize E2EE, adaptive useful work governance, and potato-friendly deployments; avoid reintroducing Docker-specific dependencies unless wrapping Wasm.
- When this document conflicts with the new plan, defer to the plan and update stale sections as you touch them.

## Project Overview

`jig-protocol` (formerly `gigue messenger-rs`) is a privacy-first, block-based AI-native messaging protocol built in Rust. It's designed to modernize IRC with AI-native features, while maintaining the core values of IRC (anonymous-by-default, federated, scriptable, minimal) and extending them into modern enterprise platform capabilities (tiered org/workspace/team structures, key management, role-based access control, audit logging, rich text / markdown / HTML / LaTeX / etc. support, audio + video + documents + files + etc. support, etc.) A core KPI is one-line self-deploy on any domain or linux machine (e.g. `curl -L https://jig.onl | sh`) in ~60sec setup (therefore clever one-shot defaults) with 10,000 msg/second capacity on any given 'potato' (e.g. $5/month VPS or Raspberry Pi).

FYI: `gigue` is a multiplayer AI-native IDE for non-technical work (emails, documents, tasks) that treats natural language artifacts as executable code with version control, transformations, and collaboration features, built by the company of the same name that also builds + sponsors `jig`. `gigue`is closed-source,`jig` is open-source, and we maintain strict boundaries between the two to prevent any accidental or perception of code reuse, rug-pulling, or other anti-competitive practices. `gigue` will point to `jig` in its dependencies; `jig` will not point to `gigue` in its dependencies (DAG relationships).

## 🚨 ROE to ensure successful integration with multiple teams / complex packages

- Build tests early and often, ideally right before implementing each file. List objectives, then edge and corner cases, then code tests, then code implementation.
- Keep code files small and focused - 100-250 LOC per file (JSDocs/comments don't count).
- Comments are good - code should be self-documenting; comments should explain why, not what.
- TOML config is the source of truth, JSON/YAML are explicitly testing/compatibility modes only.
- Balance DRY, SOC, LOB - avoid code duplication, separate concerns, avoid circular dependencies, keep common behaviors together.
- Maintain a working build at all times - run `cargo nextest run` and `cargo build` (in crate) before each commit.
- Document all interfaces and contracts - use expressive names and clear descriptions, avoid 'any' typing, take type-guard and validator complaints seriously
- Preserve DAG relationships (dependencies cannot call each other) and document data flow up to prototype-ibe at each addition
- Core crate should use absolute minimum dependencies (except for encryption, **do not roll your own**). Key KPI is self-deploy via curl | sh > SQLite in ~60sec

## Development Commands

-- Works for now on original-crate, but you'll change this once you scaffold the correct jig-protocol repo crates structure

### Building

```bash
# Build with alpha features (minimal feature set for MVP)
cd original-crate
cargo build --features alpha

# Build with all features
cargo build --all-features

# Build for production
cargo build --release --features alpha
```

### Testing

```bash
# Run all tests
cargo nextest run

# Run specific test module
cargo nextest run artifacts::
cargo nextest run encryption::
cargo nextest run storage::

# Run integration tests
cargo nextest run integration_mvp
cargo nextest run unified_artifacts_test
```

### Running Examples

```bash
# Basic messaging demo
cargo run --example basic_messaging

# Encryption demo
cargo run --example encryption_demo

# Channel lifecycle demo
cargo run --example channel_lifecycle

# Feature-gated examples
cargo run --example norad_demo --features norad-messenger
cargo run --example federation_demo --features federation
```

### Docker Operations

```bash
# Build and start all services
make build
make up

# Run database migrations
make migrate

# View logs
make logs

# Stop services
make down

# Run tests in Docker
make test
```

### Database Setup

```bash
# PostgreSQL (alpha default)
export DATABASE_URL="postgres://localhost/messenger_alpha"

# Run migrations
docker-compose -f docker-compose.alpha.yml run --rm migrate
```

## Architecture Overview

### Core Module Structure

The codebase follows a modular architecture with clear separation of concerns:

- **`src/core/`** - Core messaging service orchestration and central messaging logic
- **`src/artifacts/`** - Artifact-Block content system for composable messages (text, code, media blocks)
- **`src/encryption/`** - Privacy-controlled encryption with multiple modes (Plaintext, E2E, Homomorphic, Ring-Fenced)
- **`src/storage/`** - Multi-database abstraction layer (PostgreSQL for alpha, ScyllaDB and Redis for production)
- **`src/lifecycle/`** - Channel lifecycle management with ceremony-based initialization
- **`src/proof_of_life/`** - Human presence verification protocol
- **`src/norad/`** - Zero-trust message redaction protocol (feature-gated)
- **`src/federation/`** - Server-to-server communication protocol (feature-gated)
- **`src/sharding/`** - Global-scale data distribution (feature-gated)
- **`src/growth/`** - User acquisition and viral mechanics

### Key Architectural Decisions

1. **Multi-Database Architecture**: ScyllaDB for messages, PostgreSQL for metadata, Redis for caching
2. **Feature Flags**: Alpha release uses minimal features, production features are gated
3. **Artifact-Block System**: Messages are composable blocks (text, code, media) with transformations
4. **Threading Strategies**: Multiple threading models (Linear, Slack-style, Forum, Nested)
5. **Encryption Modes**: User-controlled privacy with four distinct encryption modes

### Service Initialization Flow

1. `MessengerService::new()` - Main entry point in `src/core/service.rs`
2. Initializes storage backends based on feature flags
3. Sets up encryption service with configured mode
4. Initializes channel lifecycle manager
5. Starts WebSocket server for real-time communication

### Message Processing Pipeline

1. Message received via WebSocket/HTTP
2. Authentication and authorization checks
3. Human signature validation (if enabled)
4. Encryption/decryption based on mode
5. Block transformation pipeline
6. Storage in appropriate backend
7. Real-time delivery to connected clients

## Feature Flags

- **`alpha`** - Minimal feature set for MVP (PostgreSQL only)
- **`beta-features`** - Advanced features for beta release
- **`norad-messenger`** - NORAD redaction protocol
- **`federation`** - Server-to-server federation
- **`sharding`** - Multi-dimensional sharding
- **`advanced-encryption`** - Homomorphic and Ring-Fenced modes
- **`enterprise`** - HSM support and full database backends

## Configuration

Configuration is managed through:

- `config/default.toml` - Default configuration
- Environment variables override config file
- `MessengerConfig` struct in `src/config.rs`

Key configuration areas:

- Database connections (PostgreSQL, ScyllaDB, Redis)
- Encryption defaults and key management
- WebSocket server settings
- Federation protocol settings
- Audit and logging levels
