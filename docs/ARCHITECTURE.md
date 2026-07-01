# ThreatOne Architecture

## System Overview

ThreatOne is designed as a modular, layered cybersecurity platform. Each layer has clear responsibilities and communicates through well-defined interfaces, enabling independent development, testing, and deployment of subsystems.

```
+===================================================================+
|                         PRESENTATION LAYER                         |
|  +-------------------------------------------------------------+  |
|  |  Qt 6 / QML UI                                              |  |
|  |  [Dashboard] [Alerts] [Network Map] [Compliance] [Reports]  |  |
|  |  [Theme Engine] [Navigation] [Notifications] [Charts]       |  |
|  +-------------------------------------------------------------+  |
+===================================================================+
|                        APPLICATION LAYER                           |
|  +-------------------------------------------------------------+  |
|  |  AppController - Orchestrates startup, lifecycle, shutdown   |  |
|  |  ServiceLocator - Dependency injection / service registry    |  |
|  |  EventBus - Decoupled pub/sub communication                 |  |
|  |  Config - Hierarchical JSON configuration with overrides    |  |
|  |  Logger - Module-scoped structured logging                  |  |
|  |  PluginLoader - Dynamic shared library plugin management    |  |
|  +-------------------------------------------------------------+  |
+===================================================================+
|                         DOMAIN LAYER                               |
|  +-------------------+  +-------------------+  +---------------+  |
|  | Security Engine   |  | Network Engine    |  | Compliance    |  |
|  | - Scanner         |  | - Monitor         |  | - Policy Eval |  |
|  | - HIDS            |  | - Firewall        |  | - Frameworks  |  |
|  | - EDR             |  | - IDS/IPS         |  | - Audit Trail |  |
|  | - XDR             |  | - Packet Capture  |  | - Reporting   |  |
|  +-------------------+  +-------------------+  +---------------+  |
|  +-------------------+  +-------------------+  +---------------+  |
|  | SIEM/SOC          |  | Identity          |  | AI/Analytics  |  |
|  | - Log Aggregation |  | - RBAC            |  | - ML Models   |  |
|  | - Correlation     |  | - SSO/SAML        |  | - Anomaly Det |  |
|  | - Incidents       |  | - MFA             |  | - Prediction  |  |
|  | - Playbooks       |  | - User Mgmt       |  | - Trending    |  |
|  +-------------------+  +-------------------+  +---------------+  |
+===================================================================+
|                       INFRASTRUCTURE LAYER                         |
|  +-------------------------------------------------------------+  |
|  |  Database - SQLite/PostgreSQL, pooling, migrations, ORM     |  |
|  |  Cloud - AWS/Azure/GCP integration, CSPM                    |  |
|  |  Telemetry - Usage metrics, crash reports, diagnostics      |  |
|  |  Updates - Auto-update, version management                  |  |
|  |  Licensing - License validation, feature gating             |  |
|  +-------------------------------------------------------------+  |
+===================================================================+
```

## Module Dependency Graph

```
                        app (entry point)
                         |
            +------------+------------+
            |            |            |
          core        database      plugin
            |            |
    +---+---+---+       |
    |   |   |   |       |
  Logger Config |    QueryBuilder
        |       |    Migration
     EventBus   |    ConnectionManager
        |       |    Models
  ServiceLocator|
        |       |
        +---+---+
            |
     All domain modules depend on core:
     security, network, scanner, monitor,
     firewall, hids, edr, xdr, siem, soc,
     vulnerability, compliance, identity,
     cloud, ai, analytics, reporting,
     licensing, telemetry, updates
```

## Core Engine

The core module provides the foundational services that all other modules depend on.

### Logger

- Built on spdlog (header-only, vendored)
- Module-scoped loggers with independent level control
- Console and file sinks with rotation
- Pattern format: `[timestamp] [module] [level] message`
- Thread-safe via mutex-protected access
- Levels: Trace, Debug, Info, Warn, Error, Critical, Off

### Config

- JSON-based hierarchical configuration (using nlohmann/json)
- Dot-notation key access: `config.getString("database.host")`
- Typed getters with default fallbacks
- Environment variable overrides: `THREATONE_DATABASE_HOST`
- Change notification callbacks
- Thread-safe with mutex protection
- File-based persistence with `loadFromFile()` / `saveToFile()`

### EventBus

- Thread-safe publish/subscribe with typed events
- Priority-based filtering (Low, Normal, High, Critical)
- Propagation control (stop propagation)
- Subscription IDs for targeted unsubscribe
- Supports async dispatch via worker thread
- Base Event class with ID, timestamp, data payload
- Concrete event types: SystemEvent, SecurityEvent, UIEvent, PluginEvent, DataEvent

### ServiceLocator

- Type-safe dependency injection container
- Singleton and transient (factory) lifetimes
- Thread-safe registration and resolution
- Interface-to-implementation mapping via `registerAs<I, Impl>()`
- Null return for missing services (no exceptions on `resolve()`)
- `resolveRequired()` throws for critical dependencies

### PluginLoader

- Dynamic shared library loading (.so / .dll / .dylib)
- Plugin lifecycle: load, initialize, shutdown, unload
- Plugin metadata discovery (name, version, dependencies)
- Hot-reload support placeholder
- Sandboxed execution environment

## Database Layer

### ConnectionManager

- Connection pooling for SQLite and PostgreSQL
- Configurable pool size, timeouts, idle management
- RAII ScopedConnection with automatic pool return
- Transaction RAII guard for commit/rollback safety
- Health check and ping mechanisms
- WAL mode and foreign key enforcement for SQLite

### Migration System

- Version-tracked schema migrations
- Ordered up/down execution
- `_migrations` table for applied migration tracking
- Transaction-wrapped execution (atomic per migration)
- Rollback support (single step, multiple, or all)
- Target version migration (forward or backward)

### QueryBuilder

- Fluent API for SQL construction
- Parameterized queries prevent SQL injection
- SelectBuilder: columns, where, join, groupBy, having, orderBy, limit, offset
- InsertBuilder: column/value pairs, bulk columns
- UpdateBuilder: set values with where conditions
- DeleteBuilder: targeted or full table deletion
- Support for NULL checks, BETWEEN, IN, subqueries, raw SQL

### Schema DSL

- Declarative table creation with column types
- Foreign key relationships
- Index creation
- Constraint definitions

### Models

- Base Model class with CRUD operations
- 11 domain-specific models:
  - User, Asset, Threat, Incident, Alert
  - Scan, Setting, License, FirewallRule, Policy, Vulnerability
- Automatic serialization to/from database rows

## Plugin System Architecture

```
Plugin Discovery
    |
    v
Plugin Loading (dlopen/LoadLibrary)
    |
    v
Plugin Metadata Query (IPlugin interface)
    |
    v
Dependency Resolution
    |
    v
Plugin Initialization (register services, subscribe events)
    |
    v
Plugin Active (responds to events, provides services)
    |
    v
Plugin Shutdown (cleanup, unregister)
    |
    v
Plugin Unload (dlclose)
```

Plugins interact with the application through:
- **ServiceLocator**: Register and consume services
- **EventBus**: Subscribe to and publish events
- **Config**: Read plugin-specific configuration sections

## Security Engine Pipeline

```
Input (file, process, network packet, log entry)
    |
    v
+-------------------+
| Pre-processing    |  Normalize, extract metadata
+-------------------+
    |
    v
+-------------------+
| Signature Engine  |  Pattern matching (YARA, ClamAV-style)
+-------------------+
    |
    v
+-------------------+
| Heuristic Engine  |  Behavioral rules, entropy analysis
+-------------------+
    |
    v
+-------------------+
| AI/ML Engine      |  Neural network classification
+-------------------+
    |
    v
+-------------------+
| Correlation       |  Cross-reference with threat intel
+-------------------+
    |
    v
+-------------------+
| Decision Engine   |  Risk scoring, verdict
+-------------------+
    |
    v
+-------------------+
| Response          |  Block, quarantine, alert, log
+-------------------+
```

## QML UI Layer

- Main window with sidebar navigation
- Dashboard with real-time security metrics
- Theme system (dark/light, customizable accent colors)
- Responsive layout adapting to window size
- Chart integration (Qt Charts / Qt Quick 3D)
- Notification system with toast messages
- Modal dialogs for confirmations and details

## Threading Model

- **Main Thread**: UI event loop (Qt event loop when GUI enabled)
- **Worker Threads**: Background operations (scanning, monitoring)
- **Database Pool**: Dedicated connections per thread
- **Event Bus Async**: Optional async event processing thread
- **Network I/O**: Asynchronous socket operations

Thread safety is enforced through:
- `std::shared_mutex` for read-heavy data (subscriber lists, service registry)
- `std::mutex` for write-heavy data (config, logger setup)
- Atomic variables for flags and counters
- RAII lock guards exclusively (no manual lock/unlock)

## Error Handling Strategy

ThreatOne uses a `Result<T, E>` type inspired by Rust for recoverable errors:

```cpp
Result<void, Error> result = config.loadFromFile("config.json");
if (result.isErr()) {
    logger.error("Failed: {}", result.error().message());
}
```

Key principles:
- No exceptions in library/module code
- `Result<T, Error>` for all operations that can fail
- Structured `Error` type with category, severity, context
- Exception types available for plugin boundary errors
- Categories: System, IO, Configuration, Plugin, Security, Database, Network, Validation

## Configuration System

Configuration follows a layered override model:

```
Priority (highest to lowest):
1. Command-line arguments
2. Environment variables (THREATONE_SECTION_KEY)
3. User config file (~/.config/threatone/config.json)
4. Application config file (./config.json)
5. Built-in defaults
```

Config keys use dot notation for nested access:
- `database.host` -> `{"database": {"host": "..."}}`
- `security.scan.maxFileSize` -> deeply nested JSON path

Change notifications allow modules to react to runtime config updates without polling.
