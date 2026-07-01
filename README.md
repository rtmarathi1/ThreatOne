# ThreatOne Enterprise Cybersecurity Platform

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![C++ Standard](https://img.shields.io/badge/C%2B%2B-20-blue)]()
[![License](https://img.shields.io/badge/license-proprietary-red)]()
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)]()

A modular, enterprise-grade cybersecurity platform built with C++20 and Qt 6. ThreatOne provides comprehensive threat detection, incident response, compliance monitoring, and security operations capabilities in a unified desktop application.

## Features

- **Real-time Threat Detection** - Multi-engine scanning with signature, heuristic, and AI-based detection
- **Endpoint Detection & Response (EDR)** - Behavioral monitoring and automated response
- **Extended Detection & Response (XDR)** - Cross-domain threat correlation
- **SIEM Integration** - Security Information and Event Management with log aggregation
- **Security Operations Center (SOC)** - Unified incident management and workflow
- **Network Monitoring** - Deep packet inspection, traffic analysis, IDS/IPS
- **Host-based IDS** - File integrity, process monitoring, registry watch
- **Firewall Management** - Rule-based traffic control with policy enforcement
- **Vulnerability Assessment** - Continuous scanning with CVE database integration
- **Compliance Engine** - Automated checks against CIS, NIST, PCI-DSS, HIPAA, ISO 27001
- **Identity & Access Management** - RBAC, SSO, MFA integration
- **Cloud Security** - Multi-cloud posture management (AWS, Azure, GCP)
- **AI-powered Analytics** - Anomaly detection and predictive threat intelligence
- **Plugin Architecture** - Extensible with custom security modules
- **Reporting Engine** - Automated compliance and incident reports

## Architecture Overview

```
+------------------------------------------------------------------+
|                        Qt 6 / QML UI Layer                        |
|   [Dashboard] [Threats] [Network] [Compliance] [Reports] [SOC]   |
+------------------------------------------------------------------+
|                         Application Core                          |
|   [EventBus] [ServiceLocator] [Config] [Logger] [PluginLoader]   |
+------------------------------------------------------------------+
|  Scanner  | Monitor | Firewall | SIEM | EDR | XDR | Compliance   |
|  Security | Network | Identity | AI   | SOC | Cloud | Analytics  |
+------------------------------------------------------------------+
|                        Database Layer                             |
|   [ConnectionManager] [Migration] [QueryBuilder] [Models]        |
+------------------------------------------------------------------+
|              Platform / OS Abstraction Layer                      |
+------------------------------------------------------------------+
```

## Build Instructions

### Prerequisites

- **CMake** 3.22 or later
- **C++20 compiler**: GCC 11+, Clang 15+, or MSVC 2022+
- **Qt 6.8+** (optional, for GUI build)
- **SQLite 3** (vendored as header-only)

### Build Without Qt (Core Engine Only)

```bash
cmake -B build -DCMAKE_CXX_STANDARD=20 -DENABLE_QT=OFF
cmake --build build
```

### Build With Qt (Full Application)

```bash
cmake -B build -DCMAKE_CXX_STANDARD=20 -DENABLE_QT=ON
cmake --build build
```

### Run Tests

```bash
cd build && ctest --output-on-failure
```

Or run the test binary directly for detailed output:

```bash
./build/tests/threatone_tests
```

### Build Options

| Option             | Default | Description                          |
|--------------------|---------|--------------------------------------|
| `ENABLE_QT`       | OFF     | Build with Qt 6 GUI support          |
| `ENABLE_TESTING`  | ON      | Build and register unit tests        |
| `ENABLE_SANITIZERS`| OFF    | Enable ASan/UBSan for debugging      |

## Module Overview

| Module         | Description                                              |
|----------------|----------------------------------------------------------|
| `core`         | Application lifecycle, logging, config, event bus        |
| `database`     | Connection pooling, migrations, query builder, ORM       |
| `network`      | Network monitoring, packet analysis, connection tracking |
| `security`     | Security engine, threat signatures, detection rules      |
| `scanner`      | File/process scanning, signature matching                |
| `monitor`      | System monitoring, resource tracking, alerts             |
| `firewall`     | Packet filtering, rule management, zone policies         |
| `hids`         | Host intrusion detection, file integrity                 |
| `edr`          | Endpoint detection & response, behavioral analysis       |
| `xdr`          | Extended detection, cross-domain correlation             |
| `siem`         | Log aggregation, event correlation, alerting             |
| `soc`          | SOC operations, incident workflow, playbooks             |
| `vulnerability`| Vulnerability scanning, CVE tracking, remediation        |
| `compliance`   | Policy evaluation, framework checks, audit reports       |
| `identity`     | User management, RBAC, authentication                    |
| `cloud`        | Cloud provider integration, CSPM                         |
| `ai`           | ML models, anomaly detection, threat prediction          |
| `analytics`    | Data analysis, trending, dashboards                      |
| `reporting`    | Report generation, templates, scheduling                 |
| `licensing`    | License validation, feature gating                       |
| `telemetry`    | Usage metrics, crash reporting, diagnostics              |
| `updates`      | Auto-update, version checking, patch management          |
| `plugin`       | Plugin SDK, loader, lifecycle management                 |
| `app`          | Application entry point, controller, startup             |
| `utils`        | Shared utilities, string ops, crypto helpers             |

## Plugin Development

ThreatOne supports a plugin architecture for extending functionality. Plugins implement the `PluginInterface`:

```cpp
#include <core/PluginInterface.h>

class MyPlugin : public ThreatOne::Core::IPlugin {
public:
    std::string name() const override { return "MyPlugin"; }
    std::string version() const override { return "1.0.0"; }
    Result<void> initialize() override { /* setup */ return ok(); }
    Result<void> shutdown() override { /* cleanup */ return ok(); }
};
```

Plugins are loaded at runtime from shared libraries and can register services, subscribe to events, and extend the UI.

## Development Setup

1. Clone the repository
2. Ensure CMake 3.22+ and a C++20 compiler are installed
3. Configure and build:
   ```bash
   cmake -B build -DENABLE_QT=OFF
   cmake --build build
   ```
4. Run tests to verify:
   ```bash
   cd build && ctest --output-on-failure
   ```

## Coding Standards

- C++20 with modern idioms (concepts, ranges, coroutines where appropriate)
- RAII for resource management
- `Result<T, E>` for error handling (no exceptions in library code)
- Thread-safe by default (shared_mutex for read-heavy, mutex for write-heavy)
- Each module has its own CMakeLists.txt with public/private include paths
- Header-only third-party dependencies vendored in `third_party/`

## Contributing

Contributions are welcome. Please follow the existing code style and ensure all tests pass before submitting changes. See `docs/ARCHITECTURE.md` for detailed design documentation.

## License

Proprietary. All rights reserved.
