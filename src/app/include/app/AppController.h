#pragma once

// ThreatOne App - AppController
// Central controller that ties all modules together and manages
// the lifecycle of all subsystem managers.

#include <memory>
#include <string>
#include <vector>

#include "core/Error.h"
#include "core/Logger.h"

namespace ThreatOne::App {

class AppController {
public:
    AppController();
    ~AppController();

    // Initialize all subsystem managers and register them with ServiceLocator
    [[nodiscard]] ThreatOne::Core::Result<void> initialize();

    // Shut down all subsystems in reverse order
    void shutdown();

    // Check if all subsystems are healthy
    [[nodiscard]] bool isHealthy() const;

    // Get the list of registered subsystem names
    [[nodiscard]] std::vector<std::string> getSubsystems() const;

    // Non-copyable, non-movable
    AppController(const AppController&) = delete;
    AppController& operator=(const AppController&) = delete;
    AppController(AppController&&) = delete;
    AppController& operator=(AppController&&) = delete;

private:
    ThreatOne::Core::Result<void> initSecurityEngine();
    ThreatOne::Core::Result<void> initAIEngine();
    ThreatOne::Core::Result<void> initScanEngine();
    ThreatOne::Core::Result<void> initMonitorEngine();
    ThreatOne::Core::Result<void> initFirewallManager();
    ThreatOne::Core::Result<void> initEDREngine();
    ThreatOne::Core::Result<void> initXDREngine();
    ThreatOne::Core::Result<void> initSIEMEngine();
    ThreatOne::Core::Result<void> initNetworkManager();
    ThreatOne::Core::Result<void> initCloudManager();
    ThreatOne::Core::Result<void> initReportEngine();
    ThreatOne::Core::Result<void> initAnalyticsEngine();
    ThreatOne::Core::Result<void> initLicenseManager();
    ThreatOne::Core::Result<void> initTelemetryManager();
    ThreatOne::Core::Result<void> initUpdateManager();
    ThreatOne::Core::Result<void> initIdentityManager();
    ThreatOne::Core::Result<void> initComplianceEngine();
    ThreatOne::Core::Result<void> initVulnerabilityScanner();
    ThreatOne::Core::Result<void> initSOCManager();
    ThreatOne::Core::Result<void> initHIDSEngine();
    ThreatOne::Core::Result<void> initSandboxEngine();
    ThreatOne::Core::Result<void> initPluginManager();

    ThreatOne::Core::ModuleLogger logger_;
    bool initialized_ = false;
    std::vector<std::string> subsystems_;
};

} // namespace ThreatOne::App
