#include "app/AppController.h"

#include "core/ServiceLocator.h"
#include "security/ISecurityEngine.h"
#include "security/SecurityEngine.h"
#include "ai/IAIEngine.h"
#include "ai/AIEngine.h"
#include "scanner/IScanEngine.h"
#include "scanner/ScanEngine.h"
#include "monitor/IMonitorEngine.h"
#include "monitor/MonitorEngine.h"
#include "firewall/IFirewallManager.h"
#include "firewall/FirewallManager.h"
#include "edr/IEDREngine.h"
#include "edr/EDREngine.h"
#include "xdr/IXDREngine.h"
#include "xdr/XDREngine.h"
#include "siem/ISIEMEngine.h"
#include "siem/SIEMEngine.h"
#include "network/INetworkManager.h"
#include "network/NetworkManager.h"
#include "cloud/ICloudManager.h"
#include "cloud/CloudManager.h"
#include "reporting/IReportEngine.h"
#include "reporting/ReportEngine.h"
#include "analytics/IAnalyticsEngine.h"
#include "analytics/AnalyticsEngine.h"
#include "licensing/ILicenseManager.h"
#include "licensing/LicenseManager.h"
#include "telemetry/ITelemetryManager.h"
#include "telemetry/TelemetryManager.h"
#include "updates/IUpdateManager.h"
#include "updates/UpdateManager.h"
#include "identity/IIdentityManager.h"
#include "identity/IdentityManager.h"
#include "compliance/IComplianceEngine.h"
#include "compliance/ComplianceEngine.h"
#include "vulnerability/IVulnerabilityScanner.h"
#include "vulnerability/VulnerabilityScanner.h"
#include "soc/ISOCManager.h"
#include "soc/SOCManager.h"
#include "hids/IHIDSEngine.h"
#include "hids/HIDSEngine.h"
#include "sandbox/ISandboxEngine.h"
#include "sandbox/SandboxEngine.h"
#include "plugin/IPluginManager.h"
#include "plugin/PluginManager.h"
#include <memory>
#include <string>
#include <vector>

namespace ThreatOne::App {

AppController::AppController()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("AppController")) {
}

AppController::~AppController() {
    if (initialized_) {
        shutdown();
    }
}

ThreatOne::Core::Result<void> AppController::initialize() {
    logger_.info("Initializing all subsystem managers...");

    auto tryInit = [this](auto initFn, const std::string& name) -> ThreatOne::Core::Result<void> {
        auto result = (this->*initFn)();
        if (result) {
            subsystems_.push_back(name);
            logger_.debug("  [OK] {}", name);
        } else {
            logger_.error("  [FAIL] {}: {}", name, result.error().message());
            return result;
        }
        return ThreatOne::Core::Result<void>::ok();
    };

    // Initialize all subsystems
    auto r = tryInit(&AppController::initSecurityEngine, "SecurityEngine"); if (!r) return r;
    r = tryInit(&AppController::initAIEngine, "AIEngine"); if (!r) return r;
    r = tryInit(&AppController::initScanEngine, "ScanEngine"); if (!r) return r;
    r = tryInit(&AppController::initMonitorEngine, "MonitorEngine"); if (!r) return r;
    r = tryInit(&AppController::initFirewallManager, "FirewallManager"); if (!r) return r;
    r = tryInit(&AppController::initEDREngine, "EDREngine"); if (!r) return r;
    r = tryInit(&AppController::initXDREngine, "XDREngine"); if (!r) return r;
    r = tryInit(&AppController::initSIEMEngine, "SIEMEngine"); if (!r) return r;
    r = tryInit(&AppController::initNetworkManager, "NetworkManager"); if (!r) return r;
    r = tryInit(&AppController::initCloudManager, "CloudManager"); if (!r) return r;
    r = tryInit(&AppController::initReportEngine, "ReportEngine"); if (!r) return r;
    r = tryInit(&AppController::initAnalyticsEngine, "AnalyticsEngine"); if (!r) return r;
    r = tryInit(&AppController::initLicenseManager, "LicenseManager"); if (!r) return r;
    r = tryInit(&AppController::initTelemetryManager, "TelemetryManager"); if (!r) return r;
    r = tryInit(&AppController::initUpdateManager, "UpdateManager"); if (!r) return r;
    r = tryInit(&AppController::initIdentityManager, "IdentityManager"); if (!r) return r;
    r = tryInit(&AppController::initComplianceEngine, "ComplianceEngine"); if (!r) return r;
    r = tryInit(&AppController::initVulnerabilityScanner, "VulnerabilityScanner"); if (!r) return r;
    r = tryInit(&AppController::initSOCManager, "SOCManager"); if (!r) return r;
    r = tryInit(&AppController::initHIDSEngine, "HIDSEngine"); if (!r) return r;
    r = tryInit(&AppController::initSandboxEngine, "SandboxEngine"); if (!r) return r;
    r = tryInit(&AppController::initPluginManager, "PluginManager"); if (!r) return r;

    initialized_ = true;
    logger_.info("All {} subsystems initialized successfully", subsystems_.size());
    return ThreatOne::Core::Result<void>::ok();
}

void AppController::shutdown() {
    if (!initialized_) return;
    logger_.info("Shutting down subsystems...");
    // Subsystems are managed via shared_ptr in ServiceLocator; clearing will release them
    initialized_ = false;
    logger_.info("All subsystems shut down");
}

bool AppController::isHealthy() const {
    return initialized_;
}

std::vector<std::string> AppController::getSubsystems() const {
    return subsystems_;
}

// Individual subsystem initialization methods

ThreatOne::Core::Result<void> AppController::initSecurityEngine() {
    auto engine = std::make_shared<ThreatOne::Security::SecurityEngine>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Security::ISecurityEngine>(engine);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initAIEngine() {
    auto engine = std::make_shared<ThreatOne::AI::AIEngine>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::AI::IAIEngine>(engine);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initScanEngine() {
    auto engine = std::make_shared<ThreatOne::Scanner::ScanEngine>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Scanner::IScanEngine>(engine);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initMonitorEngine() {
    auto engine = std::make_shared<ThreatOne::Monitor::MonitorEngine>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Monitor::IMonitorEngine>(engine);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initFirewallManager() {
    auto mgr = std::make_shared<ThreatOne::Firewall::FirewallManager>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Firewall::IFirewallManager>(mgr);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initEDREngine() {
    auto engine = std::make_shared<ThreatOne::EDR::EDREngine>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::EDR::IEDREngine>(engine);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initXDREngine() {
    auto engine = std::make_shared<ThreatOne::XDR::XDREngine>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::XDR::IXDREngine>(engine);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initSIEMEngine() {
    auto engine = std::make_shared<ThreatOne::SIEM::SIEMEngine>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::SIEM::ISIEMEngine>(engine);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initNetworkManager() {
    auto mgr = std::make_shared<ThreatOne::Network::NetworkManager>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Network::INetworkManager>(mgr);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initCloudManager() {
    auto mgr = std::make_shared<ThreatOne::Cloud::CloudManager>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Cloud::ICloudManager>(mgr);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initReportEngine() {
    auto engine = std::make_shared<ThreatOne::Reporting::ReportEngine>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Reporting::IReportEngine>(engine);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initAnalyticsEngine() {
    auto engine = std::make_shared<ThreatOne::Analytics::AnalyticsEngine>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Analytics::IAnalyticsEngine>(engine);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initLicenseManager() {
    auto mgr = std::make_shared<ThreatOne::Licensing::LicenseManager>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Licensing::ILicenseManager>(mgr);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initTelemetryManager() {
    auto mgr = std::make_shared<ThreatOne::Telemetry::TelemetryManager>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Telemetry::ITelemetryManager>(mgr);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initUpdateManager() {
    auto mgr = std::make_shared<ThreatOne::Updates::UpdateManager>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Updates::IUpdateManager>(mgr);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initIdentityManager() {
    auto mgr = std::make_shared<ThreatOne::Identity::IdentityManager>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Identity::IIdentityManager>(mgr);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initComplianceEngine() {
    auto engine = std::make_shared<ThreatOne::Compliance::ComplianceEngine>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Compliance::IComplianceEngine>(engine);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initVulnerabilityScanner() {
    auto scanner = std::make_shared<ThreatOne::Vulnerability::VulnerabilityScanner>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Vulnerability::IVulnerabilityScanner>(scanner);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initSOCManager() {
    auto mgr = std::make_shared<ThreatOne::SOC::SOCManager>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::SOC::ISOCManager>(mgr);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initHIDSEngine() {
    auto engine = std::make_shared<ThreatOne::HIDS::HIDSEngine>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::HIDS::IHIDSEngine>(engine);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initSandboxEngine() {
    auto engine = std::make_shared<ThreatOne::Sandbox::SandboxEngine>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Sandbox::ISandboxEngine>(engine);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> AppController::initPluginManager() {
    auto mgr = std::make_shared<ThreatOne::Plugin::PluginManager>();
    ThreatOne::Core::ServiceLocator::instance().registerAs<ThreatOne::Plugin::IPluginManager>(mgr);
    return ThreatOne::Core::Result<void>::ok();
}

} // namespace ThreatOne::App
