#include "telemetry/TelemetryManager.h"

namespace ThreatOne::Telemetry {

TelemetryManager::TelemetryManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("TelemetryManager")) {
    logger_.info("TelemetryManager initialized (stub)");
}

bool TelemetryManager::trackEvent(const TelemetryEvent& event) {
    logger_.info("trackEvent called: {}", event.name);
    return true;
}

bool TelemetryManager::trackError(const std::string& error, const std::string& context) {
    logger_.info("trackError called: {} ({})", error, context);
    return true;
}

UsageStats TelemetryManager::getUsageStats() {
    logger_.info("getUsageStats called");
    return {0, 0, 0, ""};
}

void TelemetryManager::setEnabled(bool enabled) {
    logger_.info("setEnabled called: {}", enabled);
    enabled_ = enabled;
}

bool TelemetryManager::isEnabled() {
    return enabled_;
}

} // namespace ThreatOne::Telemetry
