#pragma once

#include <string>
#include <vector>
#include <unordered_map>

namespace ThreatOne::Telemetry {

struct TelemetryEvent {
    std::string name;
    std::string category;
    std::unordered_map<std::string, std::string> properties;
    std::string timestamp;
};

struct UsageStats {
    uint64_t totalScans = 0;
    uint64_t threatsDetected = 0;
    uint64_t uptime = 0;
    std::string lastActive;
};

class ITelemetryManager {
public:
    virtual ~ITelemetryManager() = default;

    virtual bool trackEvent(const TelemetryEvent& event) = 0;
    virtual bool trackError(const std::string& error, const std::string& context) = 0;
    virtual UsageStats getUsageStats() = 0;
    virtual void setEnabled(bool enabled) = 0;
    virtual bool isEnabled() = 0;
};

} // namespace ThreatOne::Telemetry
