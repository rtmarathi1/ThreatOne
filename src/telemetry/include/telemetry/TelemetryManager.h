#pragma once

#include "telemetry/ITelemetryManager.h"
#include "core/Logger.h"

namespace ThreatOne::Telemetry {

class TelemetryManager : public ITelemetryManager {
public:
    TelemetryManager();
    ~TelemetryManager() override = default;

    bool trackEvent(const TelemetryEvent& event) override;
    bool trackError(const std::string& error, const std::string& context) override;
    UsageStats getUsageStats() override;
    void setEnabled(bool enabled) override;
    bool isEnabled() override;

private:
    ThreatOne::Core::ModuleLogger logger_;
    bool enabled_ = true;
};

} // namespace ThreatOne::Telemetry
