#pragma once

#include "analytics/IAnalyticsEngine.h"
#include "core/Logger.h"

namespace ThreatOne::Analytics {

class AnalyticsEngine : public IAnalyticsEngine {
public:
    AnalyticsEngine();
    ~AnalyticsEngine() override = default;

    std::vector<AnalyticsMetric> getMetrics() override;
    std::vector<TrendData> getTrends(const std::string& period) override;
    std::vector<ThreatSummary> getTopThreats(int limit) override;
    double getRiskScore() override;
    SecurityPosture getSecurityPosture() override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Analytics
