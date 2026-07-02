#pragma once

#include "soc/ISOCManager.h"
#include "soc/CaseManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <memory>

namespace ThreatOne::SOC {

struct AnalystWorkload {
    std::string analystId;
    size_t openCases = 0;
    size_t closedCases = 0;
    double avgResolutionTime = 0.0;
};

struct SOCKPIs {
    double meanTimeToDetect = 0.0;
    double meanTimeToRespond = 0.0;
    double meanTimeToContain = 0.0;
    double meanTimeToResolve = 0.0;
    size_t totalAlertsToday = 0;
    size_t falsePositiveRate = 0;
    double slaCompliance = 0.0;
};

class SOCDashboardData {
public:
    SOCDashboardData();
    ~SOCDashboardData() = default;

    // Metrics computation
    [[nodiscard]] SOCMetrics computeMetrics(const std::vector<CaseInfo>& cases,
                                            const std::vector<std::string>& activeAnalysts) const;

    // KPI tracking
    void recordDetectionTime(double seconds);
    void recordResponseTime(double seconds);
    void recordContainmentTime(double seconds);
    void recordResolutionTime(double seconds);

    [[nodiscard]] SOCKPIs getKPIs() const;

    // Analyst workload
    [[nodiscard]] std::vector<AnalystWorkload> computeWorkload(
        const std::vector<CaseInfo>& cases) const;

    // Alert tracking
    void recordAlert();
    void recordFalsePositive();
    [[nodiscard]] size_t getTotalAlerts() const;
    [[nodiscard]] size_t getFalsePositives() const;

private:
    mutable std::mutex mutex_;

    // Time tracking accumulators
    std::vector<double> detectionTimes_;
    std::vector<double> responseTimes_;
    std::vector<double> containmentTimes_;
    std::vector<double> resolutionTimes_;
    size_t totalAlerts_ = 0;
    size_t falsePositives_ = 0;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SOC
