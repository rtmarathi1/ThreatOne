#include "soc/SOCDashboardData.h"
#include <mutex>

#include <algorithm>
#include <numeric>

namespace ThreatOne::SOC {

SOCDashboardData::SOCDashboardData()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SOCDashboardData")) {
    logger_.info("SOCDashboardData initialized");
}

SOCMetrics SOCDashboardData::computeMetrics(const std::vector<CaseInfo>& cases,
                                            const std::vector<std::string>& activeAnalysts) const {
    SOCMetrics metrics;

    for (const auto& c : cases) {
        if (c.status == CaseStatus::Closed) {
            metrics.closedCases++;
        } else {
            metrics.openCases++;
        }
    }

    metrics.activeAnalysts = activeAnalysts.size();

    // Use tracked averages if available
    std::lock_guard<std::mutex> lock(mutex_);
    if (!detectionTimes_.empty()) {
        metrics.meanTimeToDetect = std::accumulate(detectionTimes_.begin(),
            detectionTimes_.end(), 0.0) / static_cast<double>(detectionTimes_.size());
    } else {
        metrics.meanTimeToDetect = 15.5;  // Default simulated value
    }

    if (!responseTimes_.empty()) {
        metrics.meanTimeToRespond = std::accumulate(responseTimes_.begin(),
            responseTimes_.end(), 0.0) / static_cast<double>(responseTimes_.size());
    } else {
        metrics.meanTimeToRespond = 45.0;  // Default simulated value
    }

    return metrics;
}

void SOCDashboardData::recordDetectionTime(double seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    detectionTimes_.push_back(seconds);
}

void SOCDashboardData::recordResponseTime(double seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    responseTimes_.push_back(seconds);
}

void SOCDashboardData::recordContainmentTime(double seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    containmentTimes_.push_back(seconds);
}

void SOCDashboardData::recordResolutionTime(double seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    resolutionTimes_.push_back(seconds);
}

SOCKPIs SOCDashboardData::getKPIs() const {
    std::lock_guard<std::mutex> lock(mutex_);

    SOCKPIs kpis;

    auto average = [](const std::vector<double>& v) -> double {
        if (v.empty()) return 0.0;
        return std::accumulate(v.begin(), v.end(), 0.0) / static_cast<double>(v.size());
    };

    kpis.meanTimeToDetect = average(detectionTimes_);
    kpis.meanTimeToRespond = average(responseTimes_);
    kpis.meanTimeToContain = average(containmentTimes_);
    kpis.meanTimeToResolve = average(resolutionTimes_);
    kpis.totalAlertsToday = totalAlerts_;
    kpis.falsePositiveRate = falsePositives_;

    if (totalAlerts_ > 0) {
        kpis.slaCompliance = 1.0 - (static_cast<double>(falsePositives_) /
                                     static_cast<double>(totalAlerts_));
    } else {
        kpis.slaCompliance = 1.0;
    }

    return kpis;
}

std::vector<AnalystWorkload> SOCDashboardData::computeWorkload(
    const std::vector<CaseInfo>& cases) const {

    std::map<std::string, AnalystWorkload> workloadMap;

    for (const auto& c : cases) {
        if (c.assignee.empty()) continue;

        auto& wl = workloadMap[c.assignee];
        wl.analystId = c.assignee;
        if (c.status == CaseStatus::Closed) {
            wl.closedCases++;
        } else {
            wl.openCases++;
        }
    }

    std::vector<AnalystWorkload> result;
    result.reserve(workloadMap.size());
    for (auto& [id, wl] : workloadMap) {
        result.push_back(wl);
    }
    return result;
}

void SOCDashboardData::recordAlert() {
    std::lock_guard<std::mutex> lock(mutex_);
    totalAlerts_++;
}

void SOCDashboardData::recordFalsePositive() {
    std::lock_guard<std::mutex> lock(mutex_);
    falsePositives_++;
}

size_t SOCDashboardData::getTotalAlerts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalAlerts_;
}

size_t SOCDashboardData::getFalsePositives() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return falsePositives_;
}

} // namespace ThreatOne::SOC
