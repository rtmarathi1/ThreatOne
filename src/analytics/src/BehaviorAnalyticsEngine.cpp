#include "analytics/BehaviorAnalyticsEngine.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <set>

namespace ThreatOne::Analytics {

BehaviorAnalyticsEngine::BehaviorAnalyticsEngine()
    : logger_(Core::Logger::instance().getModuleLogger("BehaviorAnalyticsEngine"))
{
    logger_.info("BehaviorAnalyticsEngine initialized");
}

void BehaviorAnalyticsEngine::buildBaseline(const std::string& userId,
                                             const std::vector<UserEvent>& events) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (events.empty()) {
        logger_.warn("Cannot build baseline for '{}': no events provided", userId);
        return;
    }

    UserBaseline baseline;
    baseline.eventCount = events.size();

    // Calculate hour-of-day distribution
    double hourSum = 0.0;
    double hourSqSum = 0.0;
    std::set<std::string> accessPatterns;
    std::set<std::string> processes;

    for (const auto& event : events) {
        int hour = extractHour(event.timestamp);
        hourSum += hour;
        hourSqSum += static_cast<double>(hour) * hour;
        accessPatterns.insert(event.resource);
        if (!event.eventType.empty()) {
            processes.insert(event.eventType);
        }
    }

    double n = static_cast<double>(events.size());
    baseline.meanHour = hourSum / n;
    double hourVariance = (hourSqSum / n) - (baseline.meanHour * baseline.meanHour);
    baseline.hourStdDev = (hourVariance > 0.0) ? std::sqrt(hourVariance) : 1.0;
    // Store M2 for Welford's online algorithm (population variance * n)
    baseline.hourM2 = hourVariance * n;

    // Set normal hours based on mean +/- 1 stddev
    int startHour = std::max(0, static_cast<int>(baseline.meanHour - baseline.hourStdDev));
    int endHour = std::min(23, static_cast<int>(baseline.meanHour + baseline.hourStdDev));
    baseline.normalHours = {startHour, endHour};

    // Typical access patterns
    for (const auto& pattern : accessPatterns) {
        baseline.typicalAccessPatterns.push_back(pattern);
    }

    // Common processes/event types
    for (const auto& proc : processes) {
        baseline.commonProcesses.push_back(proc);
    }

    // Calculate average event rate (events per hour)
    if (events.size() >= 2) {
        auto earliest = events.front().timestamp;
        auto latest = events.back().timestamp;
        auto duration = std::chrono::duration_cast<std::chrono::hours>(latest - earliest);
        double hours = std::max(1.0, static_cast<double>(duration.count()));
        baseline.averageEventRate = n / hours;

        // Calculate event rate standard deviation using windowed approach
        // Simple approximation: use sqrt of rate as stddev (Poisson-like)
        baseline.eventRateStdDev = std::sqrt(baseline.averageEventRate);
    } else {
        baseline.averageEventRate = 1.0;
        baseline.eventRateStdDev = 1.0;
    }

    baselines_[userId] = baseline;
    logger_.info("Baseline built for user '{}': {} events, rate={:.2f}/hr",
                 userId, events.size(), baseline.averageEventRate);
}

DeviationResult BehaviorAnalyticsEngine::detectDeviation(const std::string& userId,
                                                          const UserEvent& currentEvent) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = baselines_.find(userId);
    if (it == baselines_.end()) {
        DeviationResult result;
        result.isDeviation = false;
        result.description = "No baseline available for user";
        return result;
    }

    // Check time-of-day deviation (without lock since we already hold it)
    const auto& baseline = it->second;
    int currentHour = extractHour(currentEvent.timestamp);
    double hourZScore = computeZScore(static_cast<double>(currentHour),
                                       baseline.meanHour, baseline.hourStdDev);

    if (std::abs(hourZScore) > 2.0) {
        DeviationResult result;
        result.isDeviation = true;
        result.deviationScore = std::abs(hourZScore) / 3.0; // Normalize to ~[0,1]
        result.baselineMetric = "time_of_day";
        result.currentValue = static_cast<double>(currentHour);
        result.description = "Activity outside normal hours (hour=" +
                            std::to_string(currentHour) + ", baseline mean=" +
                            std::to_string(static_cast<int>(baseline.meanHour)) + ")";
        return result;
    }

    // Check access pattern deviation
    bool knownPattern = false;
    for (const auto& pattern : baseline.typicalAccessPatterns) {
        if (pattern == currentEvent.resource) {
            knownPattern = true;
            break;
        }
    }

    if (!knownPattern && !currentEvent.resource.empty()) {
        DeviationResult result;
        result.isDeviation = true;
        result.deviationScore = 0.6;
        result.baselineMetric = "access_pattern";
        result.currentValue = 0.0;
        result.description = "Access to unusual resource: " + currentEvent.resource;
        return result;
    }

    // No deviation detected
    DeviationResult result;
    result.isDeviation = false;
    result.deviationScore = 0.0;
    result.baselineMetric = "none";
    result.description = "Activity within normal baseline";
    return result;
}

DeviationResult BehaviorAnalyticsEngine::analyzeTimeOfDay(
    const std::string& userId,
    std::chrono::system_clock::time_point timestamp) const {
    std::lock_guard<std::mutex> lock(mutex_);

    DeviationResult result;
    auto it = baselines_.find(userId);
    if (it == baselines_.end()) {
        result.isDeviation = false;
        result.description = "No baseline available for user";
        return result;
    }

    const auto& baseline = it->second;
    int currentHour = extractHour(timestamp);
    double zScore = computeZScore(static_cast<double>(currentHour),
                                   baseline.meanHour, baseline.hourStdDev);

    result.baselineMetric = "time_of_day";
    result.currentValue = static_cast<double>(currentHour);

    if (std::abs(zScore) > 2.0) {
        result.isDeviation = true;
        result.deviationScore = std::min(1.0, std::abs(zScore) / 3.0);
        result.description = "Unusual activity time: hour " + std::to_string(currentHour) +
                            " (normal range: " + std::to_string(baseline.normalHours.first) +
                            "-" + std::to_string(baseline.normalHours.second) + ")";
    } else {
        result.isDeviation = false;
        result.deviationScore = std::abs(zScore) / 3.0;
        result.description = "Activity time within normal range";
    }

    return result;
}

DeviationResult BehaviorAnalyticsEngine::analyzeAccessPattern(
    const std::string& userId,
    const std::string& resource) const {
    std::lock_guard<std::mutex> lock(mutex_);

    DeviationResult result;
    auto it = baselines_.find(userId);
    if (it == baselines_.end()) {
        result.isDeviation = false;
        result.description = "No baseline available for user";
        return result;
    }

    const auto& baseline = it->second;
    result.baselineMetric = "access_pattern";

    bool found = false;
    for (const auto& pattern : baseline.typicalAccessPatterns) {
        if (pattern == resource) {
            found = true;
            break;
        }
    }

    if (!found && !resource.empty()) {
        result.isDeviation = true;
        result.deviationScore = 0.7;
        result.currentValue = 0.0;
        result.description = "Access to unrecognized resource: " + resource;
    } else {
        result.isDeviation = false;
        result.deviationScore = 0.0;
        result.currentValue = 1.0;
        result.description = "Access pattern matches baseline";
    }

    return result;
}

UserBaseline BehaviorAnalyticsEngine::getBaseline(const std::string& userId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = baselines_.find(userId);
    if (it != baselines_.end()) {
        return it->second;
    }
    return UserBaseline{};
}

void BehaviorAnalyticsEngine::updateBaseline(const std::string& userId, const UserEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = baselines_.find(userId);
    if (it == baselines_.end()) {
        // Create a minimal baseline from this single event
        UserBaseline baseline;
        baseline.eventCount = 1;
        baseline.meanHour = static_cast<double>(extractHour(event.timestamp));
        baseline.hourStdDev = 3.0; // Default
        baseline.averageEventRate = 1.0;
        baseline.eventRateStdDev = 1.0;
        if (!event.resource.empty()) {
            baseline.typicalAccessPatterns.push_back(event.resource);
        }
        if (!event.eventType.empty()) {
            baseline.commonProcesses.push_back(event.eventType);
        }
        baselines_[userId] = baseline;
        return;
    }

    auto& baseline = it->second;
    baseline.eventCount++;

    // Welford's online algorithm for running mean and variance
    double n = static_cast<double>(baseline.eventCount);
    int currentHour = extractHour(event.timestamp);
    double delta = static_cast<double>(currentHour) - baseline.meanHour;
    baseline.meanHour += delta / n;
    double delta2 = static_cast<double>(currentHour) - baseline.meanHour;
    baseline.hourM2 += delta * delta2;

    if (n > 1) {
        // Derive stddev from M2: variance = M2 / (n - 1) (sample variance)
        double variance = baseline.hourM2 / (n - 1.0);
        baseline.hourStdDev = std::sqrt(std::max(0.0, variance));
    }

    // Update normal hours
    int startHour = std::max(0, static_cast<int>(baseline.meanHour - baseline.hourStdDev));
    int endHour = std::min(23, static_cast<int>(baseline.meanHour + baseline.hourStdDev));
    baseline.normalHours = {startHour, endHour};

    // Add new access pattern if not already tracked
    if (!event.resource.empty()) {
        bool found = false;
        for (const auto& p : baseline.typicalAccessPatterns) {
            if (p == event.resource) {
                found = true;
                break;
            }
        }
        if (!found) {
            baseline.typicalAccessPatterns.push_back(event.resource);
        }
    }
}

bool BehaviorAnalyticsEngine::hasBaseline(const std::string& userId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return baselines_.find(userId) != baselines_.end();
}

size_t BehaviorAnalyticsEngine::getUserCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return baselines_.size();
}

double BehaviorAnalyticsEngine::computeZScore(double value, double mean, double stdDev) const {
    if (stdDev < 1e-10) {
        return 0.0;
    }
    return (value - mean) / stdDev;
}

int BehaviorAnalyticsEngine::extractHour(std::chrono::system_clock::time_point tp) const {
    auto timeT = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    gmtime_r(&timeT, &tm);
    return tm.tm_hour;
}

} // namespace ThreatOne::Analytics
