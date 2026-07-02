#include "monitor/HealthChecker.h"

#include <chrono>
#include <sstream>

namespace ThreatOne::Monitor {

HealthChecker::HealthChecker()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("HealthChecker")) {
    logger_.info("HealthChecker initialized");
}

std::string HealthChecker::generateCheckId() {
    return "HC-" + std::to_string(nextCheckId_++);
}

std::string HealthChecker::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::string HealthChecker::addHealthCheck(const HealthCheck& check) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (check.name.empty()) {
        return "";
    }

    std::string id = generateCheckId();
    HealthCheck newCheck = check;
    newCheck.id = id;
    healthChecks_[id] = newCheck;

    logger_.info("Added health check: {} ({})", check.name, id);
    return id;
}

bool HealthChecker::removeHealthCheck(const std::string& checkId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = healthChecks_.find(checkId);
    if (it == healthChecks_.end()) {
        return false;
    }
    healthChecks_.erase(it);
    return true;
}

bool HealthChecker::enableCheck(const std::string& checkId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = healthChecks_.find(checkId);
    if (it == healthChecks_.end()) {
        return false;
    }
    it->second.enabled = true;
    return true;
}

bool HealthChecker::disableCheck(const std::string& checkId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = healthChecks_.find(checkId);
    if (it == healthChecks_.end()) {
        return false;
    }
    it->second.enabled = false;
    return true;
}

std::vector<HealthCheck> HealthChecker::getHealthChecks() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<HealthCheck> result;
    result.reserve(healthChecks_.size());
    for (const auto& [id, check] : healthChecks_) {
        result.push_back(check);
    }
    return result;
}

HealthCheckResult HealthChecker::evaluateCheck(const HealthCheck& check) const {
    HealthCheckResult result;
    result.checkId = check.id;
    result.name = check.name;
    result.checkedAt = getCurrentTimestamp();

    // Simulate health check evaluation
    // In production, this would ping services, check ports, verify dependencies
    result.status = HealthStatus::Healthy;
    result.message = check.component + " is operating normally";
    result.latencyMs = 5;

    return result;
}

std::vector<HealthCheckResult> HealthChecker::runAllChecks() {
    std::lock_guard<std::mutex> lock(mutex_);

    lastResults_.clear();

    for (const auto& [id, check] : healthChecks_) {
        if (!check.enabled) continue;

        auto result = evaluateCheck(check);
        lastResults_.push_back(result);
        totalChecksRun_++;
    }

    logger_.info("Health checks completed: {} checks run", lastResults_.size());
    return lastResults_;
}

HealthCheckResult HealthChecker::runCheck(const std::string& checkId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = healthChecks_.find(checkId);
    if (it == healthChecks_.end()) {
        return {};
    }

    auto result = evaluateCheck(it->second);
    totalChecksRun_++;
    return result;
}

std::vector<HealthCheckResult> HealthChecker::getLastResults() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastResults_;
}

OverallHealth HealthChecker::getOverallHealth() const {
    std::lock_guard<std::mutex> lock(mutex_);

    OverallHealth overall;
    overall.totalChecks = lastResults_.size();

    for (const auto& result : lastResults_) {
        switch (result.status) {
            case HealthStatus::Healthy:
                overall.healthyCount++;
                break;
            case HealthStatus::Degraded:
                overall.degradedCount++;
                break;
            case HealthStatus::Unhealthy:
                overall.unhealthyCount++;
                break;
            case HealthStatus::Unknown:
                break;
        }
    }

    if (overall.unhealthyCount > 0) {
        overall.status = HealthStatus::Unhealthy;
    } else if (overall.degradedCount > 0) {
        overall.status = HealthStatus::Degraded;
    } else if (overall.healthyCount > 0) {
        overall.status = HealthStatus::Healthy;
    } else {
        overall.status = HealthStatus::Unknown;
    }

    return overall;
}

HealthStatus HealthChecker::getComponentHealth(const std::string& component) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& result : lastResults_) {
        auto it = healthChecks_.find(result.checkId);
        if (it != healthChecks_.end() && it->second.component == component) {
            return result.status;
        }
    }
    return HealthStatus::Unknown;
}

uint64_t HealthChecker::getTotalChecksRun() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalChecksRun_;
}

} // namespace ThreatOne::Monitor
