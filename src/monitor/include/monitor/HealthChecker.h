#pragma once

#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace ThreatOne::Monitor {

enum class HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown
};

struct HealthCheck {
    std::string id;
    std::string name;
    std::string component;
    std::string description;
    uint64_t intervalSeconds = 60;
    uint64_t timeoutSeconds = 10;
    bool enabled = true;
};

struct HealthCheckResult {
    std::string checkId;
    std::string name;
    HealthStatus status = HealthStatus::Unknown;
    std::string message;
    uint64_t latencyMs = 0;
    std::string checkedAt;
};

struct OverallHealth {
    HealthStatus status = HealthStatus::Unknown;
    uint64_t totalChecks = 0;
    uint64_t healthyCount = 0;
    uint64_t degradedCount = 0;
    uint64_t unhealthyCount = 0;
    std::string lastCheckTime;
};

class HealthChecker {
public:
    HealthChecker();
    ~HealthChecker() = default;

    // Health check management
    std::string addHealthCheck(const HealthCheck& check);
    bool removeHealthCheck(const std::string& checkId);
    bool enableCheck(const std::string& checkId);
    bool disableCheck(const std::string& checkId);
    [[nodiscard]] std::vector<HealthCheck> getHealthChecks() const;

    // Running checks
    std::vector<HealthCheckResult> runAllChecks();
    HealthCheckResult runCheck(const std::string& checkId);
    [[nodiscard]] std::vector<HealthCheckResult> getLastResults() const;

    // Overall health
    [[nodiscard]] OverallHealth getOverallHealth() const;
    [[nodiscard]] HealthStatus getComponentHealth(const std::string& component) const;

    // Stats
    [[nodiscard]] uint64_t getTotalChecksRun() const;

private:
    std::string generateCheckId();
    std::string getCurrentTimestamp() const;
    HealthCheckResult evaluateCheck(const HealthCheck& check) const;

    mutable std::mutex mutex_;
    std::map<std::string, HealthCheck> healthChecks_;
    std::vector<HealthCheckResult> lastResults_;
    uint64_t totalChecksRun_ = 0;

    int nextCheckId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Monitor
