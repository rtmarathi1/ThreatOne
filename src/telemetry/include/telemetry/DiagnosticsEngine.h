#pragma once

#include "telemetry/ITelemetryManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <cstdint>

namespace ThreatOne::Telemetry {

struct DiagnosticCheck {
    std::string id;
    std::string name;
    std::string category;
    HealthStatus status = HealthStatus::Unknown;
    std::string message;
    double responseTimeMs = 0.0;
    std::string lastRun;
};

struct SystemInfo {
    std::string osName;
    std::string osVersion;
    std::string hostname;
    uint64_t totalMemoryMB = 0;
    uint64_t availableMemoryMB = 0;
    uint32_t cpuCores = 0;
    double cpuUsage = 0.0;
    double diskUsage = 0.0;
    std::string appVersion;
};

struct DiagnosticReport {
    std::string id;
    std::string generatedAt;
    SystemInfo systemInfo;
    std::vector<DiagnosticCheck> checks;
    HealthStatus overallStatus = HealthStatus::Unknown;
    std::vector<std::string> issues;
    std::vector<std::string> recommendations;
};

class DiagnosticsEngine {
public:
    DiagnosticsEngine();
    ~DiagnosticsEngine() = default;

    // Register checks
    std::string registerCheck(const std::string& name, const std::string& category);
    bool unregisterCheck(const std::string& checkId);
    [[nodiscard]] std::vector<DiagnosticCheck> getRegisteredChecks() const;

    // Run diagnostics
    DiagnosticReport runDiagnostics();
    bool runSingleCheck(const std::string& checkId);
    [[nodiscard]] std::optional<DiagnosticCheck> getCheckResult(const std::string& checkId) const;

    // System info
    void setSystemInfo(const SystemInfo& info);
    [[nodiscard]] SystemInfo getSystemInfo() const;

    // Reports
    [[nodiscard]] std::vector<DiagnosticReport> getReports() const;
    [[nodiscard]] std::optional<DiagnosticReport> getLatestReport() const;

    // Health status
    [[nodiscard]] HealthStatus getOverallHealth() const;
    void updateCheckStatus(const std::string& checkId, HealthStatus status, const std::string& message);

    // Statistics
    [[nodiscard]] uint64_t getTotalDiagnosticsRun() const;
    [[nodiscard]] uint64_t getCheckCount() const;

private:
    std::string generateId(const std::string& prefix);
    std::string getCurrentTimestamp() const;
    HealthStatus computeOverallStatus(const std::vector<DiagnosticCheck>& checks) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, DiagnosticCheck> checks_;
    std::vector<DiagnosticReport> reports_;
    SystemInfo systemInfo_;
    uint64_t totalDiagnosticsRun_ = 0;
    int nextCheckId_ = 1;
    int nextReportId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Telemetry
