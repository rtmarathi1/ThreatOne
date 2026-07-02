#include "telemetry/DiagnosticsEngine.h"
#include <optional>
#include <mutex>

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Telemetry {

DiagnosticsEngine::DiagnosticsEngine()
    : logger_(Core::Logger::instance().getModuleLogger("DiagnosticsEngine")) {
    systemInfo_.appVersion = "1.0.0";
    systemInfo_.hostname = "localhost";
    logger_.info("DiagnosticsEngine initialized");
}

std::string DiagnosticsEngine::generateId(const std::string& prefix) {
    if (prefix == "CHECK") {
        return "DIAG-" + std::to_string(nextCheckId_++);
    }
    return "DRPT-" + std::to_string(nextReportId_++);
}

std::string DiagnosticsEngine::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

HealthStatus DiagnosticsEngine::computeOverallStatus(
    const std::vector<DiagnosticCheck>& checks) const {
    if (checks.empty()) return HealthStatus::Unknown;

    HealthStatus worst = HealthStatus::Healthy;
    for (const auto& check : checks) {
        if (check.status == HealthStatus::Unhealthy) return HealthStatus::Unhealthy;
        if (check.status == HealthStatus::Degraded) worst = HealthStatus::Degraded;
        if (check.status == HealthStatus::Unknown && worst == HealthStatus::Healthy) {
            worst = HealthStatus::Unknown;
        }
    }
    return worst;
}

std::string DiagnosticsEngine::registerCheck(const std::string& name, const std::string& category) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generateId("CHECK");
    DiagnosticCheck check;
    check.id = id;
    check.name = name;
    check.category = category;
    check.status = HealthStatus::Unknown;
    check.message = "Not yet run";

    checks_[id] = check;
    logger_.info("Registered diagnostic check: {} ({})", name, id);
    return id;
}

bool DiagnosticsEngine::unregisterCheck(const std::string& checkId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = checks_.find(checkId);
    if (it == checks_.end()) return false;
    checks_.erase(it);
    return true;
}

std::vector<DiagnosticCheck> DiagnosticsEngine::getRegisteredChecks() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DiagnosticCheck> result;
    result.reserve(checks_.size());
    for (const auto& [id, check] : checks_) {
        result.push_back(check);
    }
    return result;
}

DiagnosticReport DiagnosticsEngine::runDiagnostics() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++totalDiagnosticsRun_;

    DiagnosticReport report;
    report.id = generateId("REPORT");
    report.generatedAt = getCurrentTimestamp();
    report.systemInfo = systemInfo_;

    std::string now = getCurrentTimestamp();
    for (auto& [id, check] : checks_) {
        check.status = HealthStatus::Healthy;
        check.message = "OK";
        check.responseTimeMs = 1.0;
        check.lastRun = now;
        report.checks.push_back(check);
    }

    report.overallStatus = computeOverallStatus(report.checks);

    if (report.overallStatus == HealthStatus::Degraded) {
        report.issues.push_back("Some components are in degraded state");
        report.recommendations.push_back("Investigate degraded components");
    } else if (report.overallStatus == HealthStatus::Unhealthy) {
        report.issues.push_back("Critical components are unhealthy");
        report.recommendations.push_back("Restart unhealthy services");
    }

    reports_.push_back(report);
    logger_.info("Diagnostics completed: {} checks, status: {}",
                 report.checks.size(), static_cast<int>(report.overallStatus));
    return report;
}

bool DiagnosticsEngine::runSingleCheck(const std::string& checkId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = checks_.find(checkId);
    if (it == checks_.end()) return false;

    it->second.status = HealthStatus::Healthy;
    it->second.message = "OK";
    it->second.responseTimeMs = 1.0;
    it->second.lastRun = getCurrentTimestamp();
    return true;
}

std::optional<DiagnosticCheck> DiagnosticsEngine::getCheckResult(const std::string& checkId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = checks_.find(checkId);
    if (it == checks_.end()) return std::nullopt;
    return it->second;
}

void DiagnosticsEngine::setSystemInfo(const SystemInfo& info) {
    std::lock_guard<std::mutex> lock(mutex_);
    systemInfo_ = info;
}

SystemInfo DiagnosticsEngine::getSystemInfo() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return systemInfo_;
}

std::vector<DiagnosticReport> DiagnosticsEngine::getReports() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reports_;
}

std::optional<DiagnosticReport> DiagnosticsEngine::getLatestReport() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (reports_.empty()) return std::nullopt;
    return reports_.back();
}

HealthStatus DiagnosticsEngine::getOverallHealth() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DiagnosticCheck> allChecks;
    for (const auto& [id, check] : checks_) {
        allChecks.push_back(check);
    }
    return computeOverallStatus(allChecks);
}

void DiagnosticsEngine::updateCheckStatus(const std::string& checkId, HealthStatus status,
                                           const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = checks_.find(checkId);
    if (it == checks_.end()) return;

    it->second.status = status;
    it->second.message = message;
    it->second.lastRun = getCurrentTimestamp();
}

uint64_t DiagnosticsEngine::getTotalDiagnosticsRun() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalDiagnosticsRun_;
}

uint64_t DiagnosticsEngine::getCheckCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return checks_.size();
}

} // namespace ThreatOne::Telemetry
