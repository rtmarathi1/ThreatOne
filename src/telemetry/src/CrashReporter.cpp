#include "telemetry/CrashReporter.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Telemetry {

CrashReporter::CrashReporter()
    : logger_(Core::Logger::instance().getModuleLogger("CrashReporter")) {
    logger_.info("CrashReporter initialized");
}

std::string CrashReporter::generateId() {
    return "CRASH-" + std::to_string(nextId_++);
}

std::string CrashReporter::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::string CrashReporter::reportCrash(const std::string& component,
                                         const std::string& errorMessage,
                                         const std::string& stackTrace,
                                         bool fatal) {
    std::lock_guard<std::mutex> lock(mutex_);

    CrashReport report;
    report.id = generateId();
    report.component = component;
    report.errorMessage = errorMessage;
    report.stackTrace = stackTrace;
    report.systemState = systemState_;
    report.timestamp = getCurrentTimestamp();
    report.fatal = fatal;
    report.metadata = globalMetadata_;

    reports_.push_back(report);
    logger_.info("Crash reported: {} in {} (fatal: {})", errorMessage, component, fatal);
    return report.id;
}

std::string CrashReporter::reportException(const std::string& component,
                                            const std::string& exceptionType,
                                            const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);

    CrashReport report;
    report.id = generateId();
    report.component = component;
    report.errorMessage = exceptionType + ": " + message;
    report.stackTrace = "";
    report.systemState = systemState_;
    report.timestamp = getCurrentTimestamp();
    report.fatal = false;
    report.metadata = globalMetadata_;
    report.metadata["exception_type"] = exceptionType;

    reports_.push_back(report);
    logger_.info("Exception reported: {} in {}", exceptionType, component);
    return report.id;
}

void CrashReporter::setSystemState(const std::string& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    systemState_ = state;
}

std::string CrashReporter::getSystemState() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return systemState_;
}

std::vector<CrashReport> CrashReporter::getCrashReports() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reports_;
}

std::vector<CrashReport> CrashReporter::getCrashReportsByComponent(const std::string& component) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<CrashReport> result;
    for (const auto& report : reports_) {
        if (report.component == component) {
            result.push_back(report);
        }
    }
    return result;
}

std::optional<CrashReport> CrashReporter::getCrashReport(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& report : reports_) {
        if (report.id == id) {
            return report;
        }
    }
    return std::nullopt;
}

std::vector<CrashReport> CrashReporter::getFatalCrashes() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<CrashReport> result;
    for (const auto& report : reports_) {
        if (report.fatal) {
            result.push_back(report);
        }
    }
    return result;
}

CrashStatistics CrashReporter::getStatistics() const {
    std::lock_guard<std::mutex> lock(mutex_);

    CrashStatistics stats;
    stats.totalCrashes = reports_.size();

    std::unordered_map<std::string, uint64_t> componentCounts;

    for (const auto& report : reports_) {
        if (report.fatal) {
            ++stats.fatalCrashes;
        } else {
            ++stats.nonFatalCrashes;
        }
        componentCounts[report.component]++;
    }

    if (!reports_.empty()) {
        stats.lastCrashTime = reports_.back().timestamp;

        uint64_t maxCount = 0;
        for (const auto& [comp, count] : componentCounts) {
            if (count > maxCount) {
                maxCount = count;
                stats.mostCrashedComponent = comp;
            }
        }
    }

    return stats;
}

uint64_t CrashReporter::getCrashCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reports_.size();
}

uint64_t CrashReporter::getCrashCountForComponent(const std::string& component) const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t count = 0;
    for (const auto& report : reports_) {
        if (report.component == component) {
            ++count;
        }
    }
    return count;
}

bool CrashReporter::deleteCrashReport(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find_if(reports_.begin(), reports_.end(),
                           [&id](const CrashReport& r) { return r.id == id; });
    if (it == reports_.end()) {
        return false;
    }
    reports_.erase(it);
    return true;
}

void CrashReporter::clearCrashReports() {
    std::lock_guard<std::mutex> lock(mutex_);
    reports_.clear();
}

void CrashReporter::addGlobalMetadata(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    globalMetadata_[key] = value;
}

} // namespace ThreatOne::Telemetry
