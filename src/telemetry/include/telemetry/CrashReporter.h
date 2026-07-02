#pragma once

#include "core/Logger.h"

#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Telemetry {

struct CrashReport {
    std::string id;
    std::string component;
    std::string errorMessage;
    std::string stackTrace;
    std::string systemState;
    std::string timestamp;
    bool fatal = false;
    std::unordered_map<std::string, std::string> metadata;
};

struct CrashStatistics {
    uint64_t totalCrashes = 0;
    uint64_t fatalCrashes = 0;
    uint64_t nonFatalCrashes = 0;
    std::string lastCrashTime;
    std::string mostCrashedComponent;
};

class CrashReporter {
public:
    CrashReporter();
    ~CrashReporter() = default;

    // Report crashes
    std::string reportCrash(const std::string& component, const std::string& errorMessage,
                            const std::string& stackTrace, bool fatal = false);
    std::string reportException(const std::string& component, const std::string& exceptionType,
                                const std::string& message);

    // System state capture
    void setSystemState(const std::string& state);
    [[nodiscard]] std::string getSystemState() const;

    // Query crash data
    [[nodiscard]] std::vector<CrashReport> getCrashReports() const;
    [[nodiscard]] std::vector<CrashReport> getCrashReportsByComponent(const std::string& component) const;
    [[nodiscard]] std::optional<CrashReport> getCrashReport(const std::string& id) const;
    [[nodiscard]] std::vector<CrashReport> getFatalCrashes() const;

    // Statistics
    [[nodiscard]] CrashStatistics getStatistics() const;
    [[nodiscard]] uint64_t getCrashCount() const;
    [[nodiscard]] uint64_t getCrashCountForComponent(const std::string& component) const;

    // Management
    bool deleteCrashReport(const std::string& id);
    void clearCrashReports();

    // Metadata
    void addGlobalMetadata(const std::string& key, const std::string& value);

private:
    std::string generateId();
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::vector<CrashReport> reports_;
    std::unordered_map<std::string, std::string> globalMetadata_;
    std::string systemState_;
    int nextId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Telemetry
