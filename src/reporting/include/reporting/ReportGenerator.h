#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <optional>

#include "reporting/IReportEngine.h"
#include "core/Logger.h"
#include "core/Error.h"

namespace ThreatOne::Reporting {

class ReportGenerator {
public:
    ReportGenerator();
    ~ReportGenerator() = default;

    // Generate a report based on configuration
    [[nodiscard]] ThreatOne::Core::Result<Report> generateReport(const ReportConfig& config);

    // Get all generated reports
    [[nodiscard]] std::vector<Report> getReports() const;

    // Get a specific report by ID
    [[nodiscard]] std::optional<Report> getReport(const std::string& reportId) const;

    // Get count of generated reports
    [[nodiscard]] size_t getReportCount() const;

    // Clear all stored reports
    void clearReports();

private:
    [[nodiscard]] std::string generateId();
    [[nodiscard]] std::string getCurrentTimestamp() const;
    [[nodiscard]] std::string generateContent(const ReportConfig& config) const;
    [[nodiscard]] static std::string reportTypeToString(ReportType type);

    mutable std::mutex mutex_;
    std::map<std::string, Report> reports_;
    std::atomic<int> nextId_{1};
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Reporting
