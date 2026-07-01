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

class ReportStorage {
public:
    ReportStorage();
    ~ReportStorage() = default;

    // Store a report and return its storage ID
    [[nodiscard]] ThreatOne::Core::Result<std::string> storeReport(const Report& report);

    // Retrieve a stored report by ID
    [[nodiscard]] std::optional<Report> retrieveReport(const std::string& reportId) const;

    // Delete a stored report
    bool deleteReport(const std::string& reportId);

    // Search and filter reports
    [[nodiscard]] std::vector<ReportMetadata> searchReports(const ReportFilter& filter) const;

    // Get all report metadata
    [[nodiscard]] std::vector<ReportMetadata> getAllMetadata() const;

    // Get metadata for a specific report
    [[nodiscard]] std::optional<ReportMetadata> getMetadata(const std::string& reportId) const;

    // Download tracking
    bool trackDownload(const std::string& reportId, const std::string& userId);
    [[nodiscard]] int getDownloadCount(const std::string& reportId) const;
    [[nodiscard]] std::vector<DownloadRecord> getDownloadHistory(const std::string& reportId) const;

    // Storage stats
    [[nodiscard]] size_t getStoredReportCount() const;
    [[nodiscard]] size_t getTotalStorageSize() const;

    // Clear all stored data
    void clear();

private:
    mutable std::mutex mutex_;
    std::map<std::string, Report> reports_;
    std::map<std::string, ReportMetadata> metadata_;
    std::map<std::string, std::vector<DownloadRecord>> downloads_;
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Reporting
