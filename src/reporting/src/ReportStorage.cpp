#include "reporting/ReportStorage.h"

#include <algorithm>
#include <chrono>
#include <sstream>
#include <cctype>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ThreatOne::Reporting {

ReportStorage::ReportStorage()
    : logger_("ReportStorage") {
    logger_.info("Report Storage initialized");
}

ThreatOne::Core::Result<std::string> ReportStorage::storeReport(const Report& report) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (report.id.empty()) {
        return ThreatOne::Core::Result<std::string>::err(
            ThreatOne::Core::Error("Report ID cannot be empty",
                                   ThreatOne::Core::ErrorCategory::Validation));
    }

    reports_[report.id] = report;

    // Create metadata entry
    ReportMetadata meta;
    meta.id = report.id;
    meta.title = report.title;
    meta.type = report.type;
    meta.generatedAt = report.generatedAt;
    meta.generatedAtTimePoint = std::chrono::system_clock::now();
    meta.sizeBytes = report.sizeBytes;
    meta.format = report.format;
    meta.downloadCount = 0;
    metadata_[report.id] = meta;

    logger_.info("Stored report: {} ({})", report.title, report.id);
    return ThreatOne::Core::Result<std::string>::ok(report.id);
}

std::optional<Report> ReportStorage::retrieveReport(const std::string& reportId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reports_.find(reportId);
    if (it == reports_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool ReportStorage::deleteReport(const std::string& reportId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reports_.find(reportId);
    if (it == reports_.end()) {
        return false;
    }
    reports_.erase(it);
    metadata_.erase(reportId);
    downloads_.erase(reportId);
    logger_.info("Deleted report: {}", reportId);
    return true;
}

std::vector<ReportMetadata> ReportStorage::searchReports(const ReportFilter& filter) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ReportMetadata> results;

    for (const auto& [id, meta] : metadata_) {
        bool matches = true;

        // Filter by title (partial match, case-insensitive)
        if (!filter.titleContains.empty()) {
            std::string lowerTitle = meta.title;
            std::string lowerFilter = filter.titleContains;
            std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(),
                [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
            std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(),
                [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
            if (lowerTitle.find(lowerFilter) == std::string::npos) {
                matches = false;
            }
        }

        // Filter by type
        if (!filter.types.empty()) {
            bool typeMatch = false;
            for (const auto& t : filter.types) {
                if (meta.type == t) {
                    typeMatch = true;
                    break;
                }
            }
            if (!typeMatch) {
                matches = false;
            }
        }

        // Filter by date range
        if (filter.hasDateFilter) {
            if (meta.generatedAtTimePoint < filter.dateRange.start ||
                meta.generatedAtTimePoint > filter.dateRange.end) {
                matches = false;
            }
        }

        if (matches) {
            results.push_back(meta);
        }
    }

    return results;
}

std::vector<ReportMetadata> ReportStorage::getAllMetadata() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ReportMetadata> results;
    results.reserve(metadata_.size());
    for (const auto& [id, meta] : metadata_) {
        results.push_back(meta);
    }
    return results;
}

std::optional<ReportMetadata> ReportStorage::getMetadata(const std::string& reportId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = metadata_.find(reportId);
    if (it == metadata_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool ReportStorage::trackDownload(const std::string& reportId, const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto metaIt = metadata_.find(reportId);
    if (metaIt == metadata_.end()) {
        return false;
    }

    // Increment download count
    metaIt->second.downloadCount++;

    // Record download
    DownloadRecord record;
    record.reportId = reportId;
    record.userId = userId;
    record.downloadedAt = std::chrono::system_clock::now();
    downloads_[reportId].push_back(record);

    logger_.info("Tracked download for report {} by user {}", reportId, userId);
    return true;
}

int ReportStorage::getDownloadCount(const std::string& reportId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = metadata_.find(reportId);
    if (it == metadata_.end()) {
        return 0;
    }
    return it->second.downloadCount;
}

std::vector<DownloadRecord> ReportStorage::getDownloadHistory(const std::string& reportId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = downloads_.find(reportId);
    if (it == downloads_.end()) {
        return {};
    }
    return it->second;
}

size_t ReportStorage::getStoredReportCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reports_.size();
}

size_t ReportStorage::getTotalStorageSize() const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t total = 0;
    for (const auto& [id, meta] : metadata_) {
        total += meta.sizeBytes;
    }
    return total;
}

void ReportStorage::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    reports_.clear();
    metadata_.clear();
    downloads_.clear();
    logger_.info("Report storage cleared");
}

} // namespace ThreatOne::Reporting
