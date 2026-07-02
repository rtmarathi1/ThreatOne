#include "reporting/ReportGenerator.h"

#include <algorithm>
#include <chrono>
#include <sstream>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ThreatOne::Reporting {

ReportGenerator::ReportGenerator()
    : logger_("ReportGenerator") {
    logger_.info("Report Generator initialized");
}

std::string ReportGenerator::generateId() {
    std::ostringstream oss;
    oss << "rpt-" << nextId_.fetch_add(1);
    return oss.str();
}

std::string ReportGenerator::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::ctime(&time);
    std::string result = oss.str();
    // Remove trailing newline from ctime
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}

std::string ReportGenerator::reportTypeToString(ReportType type) {
    switch (type) {
        case ReportType::Executive: return "Executive";
        case ReportType::Technical: return "Technical";
        case ReportType::Incident: return "Incident";
        case ReportType::Compliance: return "Compliance";
        case ReportType::Vulnerability: return "Vulnerability";
        case ReportType::Scan: return "Scan";
        case ReportType::Audit: return "Audit";
        case ReportType::Risk: return "Risk";
    }
    return "Unknown";
}

std::string ReportGenerator::generateContent(const ReportConfig& config) const {
    std::ostringstream oss;
    oss << "=== " << reportTypeToString(config.type) << " Report ===\n";
    oss << "Title: " << config.title << "\n";
    oss << "Author: " << config.author << "\n";
    oss << "Detail Level: ";

    switch (config.detailLevel) {
        case DetailLevel::Summary: oss << "Summary"; break;
        case DetailLevel::Standard: oss << "Standard"; break;
        case DetailLevel::Detailed: oss << "Detailed"; break;
        case DetailLevel::Full: oss << "Full"; break;
    }
    oss << "\n\n";

    // Include configured sections
    for (const auto& section : config.sections) {
        if (section.enabled) {
            oss << "--- " << section.title << " ---\n";
            oss << section.content << "\n\n";
        }
    }

    // Add metadata
    if (!config.metadata.empty()) {
        oss << "--- Metadata ---\n";
        for (const auto& [key, value] : config.metadata) {
            oss << key << ": " << value << "\n";
        }
    }

    return oss.str();
}

ThreatOne::Core::Result<Report> ReportGenerator::generateReport(const ReportConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (config.title.empty()) {
        return ThreatOne::Core::Result<Report>::err(
            ThreatOne::Core::Error("Report title cannot be empty",
                                   ThreatOne::Core::ErrorCategory::Validation));
    }

    Report report;
    report.id = generateId();
    report.title = config.title;
    report.type = config.type;
    report.detailLevel = config.detailLevel;
    report.author = config.author;
    report.generatedAt = getCurrentTimestamp();
    report.sections = config.sections;
    report.metadata = config.metadata;
    report.content = generateContent(config);
    report.sizeBytes = report.content.size();
    report.format = ExportFormat::JSON;

    reports_[report.id] = report;

    logger_.info("Generated {} report: {} ({})",
                 reportTypeToString(config.type), report.title, report.id);

    return ThreatOne::Core::Result<Report>::ok(report);
}

std::vector<Report> ReportGenerator::getReports() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<Report> result;
    result.reserve(reports_.size());
    for (const auto& [id, report] : reports_) {
        result.push_back(report);
    }
    return result;
}

std::optional<Report> ReportGenerator::getReport(const std::string& reportId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reports_.find(reportId);
    if (it == reports_.end()) {
        return std::nullopt;
    }
    return it->second;
}

size_t ReportGenerator::getReportCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reports_.size();
}

void ReportGenerator::clearReports() {
    std::lock_guard<std::mutex> lock(mutex_);
    reports_.clear();
    logger_.info("All reports cleared");
}

} // namespace ThreatOne::Reporting
