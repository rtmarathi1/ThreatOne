#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>

#include "core/Error.h"

namespace ThreatOne::Reporting {

// Report types supported by the system
enum class ReportType {
    Executive,
    Technical,
    Incident,
    Compliance,
    Vulnerability,
    Scan,
    Audit,
    Risk
};

// Detail level for report generation
enum class DetailLevel {
    Summary,
    Standard,
    Detailed,
    Full
};

// Export format options
enum class ExportFormat {
    PDF,
    HTML,
    JSON,
    CSV
};

// Scheduling frequency
enum class ScheduleFrequency {
    Daily,
    Weekly,
    Monthly
};

// Report section configuration
struct ReportSection {
    std::string id;
    std::string title;
    std::string content;
    int order = 0;
    bool enabled = true;
};

// Date range for report data
struct DateRange {
    std::chrono::system_clock::time_point start;
    std::chrono::system_clock::time_point end;
};

// Configuration for report generation
struct ReportConfig {
    std::string title;
    ReportType type = ReportType::Technical;
    DetailLevel detailLevel = DetailLevel::Standard;
    std::vector<ReportSection> sections;
    DateRange dateRange;
    std::string author;
    std::map<std::string, std::string> metadata;
};

// Generated report structure
struct Report {
    std::string id;
    std::string title;
    ReportType type = ReportType::Technical;
    DetailLevel detailLevel = DetailLevel::Standard;
    std::string content;
    std::string generatedAt;
    ExportFormat format = ExportFormat::JSON;
    std::vector<ReportSection> sections;
    std::string author;
    size_t sizeBytes = 0;
    std::map<std::string, std::string> metadata;
};

// Template section for report formatting
struct TemplateSection {
    std::string id;
    std::string name;
    std::string templateContent;
    int order = 0;
};

// Report template with branding and formatting
struct ReportTemplate {
    std::string id;
    std::string name;
    std::string header;
    std::string footer;
    std::string companyName;
    std::string companyLogo;
    std::vector<TemplateSection> sections;
    std::map<std::string, std::string> placeholders;
};

// Schedule for recurring report generation
struct ReportSchedule {
    std::string id;
    std::string reportConfigId;
    ScheduleFrequency frequency = ScheduleFrequency::Weekly;
    bool enabled = true;
    std::vector<std::string> distributionList;
    int retentionDays = 90;
    std::chrono::system_clock::time_point lastRun;
    std::chrono::system_clock::time_point nextRun;
};

// Download tracking record
struct DownloadRecord {
    std::string reportId;
    std::string userId;
    std::chrono::system_clock::time_point downloadedAt;
};

// Report storage metadata
struct ReportMetadata {
    std::string id;
    std::string title;
    ReportType type = ReportType::Technical;
    std::string generatedAt;
    std::chrono::system_clock::time_point generatedAtTimePoint;
    size_t sizeBytes = 0;
    ExportFormat format = ExportFormat::JSON;
    int downloadCount = 0;
};

// Search/filter criteria for stored reports
struct ReportFilter {
    std::string titleContains;
    std::vector<ReportType> types;
    DateRange dateRange;
    bool hasDateFilter = false;
};

// Interface for the complete reporting engine
class IReportEngine {
public:
    virtual ~IReportEngine() = default;

    // Report generation
    virtual ThreatOne::Core::Result<Report> generateReport(const ReportConfig& config) = 0;
    virtual std::vector<Report> getReports() const = 0;

    // Export
    virtual ThreatOne::Core::Result<std::string> exportReport(const std::string& reportId, ExportFormat format) = 0;

    // Templates
    virtual ThreatOne::Core::Result<std::string> createTemplate(const ReportTemplate& tmpl) = 0;
    virtual std::vector<ReportTemplate> getTemplates() const = 0;

    // Scheduling
    virtual ThreatOne::Core::Result<std::string> scheduleReport(const ReportSchedule& schedule) = 0;
    virtual bool cancelSchedule(const std::string& scheduleId) = 0;
    virtual std::vector<ReportSchedule> getSchedules() const = 0;

    // Storage
    virtual ThreatOne::Core::Result<std::string> storeReport(const Report& report) = 0;
    virtual std::vector<ReportMetadata> searchReports(const ReportFilter& filter) const = 0;
    virtual bool trackDownload(const std::string& reportId, const std::string& userId) = 0;
};

} // namespace ThreatOne::Reporting
