#include "reporting/ReportEngine.h"

namespace ThreatOne::Reporting {

ReportEngine::ReportEngine()
    : logger_("ReportEngine") {
    logger_.info("ReportEngine initialized");
}

ThreatOne::Core::Result<Report> ReportEngine::generateReport(const ReportConfig& config) {
    auto result = generator_.generateReport(config);
    if (result.isOk()) {
        // Auto-store generated reports
        (void)storage_.storeReport(result.value());
    }
    return result;
}

std::vector<Report> ReportEngine::getReports() const {
    return generator_.getReports();
}

ThreatOne::Core::Result<std::string> ReportEngine::exportReport(const std::string& reportId, ExportFormat format) {
    auto report = generator_.getReport(reportId);
    if (!report.has_value()) {
        // Also check storage
        auto stored = storage_.retrieveReport(reportId);
        if (!stored.has_value()) {
            return ThreatOne::Core::Result<std::string>::err(
                ThreatOne::Core::Error("Report not found: " + reportId,
                                       ThreatOne::Core::ErrorCategory::Validation));
        }
        return exportEngine_.exportReport(stored.value(), format);
    }
    return exportEngine_.exportReport(report.value(), format);
}

ThreatOne::Core::Result<std::string> ReportEngine::createTemplate(const ReportTemplate& tmpl) {
    return templateEngine_.createTemplate(tmpl);
}

std::vector<ReportTemplate> ReportEngine::getTemplates() const {
    return templateEngine_.getTemplates();
}

ThreatOne::Core::Result<std::string> ReportEngine::scheduleReport(const ReportSchedule& schedule) {
    return scheduler_.createSchedule(schedule);
}

bool ReportEngine::cancelSchedule(const std::string& scheduleId) {
    return scheduler_.cancelSchedule(scheduleId);
}

std::vector<ReportSchedule> ReportEngine::getSchedules() const {
    return scheduler_.getSchedules();
}

ThreatOne::Core::Result<std::string> ReportEngine::storeReport(const Report& report) {
    return storage_.storeReport(report);
}

std::vector<ReportMetadata> ReportEngine::searchReports(const ReportFilter& filter) const {
    return storage_.searchReports(filter);
}

bool ReportEngine::trackDownload(const std::string& reportId, const std::string& userId) {
    return storage_.trackDownload(reportId, userId);
}

} // namespace ThreatOne::Reporting
