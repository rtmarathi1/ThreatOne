#include "sandbox/SandboxReporter.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Sandbox {

SandboxReporter::SandboxReporter()
    : logger_(Core::Logger::instance().getModuleLogger("SandboxReporter")) {
    logger_.info("SandboxReporter initialized");
}

std::string SandboxReporter::generateReportId() {
    return "RPT-" + std::to_string(nextReportId_++);
}

std::string SandboxReporter::generateTemplateId() {
    return "TMPL-" + std::to_string(nextTemplateId_++);
}

std::string SandboxReporter::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::string SandboxReporter::formatTextReport(
    const AnalysisResult& analysis,
    const BehaviorReport& behaviors,
    const std::vector<IOCInfo>& iocs,
    const std::vector<std::string>& recommendations) const {

    std::ostringstream oss;
    oss << "=== Sandbox Analysis Report ===\n";
    oss << "Sample: " << analysis.id << "\n";
    oss << "Verdict: " << analysis.verdict << "\n";
    oss << "Score: " << analysis.score << "\n";
    oss << "Hash: " << analysis.sampleHash << "\n\n";

    oss << "--- Behaviors ---\n";
    oss << "Processes created: " << behaviors.processesCreated.size() << "\n";
    oss << "Files modified: " << behaviors.filesModified.size() << "\n";
    oss << "Registry changes: " << behaviors.registryChanges.size() << "\n";
    oss << "Network connections: " << behaviors.networkConnections.size() << "\n";
    oss << "Dropped files: " << behaviors.droppedFiles.size() << "\n\n";

    if (!iocs.empty()) {
        oss << "--- IOCs (" << iocs.size() << ") ---\n";
        for (const auto& ioc : iocs) {
            oss << "[" << ioc.type << "] " << ioc.value << " (" << ioc.confidence << ")\n";
        }
        oss << "\n";
    }

    if (!recommendations.empty()) {
        oss << "--- Recommendations ---\n";
        for (const auto& rec : recommendations) {
            oss << "- " << rec << "\n";
        }
    }

    return oss.str();
}

std::string SandboxReporter::formatJSONReport(
    const AnalysisResult& analysis,
    const BehaviorReport& behaviors,
    const std::vector<IOCInfo>& iocs) const {

    std::ostringstream oss;
    oss << "{\"sample\":\"" << analysis.id << "\","
        << "\"verdict\":\"" << analysis.verdict << "\","
        << "\"score\":" << analysis.score << ","
        << "\"hash\":\"" << analysis.sampleHash << "\","
        << "\"behaviors\":{\"processes\":" << behaviors.processesCreated.size()
        << ",\"files\":" << behaviors.filesModified.size()
        << ",\"registry\":" << behaviors.registryChanges.size()
        << ",\"network\":" << behaviors.networkConnections.size()
        << ",\"dropped\":" << behaviors.droppedFiles.size() << "},"
        << "\"ioc_count\":" << iocs.size() << "}";
    return oss.str();
}

std::string SandboxReporter::formatSummary(const AnalysisResult& analysis) const {
    std::ostringstream oss;
    oss << "Sample " << analysis.id << ": " << analysis.verdict
        << " (score: " << analysis.score << ")";
    return oss.str();
}

std::string SandboxReporter::generateReport(
    const std::string& sampleId,
    const AnalysisResult& analysis,
    const BehaviorReport& behaviors,
    const std::vector<IOCInfo>& iocs,
    ReportFormat format) {

    std::lock_guard<std::mutex> lock(mutex_);

    SandboxReport report;
    report.id = generateReportId();
    report.sampleId = sampleId;
    report.format = format;
    report.generatedAt = getCurrentTimestamp();
    report.iocs = iocs;

    // Determine verdict
    if (analysis.verdict == "malicious") {
        report.verdict = SandboxVerdict::Malicious;
    } else if (analysis.verdict == "suspicious") {
        report.verdict = SandboxVerdict::Suspicious;
    } else if (analysis.verdict == "clean") {
        report.verdict = SandboxVerdict::Clean;
    } else {
        report.verdict = SandboxVerdict::Unknown;
    }
    report.threatScore = analysis.score;
    report.recommendations = generateRecommendations(report.verdict, iocs);

    switch (format) {
        case ReportFormat::Text:
            report.title = "Sandbox Analysis Report - " + sampleId;
            report.content = formatTextReport(analysis, behaviors, iocs, report.recommendations);
            break;
        case ReportFormat::JSON:
            report.title = "JSON Report - " + sampleId;
            report.content = formatJSONReport(analysis, behaviors, iocs);
            break;
        case ReportFormat::Summary:
            report.title = "Summary - " + sampleId;
            report.content = formatSummary(analysis);
            break;
        default:
            report.title = "Report - " + sampleId;
            report.content = formatTextReport(analysis, behaviors, iocs, report.recommendations);
            break;
    }

    reports_[report.id] = report;
    ++totalReportsGenerated_;
    logger_.info("Generated report: {} (format: {})", report.id, static_cast<int>(format));
    return report.id;
}

std::string SandboxReporter::generateSummaryReport(const std::string& sampleId,
                                                    const AnalysisResult& analysis) {
    BehaviorReport emptyBehaviors;
    emptyBehaviors.sampleId = sampleId;
    return generateReport(sampleId, analysis, emptyBehaviors, {}, ReportFormat::Summary);
}

std::optional<SandboxReport> SandboxReporter::getReport(const std::string& reportId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reports_.find(reportId);
    if (it == reports_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<SandboxReport> SandboxReporter::getReportsForSample(const std::string& sampleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SandboxReport> result;
    for (const auto& [id, report] : reports_) {
        if (report.sampleId == sampleId) {
            result.push_back(report);
        }
    }
    return result;
}

std::vector<SandboxReport> SandboxReporter::getAllReports() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SandboxReport> result;
    result.reserve(reports_.size());
    for (const auto& [id, report] : reports_) {
        result.push_back(report);
    }
    return result;
}

bool SandboxReporter::deleteReport(const std::string& reportId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reports_.find(reportId);
    if (it == reports_.end()) {
        return false;
    }
    reports_.erase(it);
    return true;
}

std::string SandboxReporter::createTemplate(const ReportTemplate& tmpl) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generateTemplateId();
    ReportTemplate newTmpl = tmpl;
    newTmpl.id = id;
    templates_[id] = newTmpl;
    logger_.info("Created report template: {}", id);
    return id;
}

std::vector<ReportTemplate> SandboxReporter::getTemplates() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ReportTemplate> result;
    result.reserve(templates_.size());
    for (const auto& [id, tmpl] : templates_) {
        result.push_back(tmpl);
    }
    return result;
}

std::optional<ReportTemplate> SandboxReporter::getTemplate(const std::string& templateId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = templates_.find(templateId);
    if (it == templates_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool SandboxReporter::deleteTemplate(const std::string& templateId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = templates_.find(templateId);
    if (it == templates_.end()) {
        return false;
    }
    templates_.erase(it);
    return true;
}

std::vector<std::string> SandboxReporter::generateRecommendations(
    SandboxVerdict verdict, const std::vector<IOCInfo>& iocs) const {

    std::vector<std::string> recommendations;

    switch (verdict) {
        case SandboxVerdict::Malicious:
            recommendations.push_back("Quarantine the sample immediately");
            recommendations.push_back("Block associated IOCs across the network");
            recommendations.push_back("Scan all endpoints for related artifacts");
            recommendations.push_back("Notify incident response team");
            break;
        case SandboxVerdict::Suspicious:
            recommendations.push_back("Perform deeper analysis with extended timeout");
            recommendations.push_back("Monitor for similar activity across endpoints");
            recommendations.push_back("Add associated indicators to watchlist");
            break;
        case SandboxVerdict::Clean:
            recommendations.push_back("No action required");
            break;
        default:
            recommendations.push_back("Rerun analysis with different profile");
            break;
    }

    if (!iocs.empty()) {
        recommendations.push_back("Update threat intelligence feeds with extracted IOCs");
    }

    return recommendations;
}

uint64_t SandboxReporter::getTotalReportsGenerated() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalReportsGenerated_;
}

uint64_t SandboxReporter::getReportCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reports_.size();
}

} // namespace ThreatOne::Sandbox
