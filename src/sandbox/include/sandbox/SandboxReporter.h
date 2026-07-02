#pragma once
#include <optional>

#include "sandbox/ISandboxEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Sandbox {

enum class ReportFormat {
    Text,
    JSON,
    HTML,
    Summary
};

struct SandboxReport {
    std::string id;
    std::string sampleId;
    ReportFormat format = ReportFormat::Text;
    std::string title;
    std::string content;
    std::string generatedAt;
    SandboxVerdict verdict = SandboxVerdict::Unknown;
    double threatScore = 0.0;
    std::vector<IOCInfo> iocs;
    std::vector<std::string> recommendations;
};

struct ReportTemplate {
    std::string id;
    std::string name;
    ReportFormat format = ReportFormat::Text;
    bool includeIOCs = true;
    bool includeNetworkActivity = true;
    bool includeBehaviors = true;
    bool includeRecommendations = true;
};

class SandboxReporter {
public:
    SandboxReporter();
    ~SandboxReporter() = default;

    // Report generation
    std::string generateReport(const std::string& sampleId,
                               const AnalysisResult& analysis,
                               const BehaviorReport& behaviors,
                               const std::vector<IOCInfo>& iocs,
                               ReportFormat format = ReportFormat::Text);

    std::string generateSummaryReport(const std::string& sampleId,
                                      const AnalysisResult& analysis);

    // Report management
    [[nodiscard]] std::optional<SandboxReport> getReport(const std::string& reportId) const;
    [[nodiscard]] std::vector<SandboxReport> getReportsForSample(const std::string& sampleId) const;
    [[nodiscard]] std::vector<SandboxReport> getAllReports() const;
    bool deleteReport(const std::string& reportId);

    // Template management
    std::string createTemplate(const ReportTemplate& tmpl);
    [[nodiscard]] std::vector<ReportTemplate> getTemplates() const;
    [[nodiscard]] std::optional<ReportTemplate> getTemplate(const std::string& templateId) const;
    bool deleteTemplate(const std::string& templateId);

    // Recommendations
    std::vector<std::string> generateRecommendations(SandboxVerdict verdict,
                                                     const std::vector<IOCInfo>& iocs) const;

    // Statistics
    [[nodiscard]] uint64_t getTotalReportsGenerated() const;
    [[nodiscard]] uint64_t getReportCount() const;

private:
    std::string generateReportId();
    std::string generateTemplateId();
    std::string getCurrentTimestamp() const;
    std::string formatTextReport(const AnalysisResult& analysis,
                                 const BehaviorReport& behaviors,
                                 const std::vector<IOCInfo>& iocs,
                                 const std::vector<std::string>& recommendations) const;
    std::string formatJSONReport(const AnalysisResult& analysis,
                                 const BehaviorReport& behaviors,
                                 const std::vector<IOCInfo>& iocs) const;
    std::string formatSummary(const AnalysisResult& analysis) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, SandboxReport> reports_;
    std::unordered_map<std::string, ReportTemplate> templates_;
    uint64_t totalReportsGenerated_ = 0;
    int nextReportId_ = 1;
    int nextTemplateId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Sandbox
