#pragma once

#include "reporting/IReportEngine.h"
#include "reporting/ReportGenerator.h"
#include "reporting/ReportTemplate.h"
#include "reporting/ExportEngine.h"
#include "reporting/ReportScheduler.h"
#include "reporting/ReportStorage.h"
#include "core/Logger.h"

#include <memory>
#include <string>
#include <vector>

namespace ThreatOne::Reporting {

class ReportEngine : public IReportEngine {
public:
    ReportEngine();
    ~ReportEngine() override = default;

    // IReportEngine interface
    ThreatOne::Core::Result<Report> generateReport(const ReportConfig& config) override;
    std::vector<Report> getReports() const override;
    ThreatOne::Core::Result<std::string> exportReport(const std::string& reportId, ExportFormat format) override;
    ThreatOne::Core::Result<std::string> createTemplate(const ReportTemplate& tmpl) override;
    std::vector<ReportTemplate> getTemplates() const override;
    ThreatOne::Core::Result<std::string> scheduleReport(const ReportSchedule& schedule) override;
    bool cancelSchedule(const std::string& scheduleId) override;
    std::vector<ReportSchedule> getSchedules() const override;
    ThreatOne::Core::Result<std::string> storeReport(const Report& report) override;
    std::vector<ReportMetadata> searchReports(const ReportFilter& filter) const override;
    bool trackDownload(const std::string& reportId, const std::string& userId) override;

    // Direct access to sub-components
    ReportGenerator& generator() { return generator_; }
    ReportTemplateEngine& templateEngine() { return templateEngine_; }
    ExportEngine& exportEngine() { return exportEngine_; }
    ReportScheduler& scheduler() { return scheduler_; }
    ReportStorage& storage() { return storage_; }

private:
    ReportGenerator generator_;
    ReportTemplateEngine templateEngine_;
    ExportEngine exportEngine_;
    ReportScheduler scheduler_;
    ReportStorage storage_;
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Reporting
