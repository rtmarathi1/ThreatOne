#pragma once

#include "reporting/IReportEngine.h"
#include "core/Logger.h"

namespace ThreatOne::Reporting {

class ReportEngine : public IReportEngine {
public:
    ReportEngine();
    ~ReportEngine() override = default;

    Report generateReport(ReportType type, const std::string& title) override;
    std::vector<Report> getReports() override;
    std::string exportPDF(const std::string& reportId) override;
    std::string exportHTML(const std::string& reportId) override;
    std::string exportJSON(const std::string& reportId) override;
    std::string exportExcel(const std::string& reportId) override;
    bool scheduleReport(const ReportSchedule& schedule) override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Reporting
