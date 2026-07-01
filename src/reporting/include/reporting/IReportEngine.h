#pragma once

#include <string>
#include <vector>

namespace ThreatOne::Reporting {

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

struct Report {
    std::string id;
    std::string title;
    ReportType type = ReportType::Technical;
    std::string content;
    std::string generatedAt;
    std::string format;
};

struct ReportSchedule {
    std::string id;
    std::string reportId;
    std::string cron;
    bool enabled = true;
};

class IReportEngine {
public:
    virtual ~IReportEngine() = default;

    virtual Report generateReport(ReportType type, const std::string& title) = 0;
    virtual std::vector<Report> getReports() = 0;
    virtual std::string exportPDF(const std::string& reportId) = 0;
    virtual std::string exportHTML(const std::string& reportId) = 0;
    virtual std::string exportJSON(const std::string& reportId) = 0;
    virtual std::string exportExcel(const std::string& reportId) = 0;
    virtual bool scheduleReport(const ReportSchedule& schedule) = 0;
};

} // namespace ThreatOne::Reporting
