#pragma once

#include <string>

#include "reporting/IReportEngine.h"
#include "core/Logger.h"
#include "core/Error.h"

namespace ThreatOne::Reporting {

class ExportEngine {
public:
    ExportEngine();
    ~ExportEngine() = default;

    // Export a report to the specified format
    [[nodiscard]] ThreatOne::Core::Result<std::string> exportReport(const Report& report, ExportFormat format);

    // Individual format exporters
    [[nodiscard]] ThreatOne::Core::Result<std::string> exportToPDF(const Report& report);
    [[nodiscard]] ThreatOne::Core::Result<std::string> exportToHTML(const Report& report);
    [[nodiscard]] ThreatOne::Core::Result<std::string> exportToJSON(const Report& report);
    [[nodiscard]] ThreatOne::Core::Result<std::string> exportToCSV(const Report& report);

private:
    [[nodiscard]] static std::string escapeHtml(const std::string& text);
    [[nodiscard]] static std::string escapeCsv(const std::string& text);

    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Reporting
