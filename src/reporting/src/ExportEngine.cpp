#include "reporting/ExportEngine.h"

#include <sstream>
#include <nlohmann/json.hpp>

namespace ThreatOne::Reporting {

ExportEngine::ExportEngine()
    : logger_("ExportEngine") {
    logger_.info("Export Engine initialized");
}

std::string ExportEngine::escapeHtml(const std::string& text) {
    std::string result;
    result.reserve(text.size());
    for (char c : text) {
        switch (c) {
            case '&': result += "&amp;"; break;
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&#39;"; break;
            default: result += c; break;
        }
    }
    return result;
}

std::string ExportEngine::escapeCsv(const std::string& text) {
    if (text.find(',') != std::string::npos ||
        text.find('"') != std::string::npos ||
        text.find('\n') != std::string::npos) {
        std::string escaped = "\"";
        for (char c : text) {
            if (c == '"') {
                escaped += "\"\"";
            } else {
                escaped += c;
            }
        }
        escaped += "\"";
        return escaped;
    }
    return text;
}

ThreatOne::Core::Result<std::string> ExportEngine::exportReport(const Report& report, ExportFormat format) {
    switch (format) {
        case ExportFormat::PDF:
            return exportToPDF(report);
        case ExportFormat::HTML:
            return exportToHTML(report);
        case ExportFormat::JSON:
            return exportToJSON(report);
        case ExportFormat::CSV:
            return exportToCSV(report);
    }
    return ThreatOne::Core::Result<std::string>::err(
        ThreatOne::Core::Error("Unsupported export format",
                               ThreatOne::Core::ErrorCategory::Validation));
}

ThreatOne::Core::Result<std::string> ExportEngine::exportToPDF(const Report& report) {
    std::lock_guard<std::mutex> lock(mutex_);

    // PDF export produces structured document metadata (since we cannot produce actual binary PDF)
    std::ostringstream oss;
    oss << "%PDF-1.4\n";
    oss << "% ThreatOne Report Document\n";
    oss << "% Title: " << report.title << "\n";
    oss << "% Type: ";
    switch (report.type) {
        case ReportType::Executive: oss << "Executive"; break;
        case ReportType::Technical: oss << "Technical"; break;
        case ReportType::Incident: oss << "Incident"; break;
        case ReportType::Compliance: oss << "Compliance"; break;
        case ReportType::Vulnerability: oss << "Vulnerability"; break;
        case ReportType::Scan: oss << "Scan"; break;
        case ReportType::Audit: oss << "Audit"; break;
        case ReportType::Risk: oss << "Risk"; break;
    }
    oss << "\n";
    oss << "% Generated: " << report.generatedAt << "\n";
    oss << "% Author: " << report.author << "\n\n";

    // Document structure
    oss << "1 0 obj\n";
    oss << "<< /Type /Catalog /Pages 2 0 R >>\n";
    oss << "endobj\n\n";

    oss << "2 0 obj\n";
    oss << "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n";
    oss << "endobj\n\n";

    oss << "3 0 obj\n";
    oss << "<< /Type /Page /Parent 2 0 R\n";
    oss << "   /MediaBox [0 0 612 792]\n";
    oss << "   /Contents 4 0 R >>\n";
    oss << "endobj\n\n";

    // Content stream with report sections
    oss << "4 0 obj\n";
    oss << "<< /Length " << report.content.size() << " >>\n";
    oss << "stream\n";

    // Headers and tables metadata
    for (const auto& section : report.sections) {
        if (section.enabled) {
            oss << "[HEADER] " << section.title << "\n";
            oss << "[CONTENT] " << section.content << "\n";
        }
    }
    if (report.sections.empty()) {
        oss << "[CONTENT] " << report.content << "\n";
    }

    oss << "endstream\n";
    oss << "endobj\n\n";
    oss << "%%EOF\n";

    logger_.info("Exported report {} to PDF format", report.id);
    return ThreatOne::Core::Result<std::string>::ok(oss.str());
}

ThreatOne::Core::Result<std::string> ExportEngine::exportToHTML(const Report& report) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ostringstream oss;
    oss << "<!DOCTYPE html>\n";
    oss << "<html lang=\"en\">\n";
    oss << "<head>\n";
    oss << "  <meta charset=\"UTF-8\">\n";
    oss << "  <title>" << escapeHtml(report.title) << "</title>\n";
    oss << "  <style>\n";
    oss << "    body { font-family: Arial, sans-serif; margin: 40px; }\n";
    oss << "    h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }\n";
    oss << "    h2 { color: #34495e; }\n";
    oss << "    .metadata { color: #7f8c8d; font-size: 0.9em; }\n";
    oss << "    .section { margin: 20px 0; padding: 15px; background: #f9f9f9; border-left: 4px solid #3498db; }\n";
    oss << "    table { border-collapse: collapse; width: 100%; }\n";
    oss << "    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n";
    oss << "    th { background-color: #3498db; color: white; }\n";
    oss << "  </style>\n";
    oss << "</head>\n";
    oss << "<body>\n";
    oss << "  <h1>" << escapeHtml(report.title) << "</h1>\n";
    oss << "  <div class=\"metadata\">\n";
    oss << "    <p>Generated: " << escapeHtml(report.generatedAt) << "</p>\n";
    oss << "    <p>Author: " << escapeHtml(report.author) << "</p>\n";
    oss << "    <p>Report ID: " << escapeHtml(report.id) << "</p>\n";
    oss << "  </div>\n";

    for (const auto& section : report.sections) {
        if (section.enabled) {
            oss << "  <div class=\"section\">\n";
            oss << "    <h2>" << escapeHtml(section.title) << "</h2>\n";
            oss << "    <p>" << escapeHtml(section.content) << "</p>\n";
            oss << "  </div>\n";
        }
    }

    if (report.sections.empty() && !report.content.empty()) {
        oss << "  <div class=\"section\">\n";
        oss << "    <p>" << escapeHtml(report.content) << "</p>\n";
        oss << "  </div>\n";
    }

    oss << "</body>\n";
    oss << "</html>\n";

    logger_.info("Exported report {} to HTML format", report.id);
    return ThreatOne::Core::Result<std::string>::ok(oss.str());
}

ThreatOne::Core::Result<std::string> ExportEngine::exportToJSON(const Report& report) {
    std::lock_guard<std::mutex> lock(mutex_);

    nlohmann::json j;
    j["id"] = report.id;
    j["title"] = report.title;
    j["generatedAt"] = report.generatedAt;
    j["author"] = report.author;
    j["content"] = report.content;
    j["sizeBytes"] = report.sizeBytes;

    // Report type as string
    switch (report.type) {
        case ReportType::Executive: j["type"] = "Executive"; break;
        case ReportType::Technical: j["type"] = "Technical"; break;
        case ReportType::Incident: j["type"] = "Incident"; break;
        case ReportType::Compliance: j["type"] = "Compliance"; break;
        case ReportType::Vulnerability: j["type"] = "Vulnerability"; break;
        case ReportType::Scan: j["type"] = "Scan"; break;
        case ReportType::Audit: j["type"] = "Audit"; break;
        case ReportType::Risk: j["type"] = "Risk"; break;
    }

    // Detail level
    switch (report.detailLevel) {
        case DetailLevel::Summary: j["detailLevel"] = "Summary"; break;
        case DetailLevel::Standard: j["detailLevel"] = "Standard"; break;
        case DetailLevel::Detailed: j["detailLevel"] = "Detailed"; break;
        case DetailLevel::Full: j["detailLevel"] = "Full"; break;
    }

    // Sections
    nlohmann::json sectionsArr = nlohmann::json::array();
    for (const auto& section : report.sections) {
        nlohmann::json s;
        s["id"] = section.id;
        s["title"] = section.title;
        s["content"] = section.content;
        s["order"] = section.order;
        s["enabled"] = section.enabled;
        sectionsArr.push_back(s);
    }
    j["sections"] = sectionsArr;

    // Metadata
    nlohmann::json metaObj = nlohmann::json::object();
    for (const auto& [key, val] : report.metadata) {
        metaObj[key] = val;
    }
    j["metadata"] = metaObj;

    logger_.info("Exported report {} to JSON format", report.id);
    return ThreatOne::Core::Result<std::string>::ok(j.dump(2));
}

ThreatOne::Core::Result<std::string> ExportEngine::exportToCSV(const Report& report) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ostringstream oss;

    // CSV header row
    oss << "Section ID,Section Title,Content,Order,Enabled\n";

    if (!report.sections.empty()) {
        for (const auto& section : report.sections) {
            oss << escapeCsv(section.id) << ","
                << escapeCsv(section.title) << ","
                << escapeCsv(section.content) << ","
                << section.order << ","
                << (section.enabled ? "true" : "false") << "\n";
        }
    } else {
        // Export report as single row if no sections
        oss << escapeCsv(report.id) << ","
            << escapeCsv(report.title) << ","
            << escapeCsv(report.content) << ","
            << "0,"
            << "true\n";
    }

    logger_.info("Exported report {} to CSV format", report.id);
    return ThreatOne::Core::Result<std::string>::ok(oss.str());
}

} // namespace ThreatOne::Reporting
