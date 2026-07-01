#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <optional>

#include "reporting/IReportEngine.h"
#include "core/Logger.h"
#include "core/Error.h"

namespace ThreatOne::Reporting {

class ReportTemplateEngine {
public:
    ReportTemplateEngine();
    ~ReportTemplateEngine() = default;

    // Create a new template
    [[nodiscard]] ThreatOne::Core::Result<std::string> createTemplate(const ReportTemplate& tmpl);

    // Get all templates
    [[nodiscard]] std::vector<ReportTemplate> getTemplates() const;

    // Get a specific template by ID
    [[nodiscard]] std::optional<ReportTemplate> getTemplate(const std::string& templateId) const;

    // Delete a template
    bool deleteTemplate(const std::string& templateId);

    // Render a template with placeholder substitution
    [[nodiscard]] std::string renderTemplate(const std::string& templateId,
                                              const std::map<std::string, std::string>& variables) const;

    // Render header with placeholder substitution
    [[nodiscard]] static std::string renderSection(const std::string& content,
                                                    const std::map<std::string, std::string>& variables);

    // Assemble sections into a complete document
    [[nodiscard]] std::string assembleSections(const std::string& templateId,
                                               const std::vector<ReportSection>& sections) const;

    // Get template count
    [[nodiscard]] size_t getTemplateCount() const;

private:
    [[nodiscard]] std::string generateId();

    mutable std::mutex mutex_;
    std::map<std::string, ReportTemplate> templates_;
    std::atomic<int> nextId_{1};
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Reporting
