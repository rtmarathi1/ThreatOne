#include "reporting/ReportTemplate.h"

#include <algorithm>
#include <sstream>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ThreatOne::Reporting {

ReportTemplateEngine::ReportTemplateEngine()
    : logger_("ReportTemplateEngine") {
    logger_.info("Report Template Engine initialized");
}

std::string ReportTemplateEngine::generateId() {
    std::ostringstream oss;
    oss << "tmpl-" << nextId_.fetch_add(1);
    return oss.str();
}

ThreatOne::Core::Result<std::string> ReportTemplateEngine::createTemplate(const ReportTemplate& tmpl) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (tmpl.name.empty()) {
        return ThreatOne::Core::Result<std::string>::err(
            ThreatOne::Core::Error("Template name cannot be empty",
                                   ThreatOne::Core::ErrorCategory::Validation));
    }

    ReportTemplate newTemplate = tmpl;
    if (newTemplate.id.empty()) {
        newTemplate.id = generateId();
    }

    std::string id = newTemplate.id;
    templates_[id] = newTemplate;

    logger_.info("Created template: {} ({})", newTemplate.name, id);
    return ThreatOne::Core::Result<std::string>::ok(id);
}

std::vector<ReportTemplate> ReportTemplateEngine::getTemplates() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ReportTemplate> result;
    result.reserve(templates_.size());
    for (const auto& [id, tmpl] : templates_) {
        result.push_back(tmpl);
    }
    return result;
}

std::optional<ReportTemplate> ReportTemplateEngine::getTemplate(const std::string& templateId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = templates_.find(templateId);
    if (it == templates_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool ReportTemplateEngine::deleteTemplate(const std::string& templateId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = templates_.find(templateId);
    if (it == templates_.end()) {
        return false;
    }
    templates_.erase(it);
    logger_.info("Deleted template: {}", templateId);
    return true;
}

std::string ReportTemplateEngine::renderSection(const std::string& content,
                                                 const std::map<std::string, std::string>& variables) {
    std::string result = content;

    for (const auto& [key, value] : variables) {
        std::string placeholder = "{" + key + "}";
        size_t pos = 0;
        while ((pos = result.find(placeholder, pos)) != std::string::npos) {
            result.replace(pos, placeholder.length(), value);
            pos += value.length();
        }
    }

    return result;
}

std::string ReportTemplateEngine::renderTemplate(const std::string& templateId,
                                                  const std::map<std::string, std::string>& variables) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = templates_.find(templateId);
    if (it == templates_.end()) {
        return "";
    }

    const auto& tmpl = it->second;

    // Build complete variable set (template defaults + provided variables)
    std::map<std::string, std::string> allVars = tmpl.placeholders;
    allVars["company_name"] = tmpl.companyName;
    allVars["company_logo"] = tmpl.companyLogo;

    // Override with provided variables
    for (const auto& [key, value] : variables) {
        allVars[key] = value;
    }

    std::ostringstream oss;

    // Render header
    if (!tmpl.header.empty()) {
        oss << renderSection(tmpl.header, allVars) << "\n";
    }

    // Render template sections
    // Sort sections by order
    auto sortedSections = tmpl.sections;
    std::sort(sortedSections.begin(), sortedSections.end(),
              [](const TemplateSection& a, const TemplateSection& b) {
                  return a.order < b.order;
              });

    for (const auto& section : sortedSections) {
        oss << renderSection(section.templateContent, allVars) << "\n";
    }

    // Render footer
    if (!tmpl.footer.empty()) {
        oss << renderSection(tmpl.footer, allVars) << "\n";
    }

    return oss.str();
}

std::string ReportTemplateEngine::assembleSections(const std::string& templateId,
                                                    const std::vector<ReportSection>& sections) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = templates_.find(templateId);
    if (it == templates_.end()) {
        // Without template, just assemble sections directly
        std::ostringstream oss;
        auto sorted = sections;
        std::sort(sorted.begin(), sorted.end(),
                  [](const ReportSection& a, const ReportSection& b) {
                      return a.order < b.order;
                  });
        for (const auto& section : sorted) {
            if (section.enabled) {
                oss << "## " << section.title << "\n";
                oss << section.content << "\n\n";
            }
        }
        return oss.str();
    }

    const auto& tmpl = it->second;
    std::ostringstream oss;

    // Header
    if (!tmpl.header.empty()) {
        oss << tmpl.header << "\n\n";
    }

    // Sections
    auto sorted = sections;
    std::sort(sorted.begin(), sorted.end(),
              [](const ReportSection& a, const ReportSection& b) {
                  return a.order < b.order;
              });

    for (const auto& section : sorted) {
        if (section.enabled) {
            oss << "## " << section.title << "\n";
            oss << section.content << "\n\n";
        }
    }

    // Footer
    if (!tmpl.footer.empty()) {
        oss << tmpl.footer << "\n";
    }

    return oss.str();
}

size_t ReportTemplateEngine::getTemplateCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return templates_.size();
}

} // namespace ThreatOne::Reporting
