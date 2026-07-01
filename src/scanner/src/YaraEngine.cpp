#include "scanner/YaraEngine.h"

#include <fstream>
#include <sstream>
#include <regex>

namespace ThreatOne::Scanner {

YaraEngine::YaraEngine()
    : logger_(Core::Logger::instance().getModuleLogger("YaraEngine"))
    , status_(YaraEngineStatus::Uninitialized)
    , compiled_(false) {
}

Core::Result<void, Core::Error> YaraEngine::initialize() {
    logger_.info("Initializing YARA engine (stub implementation)");
    status_ = YaraEngineStatus::Ready;
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<size_t, Core::Error> YaraEngine::loadRules(
    const std::filesystem::path& rulesPath) {

    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    std::ifstream file(rulesPath);
    if (!file.is_open()) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("Cannot open YARA rules file: " + rulesPath.string(),
                       Core::ErrorCategory::IO));
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    return loadRulesFromString(ss.str());
}

Core::Result<size_t, Core::Error> YaraEngine::loadRulesFromString(const std::string& rulesText) {
    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    auto names = parseRuleNames(rulesText);
    size_t count = names.size();

    ruleSources_.push_back(rulesText);
    for (auto& name : names) {
        ruleNames_.push_back(std::move(name));
    }

    compiled_ = false;  // Need to recompile after loading new rules
    logger_.info("Loaded {} YARA rules from text (total: {})", count, ruleNames_.size());

    return Core::Result<size_t, Core::Error>::ok(count);
}

Core::Result<void, Core::Error> YaraEngine::compileRules() {
    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    if (ruleNames_.empty()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("No rules loaded to compile", Core::ErrorCategory::Validation));
    }

    // Stub: mark as compiled without real compilation
    compiled_ = true;
    logger_.info("Compiled {} YARA rules (stub)", ruleNames_.size());

    return Core::Result<void, Core::Error>::ok();
}

Core::Result<std::vector<YaraMatch>, Core::Error> YaraEngine::matchFile(
    const std::filesystem::path& filePath) {

    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    if (!compiled_) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("Rules not compiled", Core::ErrorCategory::Internal));
    }

    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec)) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("File not found: " + filePath.string(), Core::ErrorCategory::IO));
    }

    // Stub: always returns no matches
    logger_.debug("YARA scan (stub) on file: {}", filePath.string());
    return Core::Result<std::vector<YaraMatch>, Core::Error>::ok(std::vector<YaraMatch>{});
}

Core::Result<std::vector<YaraMatch>, Core::Error> YaraEngine::matchBuffer(
    const std::vector<uint8_t>& data) {

    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    if (!compiled_) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("Rules not compiled", Core::ErrorCategory::Internal));
    }

    (void)data;  // Stub: not actually scanning

    logger_.debug("YARA scan (stub) on buffer ({} bytes)", data.size());
    return Core::Result<std::vector<YaraMatch>, Core::Error>::ok(std::vector<YaraMatch>{});
}

size_t YaraEngine::ruleCount() const {
    return ruleNames_.size();
}

std::vector<std::string> YaraEngine::getRuleNames() const {
    return ruleNames_;
}

YaraEngineStatus YaraEngine::status() const {
    return status_;
}

void YaraEngine::clearRules() {
    ruleNames_.clear();
    ruleSources_.clear();
    compiled_ = false;
    logger_.info("Cleared all YARA rules");
}

std::vector<std::string> YaraEngine::parseRuleNames(const std::string& text) const {
    std::vector<std::string> names;

    // Simple parser: look for "rule <name>" pattern
    // YARA rule syntax: rule <identifier> [: tag1 tag2] { ... }
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        // Skip comments
        size_t pos = line.find("//");
        if (pos != std::string::npos) {
            line = line.substr(0, pos);
        }

        // Find "rule" keyword
        pos = line.find("rule");
        if (pos == std::string::npos) continue;

        // Check it starts at beginning or after whitespace
        if (pos > 0 && !std::isspace(static_cast<unsigned char>(line[pos - 1]))) {
            continue;
        }

        // Skip "rule" keyword and whitespace
        pos += 4;  // len("rule")
        while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos]))) {
            pos++;
        }

        // Extract the rule name (identifier: alphanumeric + underscore)
        std::string name;
        while (pos < line.size() &&
               (std::isalnum(static_cast<unsigned char>(line[pos])) || line[pos] == '_')) {
            name.push_back(line[pos]);
            pos++;
        }

        if (!name.empty()) {
            names.push_back(std::move(name));
        }
    }

    return names;
}

} // namespace ThreatOne::Scanner
