#include "scanner/YaraEngine.h"

#include <fstream>
#include <sstream>
#include <regex>

namespace ThreatOne::Scanner {

#ifdef HAS_YARA

// ============================================================================
// Real YARA library implementation
// ============================================================================

YaraEngine::YaraEngine()
    : logger_(Core::Logger::instance().getModuleLogger("YaraEngine"))
    , status_(YaraEngineStatus::Uninitialized)
    , compiled_(false)
    , compiler_(nullptr)
    , rules_(nullptr) {
}

YaraEngine::~YaraEngine() {
    if (rules_) {
        yr_rules_destroy(rules_);
        rules_ = nullptr;
    }
    if (compiler_) {
        yr_compiler_destroy(compiler_);
        compiler_ = nullptr;
    }
    if (status_ != YaraEngineStatus::Uninitialized) {
        yr_finalize();
    }
}

Core::Result<void, Core::Error> YaraEngine::initialize() {
    logger_.info("Initializing YARA engine (libyara)");

    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        status_ = YaraEngineStatus::Error;
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to initialize YARA library", Core::ErrorCategory::Internal));
    }

    result = yr_compiler_create(&compiler_);
    if (result != ERROR_SUCCESS) {
        yr_finalize();
        status_ = YaraEngineStatus::Error;
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to create YARA compiler", Core::ErrorCategory::Internal));
    }

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

    if (!compiler_) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("YARA compiler not available", Core::ErrorCategory::Internal));
    }

    int errors = yr_compiler_add_string(compiler_, rulesText.c_str(), nullptr);
    if (errors > 0) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("YARA compilation errors: " + std::to_string(errors),
                       Core::ErrorCategory::Validation));
    }

    auto names = parseRuleNames(rulesText);
    size_t count = names.size();

    ruleSources_.push_back(rulesText);
    for (auto& name : names) {
        ruleNames_.push_back(std::move(name));
    }

    compiled_ = false;
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

    if (rules_) {
        yr_rules_destroy(rules_);
        rules_ = nullptr;
    }

    int result = yr_compiler_get_rules(compiler_, &rules_);
    if (result != ERROR_SUCCESS) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to compile YARA rules", Core::ErrorCategory::Internal));
    }

    compiled_ = true;
    logger_.info("Compiled {} YARA rules", ruleNames_.size());

    return Core::Result<void, Core::Error>::ok();
}

int YaraEngine::scanCallback(YR_SCAN_CONTEXT* /*context*/, int message,
                            void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* matches = static_cast<std::vector<YaraMatch>*>(user_data);
        auto* rule = static_cast<YR_RULE*>(message_data);

        YaraMatch match;
        match.ruleName = rule->identifier;
        match.ruleNamespace = rule->ns->name;

        // Collect tags
        const char* tag = nullptr;
        yr_rule_tags_foreach(rule, tag) {
            match.tags.emplace_back(tag);
        }

        // Collect meta strings
        YR_META* meta = nullptr;
        yr_rule_metas_foreach(rule, meta) {
            if (meta->type == META_TYPE_STRING) {
                match.metaStrings.emplace_back(meta->string);
            }
        }

        matches->push_back(std::move(match));
    }

    return CALLBACK_CONTINUE;
}

Core::Result<std::vector<YaraMatch>, Core::Error> YaraEngine::matchFile(
    const std::filesystem::path& filePath) {

    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    if (!compiled_ || !rules_) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("Rules not compiled", Core::ErrorCategory::Internal));
    }

    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec)) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("File not found: " + filePath.string(), Core::ErrorCategory::IO));
    }

    std::vector<YaraMatch> matches;
    int result = yr_rules_scan_file(rules_, filePath.string().c_str(),
                                    0, scanCallback, &matches, 0);
    if (result != ERROR_SUCCESS) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("YARA scan failed on file: " + filePath.string(),
                       Core::ErrorCategory::Internal));
    }

    logger_.debug("YARA scan on file: {} - {} matches", filePath.string(), matches.size());
    return Core::Result<std::vector<YaraMatch>, Core::Error>::ok(std::move(matches));
}

Core::Result<std::vector<YaraMatch>, Core::Error> YaraEngine::matchBuffer(
    const std::vector<uint8_t>& data) {

    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    if (!compiled_ || !rules_) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("Rules not compiled", Core::ErrorCategory::Internal));
    }

    std::vector<YaraMatch> matches;
    int result = yr_rules_scan_mem(rules_, data.data(), data.size(),
                                   0, scanCallback, &matches, 0);
    if (result != ERROR_SUCCESS) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("YARA scan failed on buffer", Core::ErrorCategory::Internal));
    }

    logger_.debug("YARA scan on buffer ({} bytes) - {} matches", data.size(), matches.size());
    return Core::Result<std::vector<YaraMatch>, Core::Error>::ok(std::move(matches));
}

#else

// ============================================================================
// Stub implementation (fallback when libyara is not available)
// ============================================================================

YaraEngine::YaraEngine()
    : logger_(Core::Logger::instance().getModuleLogger("YaraEngine"))
    , status_(YaraEngineStatus::Uninitialized)
    , compiled_(false) {
}

YaraEngine::~YaraEngine() = default;

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

#endif // HAS_YARA

// ============================================================================
// Common implementation (shared between real and stub)
// ============================================================================

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
