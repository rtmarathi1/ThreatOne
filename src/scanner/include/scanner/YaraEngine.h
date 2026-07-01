#pragma once

// ThreatOne Scanner - YARA Rule Engine
// Full integration interface for YARA rules.
// Currently a STUB backend since libyara is not available.
// The interface is designed to be swapped with a real YARA library implementation.

#include <string>
#include <vector>
#include <filesystem>
#include <unordered_map>

#include <core/Error.h>
#include <core/Logger.h>

namespace ThreatOne::Scanner {

// A YARA match result
struct YaraMatch {
    std::string ruleName;
    std::string ruleNamespace;
    std::vector<std::string> tags;
    std::vector<std::string> metaStrings;
};

// Status of the YARA engine
enum class YaraEngineStatus {
    Uninitialized,
    Ready,
    Error
};

// YARA Rule Engine interface (stubbed)
class YaraEngine {
public:
    YaraEngine();
    ~YaraEngine() = default;

    // Initialize the engine
    Core::Result<void, Core::Error> initialize();

    // Load rules from a file (stores text, parses rule names)
    Core::Result<size_t, Core::Error> loadRules(const std::filesystem::path& rulesPath);

    // Load rules from a string
    Core::Result<size_t, Core::Error> loadRulesFromString(const std::string& rulesText);

    // Compile loaded rules (stub: validates rules are loaded)
    Core::Result<void, Core::Error> compileRules();

    // Scan a file against loaded rules (stub: always returns empty matches)
    Core::Result<std::vector<YaraMatch>, Core::Error> matchFile(
        const std::filesystem::path& filePath);

    // Scan a buffer against loaded rules (stub: always returns empty matches)
    Core::Result<std::vector<YaraMatch>, Core::Error> matchBuffer(
        const std::vector<uint8_t>& data);

    // Get the number of loaded rules
    size_t ruleCount() const;

    // Get all loaded rule names
    std::vector<std::string> getRuleNames() const;

    // Get engine status
    YaraEngineStatus status() const;

    // Clear all loaded rules
    void clearRules();

private:
    // Parse rule names from YARA source text
    std::vector<std::string> parseRuleNames(const std::string& text) const;

    Core::ModuleLogger logger_;
    YaraEngineStatus status_;
    std::vector<std::string> ruleNames_;
    std::vector<std::string> ruleSources_;
    bool compiled_;
};

} // namespace ThreatOne::Scanner
