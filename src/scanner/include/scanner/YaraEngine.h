#pragma once

// ThreatOne Scanner - YARA Rule Engine
// When HAS_YARA is defined: uses real libyara for rule compilation and scanning
// Otherwise: built-in Aho-Corasick multi-pattern matching engine

#include <string>
#include <vector>
#include <array>
#include <filesystem>
#include <unordered_map>

#include <core/Error.h>
#include <core/Logger.h>

#ifdef HAS_YARA
#include <yara.h>
#endif

namespace ThreatOne::Scanner {

// A YARA match result
struct YaraMatch {
    std::string ruleName;
    std::string ruleNamespace;
    std::vector<std::string> tags;
    std::vector<std::string> metaStrings;
    std::vector<std::pair<std::string, std::vector<size_t>>> matchedStrings;
};

// Status of the YARA engine
enum class YaraEngineStatus {
    Uninitialized,
    Ready,
    Error
};

// YARA Rule Engine
class YaraEngine {
public:
    YaraEngine();
    ~YaraEngine();

    // Non-copyable
    YaraEngine(const YaraEngine&) = delete;
    YaraEngine& operator=(const YaraEngine&) = delete;

    // Initialize the engine
    Core::Result<void, Core::Error> initialize();

    // Load rules from a file (stores text, parses rule names)
    Core::Result<size_t, Core::Error> loadRules(const std::filesystem::path& rulesPath);

    // Load rules from a string
    Core::Result<size_t, Core::Error> loadRulesFromString(const std::string& rulesText);

    // Compile loaded rules
    Core::Result<void, Core::Error> compileRules();

    // Scan a file against loaded rules
    Core::Result<std::vector<YaraMatch>, Core::Error> matchFile(
        const std::filesystem::path& filePath);

    // Scan a buffer against loaded rules
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

#ifdef HAS_YARA
    YR_COMPILER* compiler_;
    YR_RULES* rules_;

    // Callback for YARA scan results
    static int scanCallback(YR_SCAN_CONTEXT* context, int message,
                           void* message_data, void* user_data);
#else
    // Internal structures for the pattern-matching automaton
    struct PatternDef {
        std::string identifier;
        enum Type { Text, Hex } type;
        std::vector<uint8_t> bytes;
        std::vector<bool> mask; // true = must match, false = wildcard
        bool nocase;
    };

    struct RuleDef {
        std::string name;
        std::string ns;
        std::vector<std::string> tags;
        std::vector<std::pair<std::string, std::string>> meta;
        std::vector<PatternDef> patterns;
        std::string condition;
    };

    struct AhoNode {
        std::array<int, 256> children;
        int failure;
        std::vector<size_t> outputs; // indices into allPatterns_
        AhoNode() : failure(0) { children.fill(-1); }
    };

    std::vector<RuleDef> compiledRules_;
    std::vector<PatternDef*> allPatterns_;
    std::vector<AhoNode> automaton_;
    bool automatonBuilt_;

    void buildAutomaton();
    std::vector<YaraMatch> scanData(const uint8_t* data, size_t length) const;
    bool evaluateCondition(const std::string& condition,
                           const std::vector<PatternDef>& patterns,
                           const std::unordered_map<std::string, std::vector<size_t>>& hits) const;
    static RuleDef parseRule(const std::string& ruleText);
    static std::vector<std::string> splitRules(const std::string& text);
#endif
};

} // namespace ThreatOne::Scanner
