#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::AI {

// Result of keyword extraction
struct KeywordResult {
    std::string keyword;
    uint32_t frequency = 0;
    double relevance = 0.0;
};

// Summary of log analysis
struct LogSummary {
    std::string summary;
    std::vector<std::string> keyPatterns;
    std::string severity;
    std::vector<std::string> actionItems;
};

class NLPProcessor {
public:
    NLPProcessor();
    ~NLPProcessor() = default;

    // Extract keywords from text, ranked by TF-based relevance
    [[nodiscard]] std::vector<KeywordResult> extractKeywords(const std::string& text) const;

    // Summarize a set of log entries
    [[nodiscard]] LogSummary summarizeLog(const std::vector<std::string>& logEntries) const;

    // Match text against a set of regex patterns, return matches
    [[nodiscard]] std::vector<std::string> matchPattern(const std::string& text,
                                                         const std::vector<std::string>& patterns) const;

    // Generate an alert summary from alert data (template-based)
    [[nodiscard]] std::string generateAlertSummary(const std::map<std::string, std::string>& alertData) const;

    // Tokenize text on whitespace and punctuation
    [[nodiscard]] std::vector<std::string> tokenize(const std::string& text) const;

private:
    Core::ModuleLogger logger_;
    std::set<std::string> stopWords_;
    std::vector<std::string> securityKeywords_;

    // Initialize stop words and security keyword dictionaries
    void initDictionaries();

    // Check if a word is a stop word
    [[nodiscard]] bool isStopWord(const std::string& word) const;

    // Convert string to lowercase
    [[nodiscard]] static std::string toLower(const std::string& str);

    // Determine severity from keywords in text
    [[nodiscard]] std::string determineSeverity(const std::vector<std::string>& tokens) const;

    // Generate action items from detected patterns
    [[nodiscard]] std::vector<std::string> generateActionItems(
        const std::vector<std::string>& patterns,
        const std::string& severity) const;
};

} // namespace ThreatOne::AI
