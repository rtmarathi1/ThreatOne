#include "ai/NLPProcessor.h"

#include <algorithm>
#include <sstream>
#include <cctype>
#include <numeric>

namespace ThreatOne::AI {

NLPProcessor::NLPProcessor()
    : logger_(Core::Logger::instance().getModuleLogger("NLPProcessor")) {
    initDictionaries();
    initPatterns();
    logger_.info("NLPProcessor initialized");
}

void NLPProcessor::initPatterns() {
    // Pre-compile default patterns for log summarization
    std::vector<std::pair<std::string, std::string>> defaultPatternDefs = {
        {"ip_address", R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"},
        {"timestamp", R"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"},
        {"error_code", R"([A-Z]{2,5}-\d{3,6})"},
        {"file_path", R"((?:/[\w.-]+)+(?:/[\w.-]*)*)"}
    };

    for (const auto& [name, pattern] : defaultPatternDefs) {
        try {
            compiledDefaultPatterns_.emplace_back(pattern, std::regex(pattern));
        } catch (const std::regex_error& e) {
            logger_.warn("Failed to compile default pattern '{}': {}", name, e.what());
        }
    }

    // Pre-compile IP regex for action item generation
    ipRegex_ = std::regex(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
}

void NLPProcessor::initDictionaries() {
    // Common English stop words
    stopWords_ = {
        "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "could",
        "should", "may", "might", "shall", "can", "need", "dare", "ought",
        "used", "to", "of", "in", "for", "on", "with", "at", "by", "from",
        "as", "into", "through", "during", "before", "after", "above", "below",
        "between", "out", "off", "over", "under", "again", "further", "then",
        "once", "here", "there", "when", "where", "why", "how", "all", "each",
        "every", "both", "few", "more", "most", "other", "some", "such", "no",
        "not", "only", "own", "same", "so", "than", "too", "very", "just",
        "because", "but", "and", "or", "if", "while", "about", "up", "this",
        "that", "these", "those", "it", "its", "he", "she", "they", "we",
        "you", "i", "me", "him", "her", "us", "them", "my", "your", "his"
    };

    // Security-relevant keywords with higher relevance
    securityKeywords_ = {
        "attack", "malware", "virus", "trojan", "ransomware", "exploit",
        "vulnerability", "breach", "intrusion", "unauthorized", "suspicious",
        "anomaly", "threat", "phishing", "injection", "overflow", "escalation",
        "denial", "brute", "force", "scan", "probe", "exfiltration",
        "lateral", "movement", "persistence", "command", "control", "c2",
        "backdoor", "rootkit", "keylogger", "botnet", "ddos", "xss",
        "csrf", "sqli", "rce", "lfi", "rfi", "ssrf", "idor",
        "privilege", "elevation", "credential", "password", "authentication",
        "firewall", "blocked", "dropped", "rejected", "failed", "error",
        "critical", "warning", "alert", "incident", "compromise"
    };
}

std::vector<std::string> NLPProcessor::tokenize(const std::string& text) const {
    std::vector<std::string> tokens;
    std::string current;

    for (char c : text) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            current += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        } else {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
        }
    }
    if (!current.empty()) {
        tokens.push_back(current);
    }

    return tokens;
}

std::vector<KeywordResult> NLPProcessor::extractKeywords(const std::string& text) const {
    logger_.debug("Extracting keywords from text of size {}", text.size());

    auto tokens = tokenize(text);

    // Count frequencies, excluding stop words
    std::map<std::string, uint32_t> freqMap;
    for (const auto& token : tokens) {
        if (!isStopWord(token) && token.size() > 2) {
            freqMap[token]++;
        }
    }

    if (freqMap.empty()) {
        return {};
    }

    // Find max frequency for normalization
    uint32_t maxFreq = 0;
    for (const auto& [word, freq] : freqMap) {
        if (freq > maxFreq) {
            maxFreq = freq;
        }
    }

    // Build keyword results with TF-based relevance
    std::vector<KeywordResult> results;
    results.reserve(freqMap.size());

    for (const auto& [word, freq] : freqMap) {
        double tf = static_cast<double>(freq) / static_cast<double>(maxFreq);

        // Boost relevance for security-relevant keywords
        double boost = 1.0;
        for (const auto& secWord : securityKeywords_) {
            if (word == secWord) {
                boost = 2.0;
                break;
            }
        }

        results.push_back({word, freq, tf * boost});
    }

    // Sort by relevance (descending)
    std::sort(results.begin(), results.end(),
              [](const KeywordResult& a, const KeywordResult& b) {
                  return a.relevance > b.relevance;
              });

    return results;
}

LogSummary NLPProcessor::summarizeLog(const std::vector<std::string>& logEntries) const {
    logger_.debug("Summarizing {} log entries", logEntries.size());

    LogSummary result;

    if (logEntries.empty()) {
        result.summary = "No log entries to analyze";
        result.severity = "info";
        return result;
    }

    // Cap combined text size to avoid unbounded memory usage and regex stack overflow.
    // Process entries individually up to the size limit.
    std::string combined;
    size_t totalSize = 0;
    size_t entriesProcessed = 0;
    for (const auto& entry : logEntries) {
        if (totalSize + entry.size() + 1 > kMaxSummarizeInputBytes) {
            break;
        }
        combined += entry + " ";
        totalSize += entry.size() + 1;
        entriesProcessed++;
    }

    // Extract keywords from combined text
    auto keywords = extractKeywords(combined);

    // Use pre-compiled patterns for matching
    std::vector<std::string> patternMatches;
    for (const auto& [patternStr, compiledRegex] : compiledDefaultPatterns_) {
        try {
            auto begin = std::sregex_iterator(combined.begin(), combined.end(), compiledRegex);
            auto end = std::sregex_iterator();

            std::set<std::string> uniqueMatches;
            for (auto it = begin; it != end; ++it) {
                uniqueMatches.insert(it->str());
            }
            for (const auto& m : uniqueMatches) {
                patternMatches.push_back(m);
            }
        } catch (const std::regex_error& e) {
            logger_.warn("Regex match error: {}", e.what());
        }
    }
    result.keyPatterns = patternMatches;

    // Determine severity
    auto tokens = tokenize(combined);
    result.severity = determineSeverity(tokens);

    // Build summary from top keywords
    std::string topKeywords;
    int count = 0;
    for (const auto& kw : keywords) {
        if (count >= 5) break;
        if (!topKeywords.empty()) topKeywords += ", ";
        topKeywords += kw.keyword;
        count++;
    }

    std::string truncationNote;
    if (entriesProcessed < logEntries.size()) {
        truncationNote = " (truncated from " + std::to_string(logEntries.size()) +
                         " entries due to size limit)";
    }

    result.summary = "Analyzed " + std::to_string(entriesProcessed) +
                     " log entries" + truncationNote +
                     ". Key topics: " + topKeywords +
                     ". Severity: " + result.severity + ".";

    // Generate action items
    result.actionItems = generateActionItems(patternMatches, result.severity);

    return result;
}

std::vector<std::string> NLPProcessor::matchPattern(
    const std::string& text,
    const std::vector<std::string>& patterns) const {

    std::vector<std::string> matches;

    for (const auto& pattern : patterns) {
        try {
            std::regex re(pattern);
            auto begin = std::sregex_iterator(text.begin(), text.end(), re);
            auto end = std::sregex_iterator();

            std::set<std::string> uniqueMatches;
            for (auto it = begin; it != end; ++it) {
                uniqueMatches.insert(it->str());
            }

            for (const auto& m : uniqueMatches) {
                matches.push_back(m);
            }
        } catch (const std::regex_error& e) {
            logger_.warn("Invalid regex pattern '{}': {}", pattern, e.what());
        }
    }

    return matches;
}

std::string NLPProcessor::generateAlertSummary(
    const std::map<std::string, std::string>& alertData) const {

    logger_.debug("Generating alert summary from {} fields", alertData.size());

    // Template: "Detected {threat_type} from {source} targeting {target} at {time}"
    std::string threatType = "unknown threat";
    std::string source = "unknown source";
    std::string target = "unknown target";
    std::string time = "unknown time";

    auto it = alertData.find("threat_type");
    if (it != alertData.end()) threatType = it->second;

    it = alertData.find("source");
    if (it != alertData.end()) source = it->second;

    it = alertData.find("target");
    if (it != alertData.end()) target = it->second;

    it = alertData.find("time");
    if (it != alertData.end()) time = it->second;

    // Also check alternative field names
    it = alertData.find("source_ip");
    if (it != alertData.end()) source = it->second;

    it = alertData.find("target_host");
    if (it != alertData.end()) target = it->second;

    it = alertData.find("timestamp");
    if (it != alertData.end()) time = it->second;

    return "Detected " + threatType + " from " + source +
           " targeting " + target + " at " + time;
}

bool NLPProcessor::isStopWord(const std::string& word) const {
    return stopWords_.count(word) > 0;
}

std::string NLPProcessor::toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

std::string NLPProcessor::determineSeverity(const std::vector<std::string>& tokens) const {
    // Count severity indicators
    int criticalCount = 0;
    int highCount = 0;
    int mediumCount = 0;

    std::set<std::string> criticalWords = {
        "critical", "emergency", "breach", "compromised", "ransomware",
        "exfiltration", "rootkit", "backdoor"
    };
    std::set<std::string> highWords = {
        "attack", "malware", "exploit", "intrusion", "unauthorized",
        "escalation", "trojan", "virus", "ddos"
    };
    std::set<std::string> mediumWords = {
        "suspicious", "anomaly", "warning", "failed", "blocked",
        "denied", "rejected", "probe", "scan"
    };

    for (const auto& token : tokens) {
        if (criticalWords.count(token)) criticalCount++;
        else if (highWords.count(token)) highCount++;
        else if (mediumWords.count(token)) mediumCount++;
    }

    if (criticalCount > 0) return "critical";
    if (highCount > 2) return "high";
    if (highCount > 0 || mediumCount > 3) return "medium";
    if (mediumCount > 0) return "low";
    return "info";
}

std::vector<std::string> NLPProcessor::generateActionItems(
    const std::vector<std::string>& patterns,
    const std::string& severity) const {

    std::vector<std::string> items;

    // Check for IP addresses in patterns using pre-compiled regex
    for (const auto& p : patterns) {
        if (std::regex_match(p, ipRegex_)) {
            items.push_back("Investigate source IP: " + p);
            break;
        }
    }

    // Severity-based actions
    if (severity == "critical") {
        items.push_back("Escalate to security operations center immediately");
        items.push_back("Initiate incident response procedure");
        items.push_back("Consider isolating affected systems");
    } else if (severity == "high") {
        items.push_back("Investigate and assess impact scope");
        items.push_back("Review related security events");
    } else if (severity == "medium") {
        items.push_back("Monitor for escalation");
        items.push_back("Review access logs for anomalies");
    } else {
        items.push_back("Continue monitoring");
    }

    return items;
}

} // namespace ThreatOne::AI
