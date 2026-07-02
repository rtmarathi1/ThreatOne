#include "siem/SIEMEngine.h"

#include <algorithm>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <regex>
#include <cmath>

namespace ThreatOne::SIEM {

SIEMEngine::SIEMEngine()
    : startTime_(std::chrono::steady_clock::now())
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SIEMEngine")) {
    logger_.info("SIEMEngine initialized");
}

std::string SIEMEngine::generateLogId() {
    return "LOG-" + std::to_string(nextLogId_++);
}

std::string SIEMEngine::generateAlertId() {
    return "ALERT-" + std::to_string(nextAlertId_++);
}

std::string SIEMEngine::generateRuleId() {
    return "RULE-" + std::to_string(nextRuleId_++);
}

std::string SIEMEngine::generateCorrelationRuleId() {
    return "CRULE-" + std::to_string(nextCorrelationRuleId_++);
}

bool SIEMEngine::matchesCondition(const LogEntry& entry, const std::string& condition) const {
    // Condition format: "field=value" or just a substring match on the message
    auto eqPos = condition.find('=');
    if (eqPos != std::string::npos) {
        std::string field = condition.substr(0, eqPos);
        std::string value = condition.substr(eqPos + 1);

        if (field == "source") return entry.source == value;
        if (field == "severity") return entry.severity == value;
        if (field == "message") return entry.message.find(value) != std::string::npos;

        // Check metadata
        auto it = entry.metadata.find(field);
        if (it != entry.metadata.end()) {
            return it->second == value;
        }
        return false;
    }

    // Simple substring match on message
    return entry.message.find(condition) != std::string::npos;
}

bool SIEMEngine::isWithinTimeRange(const std::string& timestamp, const std::string& start, const std::string& end) const {
    if (start.empty() && end.empty()) return true;
    if (!start.empty() && timestamp < start) return false;
    if (!end.empty() && timestamp > end) return false;
    return true;
}

bool SIEMEngine::ingestLog(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);

    LogEntry stored = entry;
    if (stored.id.empty()) {
        stored.id = generateLogId();
    }

    logs_.push_back(stored);
    totalIngested_++;

    logger_.debug("Ingested log: id={}, source={}", stored.id, stored.source);
    return true;
}

bool SIEMEngine::ingestBatch(const std::vector<LogEntry>& entries) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& entry : entries) {
        LogEntry stored = entry;
        if (stored.id.empty()) {
            stored.id = generateLogId();
        }
        logs_.push_back(stored);
        totalIngested_++;
    }

    logger_.info("Ingested batch of {} logs", entries.size());
    return true;
}

std::vector<LogEntry> SIEMEngine::searchLogs(const std::string& query) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<LogEntry> results;
    for (const auto& log : logs_) {
        if (log.message.find(query) != std::string::npos ||
            log.source.find(query) != std::string::npos) {
            results.push_back(log);
        }
    }
    return results;
}

std::vector<LogEntry> SIEMEngine::search(const SearchQuery& query) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<LogEntry> results;
    int count = 0;

    for (const auto& log : logs_) {
        if (count >= query.limit) break;

        // Text filter
        if (!query.text.empty()) {
            if (log.message.find(query.text) == std::string::npos &&
                log.source.find(query.text) == std::string::npos) {
                continue;
            }
        }

        // Field filters
        bool fieldMatch = true;
        for (const auto& [field, value] : query.fields) {
            if (field == "source" && log.source != value) { fieldMatch = false; break; }
            if (field == "severity" && log.severity != value) { fieldMatch = false; break; }
            if (field == "message" && log.message.find(value) == std::string::npos) { fieldMatch = false; break; }

            // Check metadata
            if (field != "source" && field != "severity" && field != "message") {
                auto it = log.metadata.find(field);
                if (it == log.metadata.end() || it->second != value) {
                    fieldMatch = false;
                    break;
                }
            }
        }
        if (!fieldMatch) continue;

        // Time range filter
        if (!isWithinTimeRange(log.timestamp, query.timeStart, query.timeEnd)) {
            continue;
        }

        results.push_back(log);
        count++;
    }

    return results;
}

std::string SIEMEngine::createAlert(const SIEMAlert& alert) {
    std::lock_guard<std::mutex> lock(mutex_);

    SIEMAlert stored = alert;
    if (stored.id.empty()) {
        stored.id = generateAlertId();
    }
    alerts_[stored.id] = stored;
    logger_.info("Created alert: id={}, title={}", stored.id, stored.title);
    return stored.id;
}

std::vector<SIEMAlert> SIEMEngine::getAlerts() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SIEMAlert> result;
    result.reserve(alerts_.size());
    for (const auto& [id, alert] : alerts_) {
        result.push_back(alert);
    }
    return result;
}

std::string SIEMEngine::createRule(const SIEMRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);

    SIEMRule stored = rule;
    if (stored.id.empty()) {
        stored.id = generateRuleId();
    }
    rules_[stored.id] = stored;
    logger_.info("Created rule: id={}, name={}", stored.id, stored.name);
    return stored.id;
}

std::vector<SIEMRule> SIEMEngine::getRules() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SIEMRule> result;
    result.reserve(rules_.size());
    for (const auto& [id, rule] : rules_) {
        result.push_back(rule);
    }
    return result;
}

std::string SIEMEngine::createCorrelationRule(const CorrelationRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);

    CorrelationRule stored = rule;
    if (stored.id.empty()) {
        stored.id = generateCorrelationRuleId();
    }
    correlationRules_[stored.id] = stored;
    logger_.info("Created correlation rule: id={}, name={}, threshold={}, window={}s",
                 stored.id, stored.name, stored.threshold, stored.timeWindowSeconds);
    return stored.id;
}

std::vector<SIEMAlert> SIEMEngine::evaluateRules() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SIEMAlert> newAlerts;

    for (const auto& [ruleId, rule] : correlationRules_) {
        if (!rule.enabled) continue;

        // Find all logs that match the condition
        std::vector<const LogEntry*> matchingLogs;
        for (const auto& log : logs_) {
            if (matchesCondition(log, rule.condition)) {
                matchingLogs.push_back(&log);
            }
        }

        // Apply time window filter: only count logs within timeWindowSeconds
        // of the most recent matching log
        std::vector<std::string> matchedIds;

        if (!matchingLogs.empty()) {
            // Find the most recent timestamp among matching logs
            std::string mostRecent;
            for (const auto* log : matchingLogs) {
                if (log->timestamp > mostRecent) {
                    mostRecent = log->timestamp;
                }
            }

            if (mostRecent.empty()) {
                // No timestamps available, include all matches (backward compatible)
                for (const auto* log : matchingLogs) {
                    matchedIds.push_back(log->id);
                }
            } else {
                // Parse the most recent timestamp and filter by time window
                auto parseTimestamp = [](const std::string& ts) -> std::time_t {
                    std::tm tm = {};
                    std::istringstream ss(ts);
                    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
                    if (ss.fail()) {
                        return 0;
                    }
                    // Use timegm/_mkgmtime for thread-safe UTC conversion
#ifdef _WIN32
                    return _mkgmtime(&tm);
#else
                    return timegm(&tm);
#endif
                };

                std::time_t recentTime = parseTimestamp(mostRecent);
                if (recentTime == 0) {
                    // Cannot parse timestamps, include all matches
                    for (const auto* log : matchingLogs) {
                        matchedIds.push_back(log->id);
                    }
                } else {
                    for (const auto* log : matchingLogs) {
                        if (log->timestamp.empty()) {
                            // No timestamp on this log, include it
                            matchedIds.push_back(log->id);
                        } else {
                            std::time_t logTime = parseTimestamp(log->timestamp);
                            if (logTime == 0) {
                                matchedIds.push_back(log->id);
                            } else {
                                double diff = std::abs(std::difftime(recentTime, logTime));
                                if (diff <= static_cast<double>(rule.timeWindowSeconds)) {
                                    matchedIds.push_back(log->id);
                                }
                            }
                        }
                    }
                }
            }
        }

        // If matches exceed threshold, create alert
        if (static_cast<int>(matchedIds.size()) >= rule.threshold) {
            SIEMAlert alert;
            alert.id = generateAlertId();
            alert.ruleId = ruleId;
            alert.title = "Correlation rule triggered: " + rule.name;
            alert.severity = rule.severity;
            alert.description = "Threshold of " + std::to_string(rule.threshold) +
                                " exceeded with " + std::to_string(matchedIds.size()) + " matches";
            alert.matchedLogIds = matchedIds;

            alerts_[alert.id] = alert;
            newAlerts.push_back(alert);

            logger_.info("Correlation rule fired: rule={}, matches={}", rule.name, matchedIds.size());
        }
    }

    return newAlerts;
}

std::vector<ParsedField> SIEMEngine::parseLog(const std::string& rawLog, LogFormat format) {
    std::lock_guard<std::mutex> lock(mutex_);

    switch (format) {
        case LogFormat::Syslog:
            return parseSyslog(rawLog);
        case LogFormat::JSON:
            return parseJSON(rawLog);
        case LogFormat::CEF:
            return parseCEF(rawLog);
        case LogFormat::LEEF:
            return parseLEEF(rawLog);
        case LogFormat::WindowsEventLog:
            return parseWindowsEventLog(rawLog);
    }
    return {};
}

std::vector<ParsedField> SIEMEngine::parseSyslog(const std::string& rawLog) const {
    std::vector<ParsedField> fields;

    // Syslog format: <priority>timestamp hostname app[pid]: message
    // or simplified: Mon DD HH:MM:SS hostname app: message
    std::regex syslogRegex(R"(^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$)");
    std::smatch match;

    if (std::regex_match(rawLog, match, syslogRegex)) {
        fields.push_back({"timestamp", match[1].str(), "timestamp"});
        fields.push_back({"hostname", match[2].str(), "string"});
        fields.push_back({"application", match[3].str(), "string"});
        if (match[4].matched) {
            fields.push_back({"pid", match[4].str(), "integer"});
        }
        fields.push_back({"message", match[5].str(), "string"});
    } else {
        // Fallback: treat entire string as message
        fields.push_back({"raw_message", rawLog, "string"});
    }

    return fields;
}

std::vector<ParsedField> SIEMEngine::parseJSON(const std::string& rawLog) const {
    std::vector<ParsedField> fields;

    // Simple JSON key-value extraction using regex
    // Matches: "key": "value" or "key": number
    std::regex jsonStringRegex(R"re("(\w+)"\s*:\s*"([^"]*)")re");
    std::regex jsonNumberRegex(R"re("(\w+)"\s*:\s*(\d+(?:\.\d+)?))re");

    auto strBegin = std::sregex_iterator(rawLog.begin(), rawLog.end(), jsonStringRegex);
    auto strEnd = std::sregex_iterator();
    for (auto it = strBegin; it != strEnd; ++it) {
        std::smatch match = *it;
        fields.push_back({match[1].str(), match[2].str(), "string"});
    }

    auto numBegin = std::sregex_iterator(rawLog.begin(), rawLog.end(), jsonNumberRegex);
    auto numEnd = std::sregex_iterator();
    for (auto it = numBegin; it != numEnd; ++it) {
        std::smatch match = *it;
        // Skip if already captured as string
        bool alreadyCaptured = false;
        for (const auto& f : fields) {
            if (f.name == match[1].str()) {
                alreadyCaptured = true;
                break;
            }
        }
        if (!alreadyCaptured) {
            fields.push_back({match[1].str(), match[2].str(), "integer"});
        }
    }

    return fields;
}

std::vector<ParsedField> SIEMEngine::parseCEF(const std::string& rawLog) const {
    std::vector<ParsedField> fields;

    // CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    if (rawLog.substr(0, 4) != "CEF:") {
        fields.push_back({"raw_message", rawLog, "string"});
        return fields;
    }

    // Split by pipe '|'
    std::vector<std::string> parts;
    std::istringstream ss(rawLog.substr(4)); // skip "CEF:"
    std::string part;
    while (std::getline(ss, part, '|')) {
        parts.push_back(part);
    }

    if (parts.size() >= 7) {
        fields.push_back({"version", parts[0], "string"});
        fields.push_back({"device_vendor", parts[1], "string"});
        fields.push_back({"device_product", parts[2], "string"});
        fields.push_back({"device_version", parts[3], "string"});
        fields.push_back({"signature_id", parts[4], "string"});
        fields.push_back({"name", parts[5], "string"});
        fields.push_back({"severity", parts[6], "string"});

        // Extension key=value pairs
        if (parts.size() > 7) {
            std::string extension = parts[7];
            // For parts beyond 7 that may have been split by pipes in extension
            for (size_t i = 8; i < parts.size(); i++) {
                extension += "|" + parts[i];
            }

            std::regex kvRegex(R"((\w+)=([^\s]+))");
            auto kvBegin = std::sregex_iterator(extension.begin(), extension.end(), kvRegex);
            auto kvEnd = std::sregex_iterator();
            for (auto it = kvBegin; it != kvEnd; ++it) {
                std::smatch match = *it;
                fields.push_back({match[1].str(), match[2].str(), "string"});
            }
        }
    } else {
        fields.push_back({"raw_message", rawLog, "string"});
    }

    return fields;
}

std::vector<ParsedField> SIEMEngine::parseLEEF(const std::string& rawLog) const {
    std::vector<ParsedField> fields;

    // LEEF format: LEEF:Version|Vendor|Product|Version|EventID|key=value\tkey=value
    if (rawLog.substr(0, 5) != "LEEF:") {
        fields.push_back({"raw_message", rawLog, "string"});
        return fields;
    }

    std::vector<std::string> parts;
    std::istringstream ss(rawLog.substr(5));
    std::string part;
    while (std::getline(ss, part, '|')) {
        parts.push_back(part);
    }

    if (parts.size() >= 5) {
        fields.push_back({"version", parts[0], "string"});
        fields.push_back({"vendor", parts[1], "string"});
        fields.push_back({"product", parts[2], "string"});
        fields.push_back({"product_version", parts[3], "string"});
        fields.push_back({"event_id", parts[4], "string"});

        // Key-value pairs separated by tab or space after the header
        if (parts.size() > 5) {
            std::string extension = parts[5];
            for (size_t i = 6; i < parts.size(); i++) {
                extension += "|" + parts[i];
            }

            std::regex kvRegex(R"((\w+)=([^\t]+))");
            auto kvBegin = std::sregex_iterator(extension.begin(), extension.end(), kvRegex);
            auto kvEnd = std::sregex_iterator();
            for (auto it = kvBegin; it != kvEnd; ++it) {
                std::smatch match = *it;
                fields.push_back({match[1].str(), match[2].str(), "string"});
            }
        }
    }

    return fields;
}

std::vector<ParsedField> SIEMEngine::parseWindowsEventLog(const std::string& rawLog) const {
    std::vector<ParsedField> fields;

    // Windows Event Log simplified format: EventID=X Source=Y Level=Z Message=...
    std::regex kvRegex(R"((\w+)=([^\s]+(?:\s+[^\s=]+)*))");

    // Try key=value format first
    auto kvBegin = std::sregex_iterator(rawLog.begin(), rawLog.end(), kvRegex);
    auto kvEnd = std::sregex_iterator();
    for (auto it = kvBegin; it != kvEnd; ++it) {
        std::smatch match = *it;
        fields.push_back({match[1].str(), match[2].str(), "string"});
    }

    if (fields.empty()) {
        fields.push_back({"raw_message", rawLog, "string"});
    }

    return fields;
}

DashboardMetrics SIEMEngine::getDashboardMetrics() {
    std::lock_guard<std::mutex> lock(mutex_);

    DashboardMetrics metrics;
    metrics.totalLogs = static_cast<long>(logs_.size());

    // Events per second
    auto elapsed = std::chrono::steady_clock::now() - startTime_;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    if (seconds > 0) {
        metrics.eventsPerSecond = static_cast<double>(totalIngested_) / static_cast<double>(seconds);
    } else {
        metrics.eventsPerSecond = static_cast<double>(totalIngested_);
    }

    // Top sources
    std::map<std::string, int> sourceCounts;
    for (const auto& log : logs_) {
        sourceCounts[log.source]++;
    }

    for (const auto& [source, count] : sourceCounts) {
        metrics.topSources.push_back({source, count});
    }

    // Sort by count descending
    std::sort(metrics.topSources.begin(), metrics.topSources.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // Keep top 10
    if (metrics.topSources.size() > 10) {
        metrics.topSources.resize(10);
    }

    // Alert rate (alerts per log)
    if (!logs_.empty()) {
        metrics.alertRate = static_cast<double>(alerts_.size()) / static_cast<double>(logs_.size());
    }

    // Approximate storage (rough estimate based on message sizes)
    for (const auto& log : logs_) {
        metrics.storageUsedBytes += static_cast<long>(log.message.size() + log.source.size() + 100);
    }

    return metrics;
}

} // namespace ThreatOne::SIEM
