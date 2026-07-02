#include "siem/CorrelationEngine.h"
#include <memory>
#include <mutex>

#include <cmath>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace ThreatOne::SIEM {

CorrelationEngine::CorrelationEngine(std::shared_ptr<LogStorage> storage)
    : storage_(std::move(storage))
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("CorrelationEngine")) {
    logger_.info("CorrelationEngine initialized");
}

std::string CorrelationEngine::generateRuleId() {
    return "CRULE-" + std::to_string(nextRuleId_++);
}

std::string CorrelationEngine::generateAlertId() {
    return "ALERT-" + std::to_string(nextAlertId_++);
}

std::string CorrelationEngine::addRule(const CorrelationRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);

    CorrelationRule stored = rule;
    if (stored.id.empty()) {
        stored.id = generateRuleId();
    }
    rules_[stored.id] = stored;
    logger_.info("Added correlation rule: id={}, name={}, threshold={}, window={}s",
                 stored.id, stored.name, stored.threshold, stored.timeWindowSeconds);
    return stored.id;
}

bool CorrelationEngine::removeRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.erase(ruleId) > 0;
}

bool CorrelationEngine::enableRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(ruleId);
    if (it != rules_.end()) {
        it->second.enabled = true;
        return true;
    }
    return false;
}

bool CorrelationEngine::disableRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(ruleId);
    if (it != rules_.end()) {
        it->second.enabled = false;
        return true;
    }
    return false;
}

std::vector<CorrelationRule> CorrelationEngine::getRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CorrelationRule> result;
    result.reserve(rules_.size());
    for (const auto& [id, rule] : rules_) {
        result.push_back(rule);
    }
    return result;
}

std::vector<SIEMAlert> CorrelationEngine::evaluate() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto allLogs = storage_->getAll();
    std::vector<SIEMAlert> newAlerts;

    for (const auto& [ruleId, rule] : rules_) {
        if (!rule.enabled) continue;

        // Find all logs that match the condition
        std::vector<const LogEntry*> matchingLogs;
        for (const auto& log : allLogs) {
            if (matchesCondition(log, rule.condition)) {
                matchingLogs.push_back(&log);
            }
        }

        // Apply time window filter
        std::vector<std::string> matchedIds;

        if (!matchingLogs.empty()) {
            // Find the most recent timestamp
            std::string mostRecent;
            for (const auto* log : matchingLogs) {
                if (log->timestamp > mostRecent) {
                    mostRecent = log->timestamp;
                }
            }

            if (mostRecent.empty()) {
                // No timestamps, include all matches
                for (const auto* log : matchingLogs) {
                    matchedIds.push_back(log->id);
                }
            } else {
                // Parse timestamps and filter by window
                auto parseTimestamp = [](const std::string& ts) -> std::time_t {
                    std::tm tm = {};
                    std::istringstream ss(ts);
                    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
                    if (ss.fail()) {
                        return 0;
                    }
#ifdef _WIN32
                    return _mkgmtime(&tm);
#else
                    return timegm(&tm);
#endif
                };

                std::time_t recentTime = parseTimestamp(mostRecent);
                if (recentTime == 0) {
                    for (const auto* log : matchingLogs) {
                        matchedIds.push_back(log->id);
                    }
                } else {
                    for (const auto* log : matchingLogs) {
                        if (log->timestamp.empty()) {
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

            newAlerts.push_back(alert);

            // Publish SecurityEvent via EventBus for cross-module notification
            Core::SecurityEvent::Severity evtSev = Core::SecurityEvent::Severity::Medium;
            if (rule.severity == "critical") evtSev = Core::SecurityEvent::Severity::Critical;
            else if (rule.severity == "high") evtSev = Core::SecurityEvent::Severity::High;
            else if (rule.severity == "low") evtSev = Core::SecurityEvent::Severity::Low;

            Core::SecurityEvent event(
                Core::SecurityEvent::Type::Anomaly,
                evtSev,
                "Correlation triggered: " + rule.name + " (" + std::to_string(matchedIds.size()) + " matches)");
            event.setSource("CorrelationEngine");
            event.setData("ruleId", ruleId);
            event.setData("matchCount", static_cast<int>(matchedIds.size()));
            Core::EventBus::instance().publish(event);

            logger_.info("Correlation rule fired: rule={}, matches={}", rule.name, matchedIds.size());
        }
    }

    return newAlerts;
}

bool CorrelationEngine::matchesCondition(const LogEntry& entry,
                                          const std::string& condition) const {
    auto eqPos = condition.find('=');
    if (eqPos != std::string::npos) {
        std::string field = condition.substr(0, eqPos);
        std::string value = condition.substr(eqPos + 1);

        if (field == "source") return entry.source == value;
        if (field == "severity") return entry.severity == value;
        if (field == "message") return entry.message.find(value) != std::string::npos;

        auto it = entry.metadata.find(field);
        if (it != entry.metadata.end()) {
            return it->second == value;
        }
        return false;
    }

    return entry.message.find(condition) != std::string::npos;
}

} // namespace ThreatOne::SIEM
