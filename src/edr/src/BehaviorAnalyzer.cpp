#include "edr/BehaviorAnalyzer.h"

#include <algorithm>
#include <unordered_map>

namespace ThreatOne::EDR {

BehaviorAnalyzer::BehaviorAnalyzer(size_t windowSize)
    : logger_(Core::Logger::instance().getModuleLogger("BehaviorAnalyzer"))
    , windowSize_(windowSize)
{
    logger_.info("BehaviorAnalyzer initialized with window size {}", windowSize_);
}

void BehaviorAnalyzer::addEvent(const EDREvent& event) {
    std::lock_guard lock(mutex_);
    events_.push_back(event);
    while (events_.size() > windowSize_) {
        events_.pop_front();
    }
}

std::vector<BehaviorAlert> BehaviorAnalyzer::analyzePatterns() const {
    std::vector<BehaviorAlert> alerts;

    auto ransomware = detectRansomwareBehavior();
    alerts.insert(alerts.end(), ransomware.begin(), ransomware.end());

    auto privesc = detectPrivilegeEscalation();
    alerts.insert(alerts.end(), privesc.begin(), privesc.end());

    auto exfil = detectDataExfiltration();
    alerts.insert(alerts.end(), exfil.begin(), exfil.end());

    return alerts;
}

std::vector<BehaviorAlert> BehaviorAnalyzer::detectRansomwareBehavior() const {
    std::lock_guard lock(mutex_);
    std::vector<BehaviorAlert> alerts;

    if (events_.empty()) return alerts;

    // Look for ransomware patterns:
    // Many file renames to crypto extensions + high entropy writes in a short time window
    auto now = events_.back().timestamp;
    auto windowStart = now - std::chrono::seconds(60);

    size_t renameCount = 0;
    size_t highEntropyWriteCount = 0;
    std::vector<std::string> relatedPaths;

    // Known ransomware extensions
    static const std::vector<std::string> cryptoExtensions = {
        ".encrypted", ".locked", ".crypto", ".crypt", ".locky",
        ".cerber", ".zepto", ".thor", ".aaa", ".abc", ".zzz",
        ".enc", ".crypted", ".pays", ".ransom"
    };

    for (const auto& event : events_) {
        if (event.timestamp < windowStart) continue;

        if (event.type == "file_rename") {
            // Check if renamed to a crypto extension
            for (const auto& ext : cryptoExtensions) {
                if (event.path.size() >= ext.size() &&
                    event.path.compare(event.path.size() - ext.size(), ext.size(), ext) == 0) {
                    renameCount++;
                    relatedPaths.push_back(event.path);
                    break;
                }
            }
        }

        if (event.type == "file_write" && event.entropy > 7.5) {
            highEntropyWriteCount++;
            relatedPaths.push_back(event.path);
        }
    }

    // Trigger if we see many renames to crypto extensions + high entropy writes
    if (renameCount >= 5 && highEntropyWriteCount >= 3) {
        BehaviorAlert alert;
        alert.patternType = "ransomware";
        alert.description = "Detected ransomware-like behavior: " +
                            std::to_string(renameCount) + " file renames to crypto extensions and " +
                            std::to_string(highEntropyWriteCount) + " high-entropy writes within 60 seconds";
        alert.severity = "critical";
        alert.relatedEvents = relatedPaths;
        alerts.push_back(alert);
    } else if (renameCount >= 5) {
        BehaviorAlert alert;
        alert.patternType = "ransomware";
        alert.description = "Detected potential ransomware: " +
                            std::to_string(renameCount) + " file renames to crypto extensions";
        alert.severity = "high";
        alert.relatedEvents = relatedPaths;
        alerts.push_back(alert);
    }

    return alerts;
}

std::vector<BehaviorAlert> BehaviorAnalyzer::detectPrivilegeEscalation() const {
    std::lock_guard lock(mutex_);
    std::vector<BehaviorAlert> alerts;

    if (events_.empty()) return alerts;

    auto now = events_.back().timestamp;
    auto windowStart = now - std::chrono::seconds(120);

    size_t suidChanges = 0;
    size_t unexpectedSudo = 0;
    std::vector<std::string> relatedEvents;

    // Suspicious processes that should not normally invoke sudo/su
    static const std::vector<std::string> suspiciousParents = {
        "httpd", "apache", "nginx", "node", "python", "ruby",
        "perl", "php", "java", "tomcat"
    };

    for (const auto& event : events_) {
        if (event.timestamp < windowStart) continue;

        // SUID bit changes
        if (event.type == "suid_change" || 
            (event.type == "process_exec" && event.details.find("chmod +s") != std::string::npos)) {
            suidChanges++;
            relatedEvents.push_back("suid_change: " + event.path);
        }

        // Unexpected sudo/su usage
        if (event.type == "process_exec" &&
            (event.details.find("sudo") != std::string::npos || 
             event.details.find("/bin/su") != std::string::npos)) {
            for (const auto& parent : suspiciousParents) {
                if (event.source == parent) {
                    unexpectedSudo++;
                    relatedEvents.push_back("unexpected_sudo from " + event.source);
                    break;
                }
            }
        }
    }

    if (suidChanges >= 2 || unexpectedSudo >= 2) {
        BehaviorAlert alert;
        alert.patternType = "privilege_escalation";
        alert.description = "Detected privilege escalation attempt: " +
                            std::to_string(suidChanges) + " SUID changes, " +
                            std::to_string(unexpectedSudo) + " unexpected sudo invocations";
        alert.severity = "high";
        alert.relatedEvents = relatedEvents;
        alerts.push_back(alert);
    }

    return alerts;
}

std::vector<BehaviorAlert> BehaviorAnalyzer::detectDataExfiltration() const {
    std::lock_guard lock(mutex_);
    std::vector<BehaviorAlert> alerts;

    if (events_.empty()) return alerts;

    auto now = events_.back().timestamp;
    auto windowStart = now - std::chrono::seconds(300);

    uint64_t totalOutbound = 0;
    bool archiveCreated = false;
    std::vector<std::string> relatedEvents;

    static const std::vector<std::string> archiveExtensions = {
        ".tar", ".gz", ".zip", ".rar", ".7z", ".bz2", ".xz"
    };

    for (const auto& event : events_) {
        if (event.timestamp < windowStart) continue;

        // Large outbound network traffic
        if (event.type == "network_out") {
            totalOutbound += event.dataSize;
            if (event.dataSize > 10 * 1024 * 1024) { // > 10MB single transfer
                relatedEvents.push_back("large_transfer: " + event.path + " (" +
                                        std::to_string(event.dataSize) + " bytes)");
            }
        }

        // Archive creation
        if (event.type == "file_write" || event.type == "file_create") {
            for (const auto& ext : archiveExtensions) {
                if (event.path.size() >= ext.size() &&
                    event.path.compare(event.path.size() - ext.size(), ext.size(), ext) == 0) {
                    archiveCreated = true;
                    relatedEvents.push_back("archive_created: " + event.path);
                    break;
                }
            }
        }
    }

    // Large outbound data + archive creation = potential exfiltration
    if (totalOutbound > 100 * 1024 * 1024 && archiveCreated) { // > 100MB total outbound + archive
        BehaviorAlert alert;
        alert.patternType = "data_exfiltration";
        alert.description = "Potential data exfiltration: " +
                            std::to_string(totalOutbound / (1024 * 1024)) +
                            " MB outbound data with archive creation";
        alert.severity = "high";
        alert.relatedEvents = relatedEvents;
        alerts.push_back(alert);
    } else if (totalOutbound > 500 * 1024 * 1024) { // > 500MB regardless
        BehaviorAlert alert;
        alert.patternType = "data_exfiltration";
        alert.description = "Unusual outbound data volume: " +
                            std::to_string(totalOutbound / (1024 * 1024)) + " MB";
        alert.severity = "medium";
        alert.relatedEvents = relatedEvents;
        alerts.push_back(alert);
    }

    return alerts;
}

void BehaviorAnalyzer::setWindowSize(size_t size) {
    std::lock_guard lock(mutex_);
    windowSize_ = size;
    while (events_.size() > windowSize_) {
        events_.pop_front();
    }
}

size_t BehaviorAnalyzer::getWindowSize() const {
    std::lock_guard lock(mutex_);
    return windowSize_;
}

size_t BehaviorAnalyzer::getEventCount() const {
    std::lock_guard lock(mutex_);
    return events_.size();
}

void BehaviorAnalyzer::clear() {
    std::lock_guard lock(mutex_);
    events_.clear();
}

} // namespace ThreatOne::EDR
