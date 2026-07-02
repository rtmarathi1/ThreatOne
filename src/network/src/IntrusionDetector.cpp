#include "network/IntrusionDetector.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace ThreatOne::Network {

IntrusionDetector::IntrusionDetector()
    : logger_(Core::Logger::instance().getModuleLogger("IntrusionDetector")) {
    logger_.info("IntrusionDetector initialized");
}

void IntrusionDetector::addRule(const IDSRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.push_back(rule);
    logger_.info("Added IDS rule: {} ({})", rule.id, rule.name);
}

void IntrusionDetector::removeRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.erase(
        std::remove_if(rules_.begin(), rules_.end(),
            [&ruleId](const IDSRule& r) { return r.id == ruleId; }),
        rules_.end());
}

std::vector<IDSRule> IntrusionDetector::getRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_;
}

std::vector<IDSAlert> IntrusionDetector::evaluate(const PacketInfo& packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IDSAlert> triggered;

    // Periodically prune stale port scan tracker entries
    pruneOldEntries();

    for (const auto& rule : rules_) {
        if (matchesRule(rule, packet)) {
            IDSAlert alert;
            alert.ruleId = rule.id;
            alert.ruleName = rule.name;
            alert.action = rule.action;
            alert.sourceIP = packet.sourceIP;
            alert.destIP = packet.destIP;
            alert.sourcePort = packet.sourcePort;
            alert.destPort = packet.destPort;
            alert.description = "Rule triggered: " + rule.name;
            alert.timestamp = std::chrono::steady_clock::now();

            triggered.push_back(alert);
            appendAlert(alert);

            logger_.warn("IDS alert: rule={}, src={}:{}, dst={}:{}",
                         rule.name, packet.sourceIP, packet.sourcePort,
                         packet.destIP, packet.destPort);
        }
    }

    return triggered;
}

bool IntrusionDetector::detectPortScan(const std::string& sourceIP,
                                       const std::vector<uint16_t>& ports) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    // Prune stale entries from other IPs to prevent unbounded growth
    pruneOldEntries();

    auto& attempts = portScanTracker_[sourceIP];
    for (uint16_t port : ports) {
        attempts.push_back({now, port});
    }

    // Prune entries older than 60 seconds
    auto cutoff = now - std::chrono::seconds(60);
    attempts.erase(
        std::remove_if(attempts.begin(), attempts.end(),
            [&cutoff](const ConnectionAttempt& a) { return a.timestamp < cutoff; }),
        attempts.end());

    // Count unique ports in window
    std::vector<uint16_t> uniquePorts;
    for (const auto& attempt : attempts) {
        if (std::find(uniquePorts.begin(), uniquePorts.end(), attempt.port) == uniquePorts.end()) {
            uniquePorts.push_back(attempt.port);
        }
    }

    // Threshold: more than 10 unique ports in 60 seconds = port scan
    bool detected = uniquePorts.size() > 10;
    if (detected) {
        IDSAlert alert;
        alert.ruleId = "PORTSCAN";
        alert.ruleName = "Port Scan Detected";
        alert.action = IDSAction::Alert;
        alert.sourceIP = sourceIP;
        alert.description = "Port scan detected from " + sourceIP +
                           " (" + std::to_string(uniquePorts.size()) + " ports)";
        alert.timestamp = now;
        appendAlert(alert);

        logger_.warn("Port scan detected from {}: {} unique ports", sourceIP, uniquePorts.size());
    }

    return detected;
}

bool IntrusionDetector::detectSYNFlood(const std::string& destIP, int count, int windowSeconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    auto& timestamps = synFloodTracker_[destIP];
    timestamps.push_back(now);

    // Prune old entries
    auto cutoff = now - std::chrono::seconds(windowSeconds);
    timestamps.erase(
        std::remove_if(timestamps.begin(), timestamps.end(),
            [&cutoff](const auto& ts) { return ts < cutoff; }),
        timestamps.end());

    // Remove empty keys to prevent unbounded map growth
    if (timestamps.empty()) {
        synFloodTracker_.erase(destIP);
        return false;
    }

    bool detected = static_cast<int>(timestamps.size()) >= count;
    if (detected) {
        IDSAlert alert;
        alert.ruleId = "SYNFLOOD";
        alert.ruleName = "SYN Flood Detected";
        alert.action = IDSAction::Drop;
        alert.destIP = destIP;
        alert.description = "SYN flood targeting " + destIP +
                           " (" + std::to_string(timestamps.size()) + " in " +
                           std::to_string(windowSeconds) + "s)";
        alert.timestamp = now;
        appendAlert(alert);

        logger_.warn("SYN flood detected targeting {}: {} attempts in {}s",
                     destIP, timestamps.size(), windowSeconds);
    }

    return detected;
}

bool IntrusionDetector::detectBruteForce(const std::string& destIP, uint16_t destPort,
                                         int failCount, int windowSeconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    std::string key = destIP + ":" + std::to_string(destPort);
    auto& timestamps = bruteForceTracker_[key];
    timestamps.push_back(now);

    // Prune old entries
    auto cutoff = now - std::chrono::seconds(windowSeconds);
    timestamps.erase(
        std::remove_if(timestamps.begin(), timestamps.end(),
            [&cutoff](const auto& ts) { return ts < cutoff; }),
        timestamps.end());

    // Remove empty keys to prevent unbounded map growth
    if (timestamps.empty()) {
        bruteForceTracker_.erase(key);
        return false;
    }

    bool detected = static_cast<int>(timestamps.size()) >= failCount;
    if (detected) {
        IDSAlert alert;
        alert.ruleId = "BRUTEFORCE";
        alert.ruleName = "Brute Force Detected";
        alert.action = IDSAction::Drop;
        alert.destIP = destIP;
        alert.destPort = destPort;
        alert.description = "Brute force on " + key +
                           " (" + std::to_string(timestamps.size()) + " in " +
                           std::to_string(windowSeconds) + "s)";
        alert.timestamp = now;
        appendAlert(alert);

        logger_.warn("Brute force detected on {}: {} attempts in {}s",
                     key, timestamps.size(), windowSeconds);
    }

    return detected;
}

std::vector<IDSAlert> IntrusionDetector::getAlerts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<IDSAlert>(alerts_.begin(), alerts_.end());
}

void IntrusionDetector::clearAlerts() {
    std::lock_guard<std::mutex> lock(mutex_);
    alerts_.clear();
}

size_t IntrusionDetector::getAlertCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return alerts_.size();
}

bool IntrusionDetector::matchesRule(const IDSRule& rule, const PacketInfo& packet) const {
    // Check protocol
    if (!rule.protocol.empty() && rule.protocol != "any" && rule.protocol != packet.protocol) {
        return false;
    }

    // Check source IP (empty or "any" matches all)
    if (!rule.sourceIP.empty() && rule.sourceIP != "any" && rule.sourceIP != packet.sourceIP) {
        return false;
    }

    // Check dest IP
    if (!rule.destIP.empty() && rule.destIP != "any" && rule.destIP != packet.destIP) {
        return false;
    }

    // Check source port (0 = any)
    if (rule.sourcePort != 0 && rule.sourcePort != packet.sourcePort) {
        return false;
    }

    // Check dest port (0 = any)
    if (rule.destPort != 0 && rule.destPort != packet.destPort) {
        return false;
    }

    // Check content pattern
    if (!rule.contentPattern.empty()) {
        if (packet.payload.find(rule.contentPattern) == std::string::npos) {
            return false;
        }
    }

    return true;
}

void IntrusionDetector::pruneOldEntries() {
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(300); // 5 minute cleanup

    for (auto it = portScanTracker_.begin(); it != portScanTracker_.end();) {
        it->second.erase(
            std::remove_if(it->second.begin(), it->second.end(),
                [&cutoff](const ConnectionAttempt& a) { return a.timestamp < cutoff; }),
            it->second.end());
        if (it->second.empty()) {
            it = portScanTracker_.erase(it);
        } else {
            ++it;
        }
    }
}

void IntrusionDetector::appendAlert(const IDSAlert& alert) {
    // Evict oldest alerts when at capacity (O(1) with deque)
    if (alerts_.size() >= kMaxAlerts) {
        alerts_.pop_front();
    }
    alerts_.push_back(alert);
}

} // namespace ThreatOne::Network
