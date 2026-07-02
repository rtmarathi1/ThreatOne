#include "hids/SystemCallMonitor.h"

#include <algorithm>
#include <chrono>
#include <regex>
#include <sstream>

namespace ThreatOne::HIDS {

SystemCallMonitor::SystemCallMonitor()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SystemCallMonitor")) {
    logger_.info("SystemCallMonitor initialized");
}

std::string SystemCallMonitor::generateEventId() {
    return "SCM-EVT-" + std::to_string(nextEventId_++);
}

std::string SystemCallMonitor::generateRuleId() {
    return "SCM-RULE-" + std::to_string(nextRuleId_++);
}

std::string SystemCallMonitor::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

bool SystemCallMonitor::matchesSyscallPattern(const std::string& name, const std::string& pattern) const {
    try {
        std::regex re(pattern);
        return std::regex_search(name, re);
    } catch (const std::regex_error&) {
        return name.find(pattern) != std::string::npos;
    }
}

bool SystemCallMonitor::startMonitoring() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (monitoring_) {
        logger_.warn("Syscall monitoring already active");
        return false;
    }

    monitoring_ = true;
    logger_.info("Syscall monitoring started");
    return true;
}

bool SystemCallMonitor::stopMonitoring() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!monitoring_) {
        logger_.warn("Syscall monitoring not active");
        return false;
    }

    monitoring_ = false;
    logger_.info("Syscall monitoring stopped");
    return true;
}

bool SystemCallMonitor::isMonitoring() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return monitoring_;
}

void SystemCallMonitor::recordSyscall(const SyscallEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    SyscallEvent newEvent = event;
    if (newEvent.id.empty()) {
        newEvent.id = generateEventId();
    }
    if (newEvent.timestamp.empty()) {
        newEvent.timestamp = getCurrentTimestamp();
    }

    // Check if suspicious
    newEvent.suspicious = isSyscallSuspicious(newEvent);

    events_.push_back(newEvent);
    if (events_.size() > kMaxEvents) {
        events_.pop_front();
    }

    if (newEvent.suspicious) {
        suspiciousEvents_.push_back(newEvent);
        suspiciousCount_++;
    }

    totalEventsProcessed_++;
}

bool SystemCallMonitor::isSyscallSuspicious(const SyscallEvent& event) const {
    // Check against rules (mutex already held by caller)
    for (const auto& [id, rule] : rules_) {
        if (!rule.enabled) continue;

        if (rule.category == event.category &&
            matchesSyscallPattern(event.syscallName, rule.syscallPattern)) {
            return true;
        }
    }

    // Built-in suspicious patterns
    if (event.category == SyscallCategory::PrivilegeEscalation) {
        return true;
    }

    return false;
}

std::vector<SyscallEvent> SystemCallMonitor::getSuspiciousEvents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return suspiciousEvents_;
}

std::vector<SyscallEvent> SystemCallMonitor::getRecentEvents(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SyscallEvent> result;
    size_t start = events_.size() > count ? events_.size() - count : 0;
    for (size_t i = start; i < events_.size(); ++i) {
        result.push_back(events_[i]);
    }
    return result;
}

std::vector<SyscallEvent> SystemCallMonitor::getEventsByCategory(SyscallCategory category) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SyscallEvent> result;
    for (const auto& event : events_) {
        if (event.category == category) {
            result.push_back(event);
        }
    }
    return result;
}

std::string SystemCallMonitor::addRule(const SyscallRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (rule.name.empty() || rule.syscallPattern.empty()) {
        return "";
    }

    std::string id = generateRuleId();
    SyscallRule newRule = rule;
    newRule.id = id;
    rules_[id] = newRule;

    logger_.info("Added syscall rule: {} ({})", rule.name, id);
    return id;
}

bool SystemCallMonitor::removeRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rules_.find(ruleId);
    if (it == rules_.end()) {
        return false;
    }
    rules_.erase(it);
    return true;
}

bool SystemCallMonitor::enableRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rules_.find(ruleId);
    if (it == rules_.end()) {
        return false;
    }
    it->second.enabled = true;
    return true;
}

bool SystemCallMonitor::disableRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rules_.find(ruleId);
    if (it == rules_.end()) {
        return false;
    }
    it->second.enabled = false;
    return true;
}

std::vector<SyscallRule> SystemCallMonitor::getRules() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SyscallRule> result;
    result.reserve(rules_.size());
    for (const auto& [id, rule] : rules_) {
        result.push_back(rule);
    }
    return result;
}

SyscallMonitorStats SystemCallMonitor::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    SyscallMonitorStats stats;
    stats.totalEventsProcessed = totalEventsProcessed_;
    stats.suspiciousEvents = suspiciousCount_;
    stats.blockedCalls = blockedCalls_;
    stats.activeRules = 0;
    for (const auto& [id, rule] : rules_) {
        if (rule.enabled) {
            stats.activeRules++;
        }
    }
    return stats;
}

void SystemCallMonitor::resetStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    totalEventsProcessed_ = 0;
    suspiciousCount_ = 0;
    blockedCalls_ = 0;
}

} // namespace ThreatOne::HIDS
