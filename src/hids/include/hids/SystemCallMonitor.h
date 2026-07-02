#pragma once

#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <deque>
#include <cstdint>

namespace ThreatOne::HIDS {

enum class SyscallCategory {
    FileAccess,
    ProcessControl,
    NetworkAccess,
    PrivilegeEscalation,
    MemoryManipulation,
    DeviceAccess
};

struct SyscallEvent {
    std::string id;
    std::string syscallName;
    SyscallCategory category = SyscallCategory::FileAccess;
    uint64_t pid = 0;
    std::string processName;
    std::string arguments;
    int returnCode = 0;
    bool suspicious = false;
    std::string reason;
    std::string timestamp;
};

struct SyscallRule {
    std::string id;
    std::string name;
    std::string syscallPattern;
    SyscallCategory category = SyscallCategory::FileAccess;
    std::string description;
    bool enabled = true;
};

struct SyscallMonitorStats {
    uint64_t totalEventsProcessed = 0;
    uint64_t suspiciousEvents = 0;
    uint64_t activeRules = 0;
    uint64_t blockedCalls = 0;
};

class SystemCallMonitor {
public:
    SystemCallMonitor();
    ~SystemCallMonitor() = default;

    // Monitoring control
    bool startMonitoring();
    bool stopMonitoring();
    [[nodiscard]] bool isMonitoring() const;

    // Event processing
    void recordSyscall(const SyscallEvent& event);
    [[nodiscard]] std::vector<SyscallEvent> getSuspiciousEvents() const;
    [[nodiscard]] std::vector<SyscallEvent> getRecentEvents(size_t count) const;
    [[nodiscard]] std::vector<SyscallEvent> getEventsByCategory(SyscallCategory category) const;

    // Rule management
    std::string addRule(const SyscallRule& rule);
    bool removeRule(const std::string& ruleId);
    bool enableRule(const std::string& ruleId);
    bool disableRule(const std::string& ruleId);
    [[nodiscard]] std::vector<SyscallRule> getRules() const;

    // Analysis
    bool isSyscallSuspicious(const SyscallEvent& event) const;
    [[nodiscard]] SyscallMonitorStats getStats() const;
    void resetStats();

private:
    std::string generateEventId();
    std::string generateRuleId();
    std::string getCurrentTimestamp() const;
    bool matchesSyscallPattern(const std::string& name, const std::string& pattern) const;

    mutable std::mutex mutex_;

    bool monitoring_ = false;
    std::deque<SyscallEvent> events_;
    std::vector<SyscallEvent> suspiciousEvents_;
    std::map<std::string, SyscallRule> rules_;

    uint64_t totalEventsProcessed_ = 0;
    uint64_t suspiciousCount_ = 0;
    uint64_t blockedCalls_ = 0;

    int nextEventId_ = 1;
    int nextRuleId_ = 1;

    static constexpr size_t kMaxEvents = 50000;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::HIDS
