#pragma once

#include "updates/IUpdateManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Updates {

enum class ScheduleType {
    Periodic,
    Daily,
    Weekly,
    Manual
};

struct SchedulePolicy {
    std::string id;
    std::string name;
    ScheduleType type = ScheduleType::Periodic;
    uint64_t intervalMs = 86400000;  // Default: 24 hours
    int preferredHour = 2;  // 2 AM
    int preferredDay = 0;   // Sunday for weekly
    bool autoInstall = false;
    bool notifyUser = true;
    bool allowMeteredConnection = false;
};

struct ScheduledTask {
    std::string id;
    std::string policyId;
    std::string scheduledFor;
    std::string executedAt;
    bool executed = false;
    bool success = false;
    std::string result;
};

class UpdateScheduler {
public:
    UpdateScheduler();
    ~UpdateScheduler() = default;

    // Policy management
    std::string createPolicy(const SchedulePolicy& policy);
    bool updatePolicy(const std::string& policyId, const SchedulePolicy& policy);
    bool deletePolicy(const std::string& policyId);
    [[nodiscard]] std::vector<SchedulePolicy> getPolicies() const;
    [[nodiscard]] std::optional<SchedulePolicy> getPolicy(const std::string& policyId) const;
    [[nodiscard]] std::optional<SchedulePolicy> getActivePolicy() const;
    void setActivePolicy(const std::string& policyId);

    // Scheduling
    std::string scheduleCheck(const std::string& scheduledFor);
    std::string scheduleInstallation(const std::string& version, const std::string& scheduledFor);
    bool cancelScheduledTask(const std::string& taskId);
    bool executeTask(const std::string& taskId);
    [[nodiscard]] std::vector<ScheduledTask> getPendingTasks() const;
    [[nodiscard]] std::vector<ScheduledTask> getCompletedTasks() const;

    // Check timing
    [[nodiscard]] bool isCheckDue() const;
    void recordCheckPerformed();
    [[nodiscard]] std::string getNextCheckTime() const;
    [[nodiscard]] std::string getLastCheckTime() const;

    // Statistics
    [[nodiscard]] uint64_t getTotalTasksScheduled() const;
    [[nodiscard]] uint64_t getTotalTasksExecuted() const;
    [[nodiscard]] uint64_t getPendingTaskCount() const;

private:
    std::string generatePolicyId();
    std::string generateTaskId();
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, SchedulePolicy> policies_;
    std::vector<ScheduledTask> tasks_;
    std::string activePolicyId_;
    std::string lastCheckTime_;
    uint64_t totalScheduled_ = 0;
    uint64_t totalExecuted_ = 0;
    int nextPolicyId_ = 1;
    int nextTaskId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Updates
