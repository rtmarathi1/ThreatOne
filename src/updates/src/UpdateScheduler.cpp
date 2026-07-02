#include "updates/UpdateScheduler.h"
#include <optional>
#include <mutex>

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Updates {

UpdateScheduler::UpdateScheduler()
    : logger_(Core::Logger::instance().getModuleLogger("UpdateScheduler")) {
    logger_.info("UpdateScheduler initialized");
}

std::string UpdateScheduler::generatePolicyId() {
    return "POL-" + std::to_string(nextPolicyId_++);
}

std::string UpdateScheduler::generateTaskId() {
    return "TASK-" + std::to_string(nextTaskId_++);
}

std::string UpdateScheduler::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::string UpdateScheduler::createPolicy(const SchedulePolicy& policy) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generatePolicyId();
    SchedulePolicy newPolicy = policy;
    newPolicy.id = id;
    policies_[id] = newPolicy;

    if (activePolicyId_.empty()) {
        activePolicyId_ = id;
    }

    logger_.info("Created schedule policy: {} ({})", newPolicy.name, id);
    return id;
}

bool UpdateScheduler::updatePolicy(const std::string& policyId, const SchedulePolicy& policy) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) return false;

    SchedulePolicy updated = policy;
    updated.id = policyId;
    it->second = updated;
    return true;
}

bool UpdateScheduler::deletePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) return false;

    policies_.erase(it);
    if (activePolicyId_ == policyId) {
        activePolicyId_.clear();
    }
    return true;
}

std::vector<SchedulePolicy> UpdateScheduler::getPolicies() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SchedulePolicy> result;
    result.reserve(policies_.size());
    for (const auto& [id, policy] : policies_) {
        result.push_back(policy);
    }
    return result;
}

std::optional<SchedulePolicy> UpdateScheduler::getPolicy(const std::string& policyId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) return std::nullopt;
    return it->second;
}

std::optional<SchedulePolicy> UpdateScheduler::getActivePolicy() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (activePolicyId_.empty()) return std::nullopt;
    auto it = policies_.find(activePolicyId_);
    if (it == policies_.end()) return std::nullopt;
    return it->second;
}

void UpdateScheduler::setActivePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);
    activePolicyId_ = policyId;
}

std::string UpdateScheduler::scheduleCheck(const std::string& scheduledFor) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generateTaskId();
    ScheduledTask task;
    task.id = id;
    task.policyId = activePolicyId_;
    task.scheduledFor = scheduledFor;
    task.executed = false;

    tasks_.push_back(task);
    ++totalScheduled_;
    return id;
}

std::string UpdateScheduler::scheduleInstallation(const std::string& version,
                                                    const std::string& scheduledFor) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generateTaskId();
    ScheduledTask task;
    task.id = id;
    task.policyId = activePolicyId_;
    task.scheduledFor = scheduledFor;
    task.result = "install:" + version;
    task.executed = false;

    tasks_.push_back(task);
    ++totalScheduled_;
    return id;
}

bool UpdateScheduler::cancelScheduledTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find_if(tasks_.begin(), tasks_.end(),
                           [&taskId](const ScheduledTask& t) { return t.id == taskId; });
    if (it == tasks_.end() || it->executed) return false;

    tasks_.erase(it);
    return true;
}

bool UpdateScheduler::executeTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& task : tasks_) {
        if (task.id == taskId && !task.executed) {
            task.executed = true;
            task.success = true;
            task.executedAt = getCurrentTimestamp();
            ++totalExecuted_;
            return true;
        }
    }
    return false;
}

std::vector<ScheduledTask> UpdateScheduler::getPendingTasks() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ScheduledTask> pending;
    for (const auto& task : tasks_) {
        if (!task.executed) pending.push_back(task);
    }
    return pending;
}

std::vector<ScheduledTask> UpdateScheduler::getCompletedTasks() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ScheduledTask> completed;
    for (const auto& task : tasks_) {
        if (task.executed) completed.push_back(task);
    }
    return completed;
}

bool UpdateScheduler::isCheckDue() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (lastCheckTime_.empty()) return true;
    // Simplified: always due if no recent check
    return true;
}

void UpdateScheduler::recordCheckPerformed() {
    std::lock_guard<std::mutex> lock(mutex_);
    lastCheckTime_ = getCurrentTimestamp();
}

std::string UpdateScheduler::getNextCheckTime() const {
    std::lock_guard<std::mutex> lock(mutex_);
    // Return simulated next check time
    return getCurrentTimestamp();
}

std::string UpdateScheduler::getLastCheckTime() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastCheckTime_;
}

uint64_t UpdateScheduler::getTotalTasksScheduled() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalScheduled_;
}

uint64_t UpdateScheduler::getTotalTasksExecuted() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalExecuted_;
}

uint64_t UpdateScheduler::getPendingTaskCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t count = 0;
    for (const auto& task : tasks_) {
        if (!task.executed) ++count;
    }
    return count;
}

} // namespace ThreatOne::Updates
