#include "reporting/ReportScheduler.h"

#include <algorithm>
#include <sstream>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ThreatOne::Reporting {

ReportScheduler::ReportScheduler()
    : logger_("ReportScheduler") {
    logger_.info("Report Scheduler initialized");
}

std::string ReportScheduler::generateId() {
    std::ostringstream oss;
    oss << "sched-" << nextId_.fetch_add(1);
    return oss.str();
}

std::chrono::system_clock::time_point ReportScheduler::computeNextRun(
    ScheduleFrequency frequency,
    std::chrono::system_clock::time_point from) {
    switch (frequency) {
        case ScheduleFrequency::Daily:
            return from + std::chrono::hours(24);
        case ScheduleFrequency::Weekly:
            return from + std::chrono::hours(24 * 7);
        case ScheduleFrequency::Monthly:
            return from + std::chrono::hours(24 * 30);
    }
    return from + std::chrono::hours(24);
}

ThreatOne::Core::Result<std::string> ReportScheduler::createSchedule(const ReportSchedule& schedule) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (schedule.reportConfigId.empty()) {
        return ThreatOne::Core::Result<std::string>::err(
            ThreatOne::Core::Error("Report config ID cannot be empty",
                                   ThreatOne::Core::ErrorCategory::Validation));
    }

    ReportSchedule newSchedule = schedule;
    if (newSchedule.id.empty()) {
        newSchedule.id = generateId();
    }

    // Set next run based on frequency from now
    auto now = std::chrono::system_clock::now();
    if (newSchedule.nextRun == std::chrono::system_clock::time_point{}) {
        newSchedule.nextRun = computeNextRun(newSchedule.frequency, now);
    }

    std::string id = newSchedule.id;
    schedules_[id] = newSchedule;

    logger_.info("Created schedule: {} (frequency: {})", id,
                 newSchedule.frequency == ScheduleFrequency::Daily ? "daily" :
                 newSchedule.frequency == ScheduleFrequency::Weekly ? "weekly" : "monthly");

    return ThreatOne::Core::Result<std::string>::ok(id);
}

bool ReportScheduler::cancelSchedule(const std::string& scheduleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = schedules_.find(scheduleId);
    if (it == schedules_.end()) {
        return false;
    }
    schedules_.erase(it);
    logger_.info("Cancelled schedule: {}", scheduleId);
    return true;
}

bool ReportScheduler::enableSchedule(const std::string& scheduleId, bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = schedules_.find(scheduleId);
    if (it == schedules_.end()) {
        return false;
    }
    it->second.enabled = enabled;
    return true;
}

std::vector<ReportSchedule> ReportScheduler::getSchedules() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ReportSchedule> result;
    result.reserve(schedules_.size());
    for (const auto& [id, sched] : schedules_) {
        result.push_back(sched);
    }
    return result;
}

std::optional<ReportSchedule> ReportScheduler::getSchedule(const std::string& scheduleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = schedules_.find(scheduleId);
    if (it == schedules_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool ReportScheduler::isScheduleDue(const std::string& scheduleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = schedules_.find(scheduleId);
    if (it == schedules_.end()) {
        return false;
    }

    if (!it->second.enabled) {
        return false;
    }

    auto now = std::chrono::system_clock::now();
    return now >= it->second.nextRun;
}

std::vector<ReportSchedule> ReportScheduler::getDueSchedules() const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::system_clock::now();
    std::vector<ReportSchedule> result;

    for (const auto& [id, sched] : schedules_) {
        if (sched.enabled && now >= sched.nextRun) {
            result.push_back(sched);
        }
    }
    return result;
}

bool ReportScheduler::markAsRun(const std::string& scheduleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = schedules_.find(scheduleId);
    if (it == schedules_.end()) {
        return false;
    }

    auto now = std::chrono::system_clock::now();
    it->second.lastRun = now;
    it->second.nextRun = computeNextRun(it->second.frequency, now);
    return true;
}

bool ReportScheduler::addRecipient(const std::string& scheduleId, const std::string& recipient) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = schedules_.find(scheduleId);
    if (it == schedules_.end()) {
        return false;
    }

    // Avoid duplicates
    auto& list = it->second.distributionList;
    if (std::find(list.begin(), list.end(), recipient) == list.end()) {
        list.push_back(recipient);
    }
    return true;
}

bool ReportScheduler::removeRecipient(const std::string& scheduleId, const std::string& recipient) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = schedules_.find(scheduleId);
    if (it == schedules_.end()) {
        return false;
    }

    auto& list = it->second.distributionList;
    auto recIt = std::find(list.begin(), list.end(), recipient);
    if (recIt == list.end()) {
        return false;
    }
    list.erase(recIt);
    return true;
}

std::vector<std::string> ReportScheduler::getRecipients(const std::string& scheduleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = schedules_.find(scheduleId);
    if (it == schedules_.end()) {
        return {};
    }
    return it->second.distributionList;
}

bool ReportScheduler::setRetentionDays(const std::string& scheduleId, int days) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = schedules_.find(scheduleId);
    if (it == schedules_.end()) {
        return false;
    }

    if (days < 1) {
        return false;
    }

    it->second.retentionDays = days;
    return true;
}

int ReportScheduler::getRetentionDays(const std::string& scheduleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = schedules_.find(scheduleId);
    if (it == schedules_.end()) {
        return -1;
    }
    return it->second.retentionDays;
}

size_t ReportScheduler::getScheduleCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return schedules_.size();
}

} // namespace ThreatOne::Reporting
