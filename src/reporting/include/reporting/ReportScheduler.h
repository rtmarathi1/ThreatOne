#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <optional>

#include "reporting/IReportEngine.h"
#include "core/Logger.h"
#include "core/Error.h"
#include <chrono>

namespace ThreatOne::Reporting {

class ReportScheduler {
public:
    ReportScheduler();
    ~ReportScheduler() = default;

    // Create a new schedule
    [[nodiscard]] ThreatOne::Core::Result<std::string> createSchedule(const ReportSchedule& schedule);

    // Cancel (remove) a schedule
    bool cancelSchedule(const std::string& scheduleId);

    // Enable/disable a schedule
    bool enableSchedule(const std::string& scheduleId, bool enabled);

    // Get all schedules
    [[nodiscard]] std::vector<ReportSchedule> getSchedules() const;

    // Get a specific schedule
    [[nodiscard]] std::optional<ReportSchedule> getSchedule(const std::string& scheduleId) const;

    // Check if a schedule is due (based on frequency and last run time)
    [[nodiscard]] bool isScheduleDue(const std::string& scheduleId) const;

    // Get all schedules that are currently due
    [[nodiscard]] std::vector<ReportSchedule> getDueSchedules() const;

    // Mark a schedule as having run (updates lastRun and computes nextRun)
    bool markAsRun(const std::string& scheduleId);

    // Distribution list management
    bool addRecipient(const std::string& scheduleId, const std::string& recipient);
    bool removeRecipient(const std::string& scheduleId, const std::string& recipient);
    [[nodiscard]] std::vector<std::string> getRecipients(const std::string& scheduleId) const;

    // Retention policy
    bool setRetentionDays(const std::string& scheduleId, int days);
    [[nodiscard]] int getRetentionDays(const std::string& scheduleId) const;

    // Get count of schedules
    [[nodiscard]] size_t getScheduleCount() const;

private:
    [[nodiscard]] std::string generateId();
    [[nodiscard]] static std::chrono::system_clock::time_point computeNextRun(
        ScheduleFrequency frequency,
        std::chrono::system_clock::time_point from);

    mutable std::mutex mutex_;
    std::map<std::string, ReportSchedule> schedules_;
    std::atomic<int> nextId_{1};
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Reporting
