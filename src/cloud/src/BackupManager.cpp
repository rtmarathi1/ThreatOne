#include "cloud/BackupManager.h"
#include <mutex>

#include <algorithm>

namespace ThreatOne::Cloud {

CloudBackupManager::CloudBackupManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("CloudBackupManager")) {
    logger_.info("CloudBackupManager initialized");
}

std::string CloudBackupManager::generateBackupId() {
    return "BKP-" + std::to_string(nextBackupId_++);
}

std::string CloudBackupManager::generateScheduleId() {
    return "SCHED-" + std::to_string(nextScheduleId_++);
}

std::string CloudBackupManager::createBackup(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generateBackupId();
    BackupInfo info;
    info.id = id;
    info.name = name;
    info.timestamp = "now";
    info.size = 1024;
    info.encrypted = false;
    backups_[id] = info;

    logger_.info("Created backup: id={}, name={}", id, name);
    return id;
}

bool CloudBackupManager::restoreBackup(const std::string& backupId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = backups_.find(backupId);
    if (it == backups_.end()) {
        logger_.warn("restoreBackup failed: backup {} not found", backupId);
        return false;
    }

    logger_.info("Restored backup: id={}, name={}", backupId, it->second.name);
    return true;
}

std::vector<BackupInfo> CloudBackupManager::listBackups() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<BackupInfo> result;
    result.reserve(backups_.size());
    for (const auto& [id, backup] : backups_) {
        result.push_back(backup);
    }
    return result;
}

bool CloudBackupManager::deleteBackup(const std::string& backupId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = backups_.find(backupId);
    if (it == backups_.end()) {
        logger_.warn("deleteBackup failed: backup {} not found", backupId);
        return false;
    }

    logger_.info("Deleted backup: id={}, name={}", backupId, it->second.name);
    backups_.erase(it);
    return true;
}

std::string CloudBackupManager::createSchedule(const BackupSchedule& schedule) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generateScheduleId();
    BackupSchedule stored = schedule;
    stored.id = id;
    schedules_[id] = stored;

    logger_.info("Created backup schedule: id={}, name={}, frequency={}", id, schedule.name, schedule.frequency);
    return id;
}

std::vector<BackupSchedule> CloudBackupManager::getSchedules() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<BackupSchedule> result;
    result.reserve(schedules_.size());
    for (const auto& [id, sched] : schedules_) {
        result.push_back(sched);
    }
    return result;
}

bool CloudBackupManager::deleteSchedule(const std::string& scheduleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = schedules_.find(scheduleId);
    if (it == schedules_.end()) {
        logger_.warn("deleteSchedule failed: schedule {} not found", scheduleId);
        return false;
    }

    logger_.info("Deleted schedule: id={}", scheduleId);
    schedules_.erase(it);
    return true;
}

BackupVerification CloudBackupManager::verifyBackup(const std::string& backupId) {
    std::lock_guard<std::mutex> lock(mutex_);

    BackupVerification verification;
    verification.backupId = backupId;

    auto it = backups_.find(backupId);
    if (it == backups_.end()) {
        logger_.warn("verifyBackup: backup {} not found", backupId);
        return verification;
    }

    // Compute simple checksum (simulated using size-based hash)
    verification.integrityValid = true;
    verification.encryptionValid = it->second.encrypted;
    verification.checksum = it->second.size * 31 + 17;
    verification.verifiedAt = "now";

    logger_.info("Verified backup: id={}, integrity={}, encryption={}",
                 backupId, verification.integrityValid, verification.encryptionValid);
    return verification;
}

bool CloudBackupManager::setEncryption(const std::string& backupId, bool encrypted) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = backups_.find(backupId);
    if (it == backups_.end()) {
        logger_.warn("setEncryption: backup {} not found", backupId);
        return false;
    }

    it->second.encrypted = encrypted;
    logger_.info("Set encryption for backup {}: {}", backupId, encrypted);
    return true;
}

int CloudBackupManager::applyRetentionPolicy(int maxBackups) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (maxBackups < 0) {
        return 0;
    }

    int removed = 0;
    while (static_cast<int>(backups_.size()) > maxBackups) {
        // Remove oldest (first in ordered map)
        auto it = backups_.begin();
        logger_.info("Retention policy: removing backup {}", it->first);
        backups_.erase(it);
        removed++;
    }

    if (removed > 0) {
        logger_.info("Retention policy applied: removed {} backups, {} remaining", removed, backups_.size());
    }
    return removed;
}

uint64_t CloudBackupManager::getTotalStorageUsed() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t total = 0;
    for (const auto& [id, backup] : backups_) {
        total += backup.size;
    }
    return total;
}

} // namespace ThreatOne::Cloud
