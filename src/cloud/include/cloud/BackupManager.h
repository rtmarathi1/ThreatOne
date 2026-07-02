#pragma once

#include "cloud/ICloudManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Cloud {

struct BackupVerification {
    std::string backupId;
    bool integrityValid = false;
    bool encryptionValid = false;
    uint64_t checksum = 0;
    std::string verifiedAt;
};

class CloudBackupManager {
public:
    CloudBackupManager();
    ~CloudBackupManager() = default;

    // Backup CRUD
    std::string createBackup(const std::string& name);
    bool restoreBackup(const std::string& backupId);
    [[nodiscard]] std::vector<BackupInfo> listBackups() const;
    bool deleteBackup(const std::string& backupId);

    // Scheduling
    std::string createSchedule(const BackupSchedule& schedule);
    [[nodiscard]] std::vector<BackupSchedule> getSchedules() const;
    bool deleteSchedule(const std::string& scheduleId);

    // Verification and encryption
    BackupVerification verifyBackup(const std::string& backupId);
    bool setEncryption(const std::string& backupId, bool encrypted);

    // Retention management
    int applyRetentionPolicy(int maxBackups);

    // Storage metrics
    [[nodiscard]] uint64_t getTotalStorageUsed() const;

private:
    std::string generateBackupId();
    std::string generateScheduleId();

    mutable std::mutex mutex_;
    std::map<std::string, BackupInfo> backups_;
    std::map<std::string, BackupSchedule> schedules_;
    int nextBackupId_ = 1;
    int nextScheduleId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Cloud
