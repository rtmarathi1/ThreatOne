#pragma once

#include "cloud/ICloudManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>

namespace ThreatOne::Cloud {

class CloudManager : public ICloudManager {
public:
    CloudManager();
    ~CloudManager() override = default;

    // Basic sync and status
    bool sync() override;
    SyncResult syncWithConflictResolution(ConflictResolution resolution) override;
    [[nodiscard]] SyncStatus getSyncStatus() override;
    [[nodiscard]] CloudStatus getStatus() override;

    // Backup management
    bool backup(const std::string& name) override;
    bool restore(const std::string& backupId) override;
    [[nodiscard]] std::vector<BackupInfo> listBackups() override;
    bool deleteBackup(const std::string& backupId) override;

    // Policy distribution
    std::string distributePolicy(const PolicyInfo& policy) override;
    [[nodiscard]] std::vector<PolicyInfo> getPolicies() override;
    bool acknowledgePolicy(const std::string& policyId, const std::string& endpointId) override;

    // Backup schedules
    std::string createBackupSchedule(const BackupSchedule& schedule) override;
    [[nodiscard]] std::vector<BackupSchedule> getBackupSchedules() override;

    // Legacy
    bool uploadThreatIntel(const std::string& data) override;
    std::string downloadPolicies() override;

private:
    mutable std::mutex mutex_;
    SyncStatus syncStatus_ = SyncStatus::Idle;
    int totalItemsSynced_ = 0;
    std::string lastSyncTime_;

    std::map<std::string, BackupInfo> backups_;
    std::map<std::string, PolicyInfo> policies_;
    std::map<std::string, BackupSchedule> backupSchedules_;

    int nextBackupId_ = 1;
    int nextPolicyId_ = 1;
    int nextScheduleId_ = 1;

    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Cloud
