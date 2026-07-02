#pragma once

#include "cloud/ICloudManager.h"
#include "cloud/CloudSyncService.h"
#include "cloud/BackupManager.h"
#include "cloud/CloudPolicyManager.h"
#include "cloud/DeviceManager.h"
#include "cloud/RemoteScanService.h"
#include "cloud/CloudAssetDiscovery.h"
#include "core/Logger.h"

#include <mutex>
#include <memory>
#include <string>
#include <vector>

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

    // Access to sub-components
    [[nodiscard]] CloudSyncService& getSyncService() { return *syncService_; }
    [[nodiscard]] CloudBackupManager& getBackupManager() { return *backupManager_; }
    [[nodiscard]] CloudPolicyManager& getPolicyManager() { return *policyManager_; }
    [[nodiscard]] DeviceManager& getDeviceManager() { return *deviceManager_; }
    [[nodiscard]] RemoteScanService& getRemoteScanService() { return *remoteScanService_; }
    [[nodiscard]] CloudAssetDiscovery& getAssetDiscovery() { return *assetDiscovery_; }

private:
    // Sub-components
    std::shared_ptr<CloudSyncService> syncService_;
    std::shared_ptr<CloudBackupManager> backupManager_;
    std::shared_ptr<CloudPolicyManager> policyManager_;
    std::shared_ptr<DeviceManager> deviceManager_;
    std::shared_ptr<RemoteScanService> remoteScanService_;
    std::shared_ptr<CloudAssetDiscovery> assetDiscovery_;

    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Cloud
